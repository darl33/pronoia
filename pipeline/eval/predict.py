"""Running the live pipeline over one gold fixture (DESIGN.md §7).

Calls `extract_document` and `validate_extraction` directly rather than
reimplementing them: §7 measures "the live pipeline", so anything reimplemented
here would be a second, unshipped system whose scores describe nothing.

The one omitted step is the database write -- a gold document is not a
raw_document, and an eval must not add rows to the dataset it is measuring.

`Prediction` is the shape both systems produce, so `score.py` never learns which
one it is looking at.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from enrich.evidence import EvidenceIndex
from enrich.extract import extract_document
from enrich.prompt import render_user_prompt, system_prompt
from enrich.validate import validate_extraction
from eval.gold import GoldFixture
from eval.vocab import is_in_vocabulary, normalize_sector


@dataclass
class Prediction:
    """What one system produced for one document, in the scorer's vocabulary.

    The four sets are the scored output. Everything below them is diagnostic:
    numbers that explain a score rather than being one, and that are the
    interesting half of the scorecard when a backend does badly.
    """

    fixture_id: str
    system: str  # 'llm' | 'baseline'
    status: str = "ok"  # 'ok' | 'invalid_json' | 'schema_fail' | 'api_error'
    error: str | None = None

    actors: set[str] = field(default_factory=set)        # canonical names
    techniques: set[str] = field(default_factory=set)    # ATT&CK IDs
    countries: set[str] = field(default_factory=set)     # ISO 3166-1 alpha-2
    sectors: set[str] = field(default_factory=set)       # normalized vocabulary

    # Guardrail telemetry, per DESIGN.md §5.2. `techniques_emitted` is the
    # denominator for both rates below: it counts what the model actually
    # claimed, before any guardrail removed anything.
    techniques_emitted: int = 0
    techniques_closed_world_ok: int = 0
    evidence_quotes_valid: int = 0
    actors_emitted: int = 0
    actors_unresolved: int = 0
    sectors_off_vocabulary: int = 0

    input_tokens: int | None = None
    output_tokens: int | None = None
    attempts: int = 0
    # Context budget (§5.3). `chunks` > 1 means no single call saw the whole
    # document, which is the headline difference between backends in the §7
    # cross-backend run and has to be visible next to the scores it explains.
    chunks: int = 1
    failed_chunks: int = 0

    @property
    def succeeded(self) -> bool:
        return self.status == "ok"


def _targets_from(targets) -> tuple[set[str], set[str], int]:
    countries: set[str] = set()
    sectors: set[str] = set()
    off_vocabulary = 0

    for target in targets:
        if target.country:
            countries.add(target.country.upper())
        if target.sector:
            normalized = normalize_sector(target.sector)
            if not normalized:
                continue
            sectors.add(normalized)
            if not is_in_vocabulary(normalized):
                off_vocabulary += 1

    return countries, sectors, off_vocabulary


def _evidence_validity(extraction, clean_text: str) -> int:
    """Technique mentions whose quote is a real span of the document.

    Recomputed rather than read off `validate_extraction`'s drops, which check
    the closed world first and short-circuit: a hallucinated ID never reaches the
    quote check, so counting drops would shrink the denominator and flatter the
    rate. §7 wants it over every quote the model wrote.
    """
    index = EvidenceIndex(clean_text)
    return sum(1 for mention in extraction.techniques if index.check(mention.evidence_quote).ok)


def predict_llm(
    client,
    fixture: GoldFixture,
    *,
    technique_index,
    actor_index,
    canonical_names: dict,
    max_input_tokens: int,
    max_output_tokens: int,
) -> Prediction:
    """Run the extraction contract + all §5.2 guardrails over one document.

    `canonical_names` maps threat_actor.id -> canonical_name: scoring resolved
    identity rather than the model's raw string is the only defensible choice,
    since guardrail 4 exists so "Sandworm Team" and "APT44" become one row.
    """
    outcome = extract_document(
        client,
        system_prompt(),
        render_user_prompt,
        fixture.text,
        max_input_tokens=max_input_tokens,
        max_tokens=max_output_tokens,
    )

    prediction = Prediction(
        fixture_id=fixture.id,
        system="llm",
        status=outcome.status,
        error=outcome.error,
        input_tokens=outcome.input_tokens,
        output_tokens=outcome.output_tokens,
        attempts=len(outcome.attempts),
        chunks=outcome.chunk_count,
        failed_chunks=len(outcome.failed_chunks),
    )

    if not outcome.succeeded:
        # Empty sets, deliberately. The pipeline would have written no rows for
        # this document, so every gold item is a false negative -- see the
        # third convention in metrics.py.
        return prediction

    extraction = outcome.extraction
    validated = validate_extraction(
        extraction,
        clean_text=fixture.text,
        technique_index=technique_index,
        actor_index=actor_index,
    )

    prediction.techniques = {t.technique_id for t in validated.techniques}
    prediction.techniques_emitted = len(extraction.techniques)
    prediction.techniques_closed_world_ok = sum(
        1 for mention in extraction.techniques if technique_index.check(mention.technique_id).ok
    )
    prediction.evidence_quotes_valid = _evidence_validity(extraction, fixture.text)

    # Unresolved actors are counted, not scored. They never reach report_actor
    # (they go to the review queue), so they are not part of the system's
    # output and cannot be false positives; if the gold set expected one, its
    # absence is already a false negative. The count is reported because a
    # rising review-queue rate is a reference-data problem, not a model one.
    prediction.actors = {canonical_names[actor.actor_id] for actor in validated.actors}
    prediction.actors_emitted = len(extraction.actors)
    prediction.actors_unresolved = len(validated.review_queue)

    countries, sectors, off_vocabulary = _targets_from(extraction.targets)
    prediction.countries = countries
    prediction.sectors = sectors
    prediction.sectors_off_vocabulary = off_vocabulary

    return prediction
