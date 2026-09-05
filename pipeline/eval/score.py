"""Turning predictions into the numbers the scorecard prints.

The arithmetic is in metrics.py; this module decides what is compared to what --
technique granularity, targets as two fields, resolved actor identity, and
recall-only on the implicit subset.

docs/DECISIONS.md#what-is-compared
"""

from __future__ import annotations

from dataclasses import dataclass, field

from eval.gold import GoldFixture
from eval.metrics import Counts, macro_f1, micro, rate, score_sets, to_parents
from eval.predict import Prediction
from eval.vocab import is_in_vocabulary

# Order is the scorecard's row order.
FIELDS: tuple[str, ...] = (
    "actors",
    "techniques (sub-technique)",
    "techniques (parent)",
    "targets: countries",
    "targets: sectors",
)


@dataclass
class DocumentScore:
    fixture_id: str
    counts: dict[str, Counts]
    implicit_sub: Counts   # recall-only; see module docstring
    implicit_parent: Counts
    status: str


def score_document(fixture: GoldFixture, prediction: Prediction) -> DocumentScore:
    gold_techniques = fixture.technique_ids()
    gold_implicit = fixture.implicit_technique_ids()

    counts = {
        "actors": score_sets(prediction.actors, {a.name for a in fixture.annotation.actors}),
        "techniques (sub-technique)": score_sets(prediction.techniques, gold_techniques),
        "techniques (parent)": score_sets(
            to_parents(prediction.techniques), to_parents(gold_techniques)
        ),
        "targets: countries": score_sets(prediction.countries, fixture.countries()),
        "targets: sectors": score_sets(prediction.sectors, fixture.sectors()),
    }

    # fp stays 0: unlabelled, not zero. Read `.recall` only.
    implicit_sub = Counts(
        tp=len(prediction.techniques & gold_implicit),
        fn=len(gold_implicit - prediction.techniques),
    )
    predicted_parents = to_parents(prediction.techniques)
    implicit_parents = to_parents(gold_implicit)
    implicit_parent = Counts(
        tp=len(predicted_parents & implicit_parents),
        fn=len(implicit_parents - predicted_parents),
    )

    return DocumentScore(
        fixture_id=fixture.id,
        counts=counts,
        implicit_sub=implicit_sub,
        implicit_parent=implicit_parent,
        status=prediction.status,
    )


@dataclass
class SystemScore:
    """Everything one system scored on one gold set, ready to render."""

    label: str          # what the scorecard calls it, e.g. 'claude-sonnet-5'
    system: str         # 'llm' | 'baseline'
    documents: list[DocumentScore] = field(default_factory=list)
    predictions: list[Prediction] = field(default_factory=list)

    # ---- headline ----

    def micro(self, field_name: str) -> Counts:
        return micro(doc.counts[field_name] for doc in self.documents)

    def macro_f1(self, field_name: str) -> float | None:
        return macro_f1(doc.counts[field_name] for doc in self.documents)

    def implicit_recall(self, *, parent: bool) -> float | None:
        counts = micro(
            doc.implicit_parent if parent else doc.implicit_sub for doc in self.documents
        )
        return rate(counts.tp, counts.support)

    # ---- diagnostics ----

    @property
    def failures(self) -> list[Prediction]:
        """Documents that produced no report. Their gold items already count as
        false negatives; this says why."""
        return [p for p in self.predictions if not p.succeeded]

    @property
    def evidence_quote_validity(self) -> float | None:
        """Of every quote the model wrote, how many are real spans. Undefined
        for the baseline, which writes no quotes at all."""
        if self.system != "llm":
            return None
        valid = sum(p.evidence_quotes_valid for p in self.predictions)
        emitted = sum(p.techniques_emitted for p in self.predictions)
        return rate(valid, emitted)

    @property
    def closed_world_pass_rate(self) -> float | None:
        """Share of emitted technique IDs that exist in ATT&CK; the complement
        is the hallucinated-ID rate guardrail 2 absorbs."""
        passed = sum(p.techniques_closed_world_ok for p in self.predictions)
        emitted = sum(p.techniques_emitted for p in self.predictions)
        return rate(passed, emitted)

    @property
    def actor_review_rate(self) -> float | None:
        """Share of actor mentions routed to the review queue. High usually
        means stale reference data, not a wrong model."""
        unresolved = sum(p.actors_unresolved for p in self.predictions)
        emitted = sum(p.actors_emitted for p in self.predictions)
        return rate(unresolved, emitted)

    @property
    def chunked_documents(self) -> int:
        """Documents that exceeded the context budget (§5.3)."""
        return sum(1 for p in self.predictions if p.chunks > 1)

    @property
    def failed_chunks(self) -> int:
        """Chunks that produced nothing on a document that still merged -- this
        has no status of its own, so it would otherwise be invisible."""
        return sum(p.failed_chunks for p in self.predictions)

    @property
    def off_vocabulary_sectors(self) -> int:
        return sum(p.sectors_off_vocabulary for p in self.predictions)

    @property
    def total_tokens(self) -> tuple[int, int]:
        return (
            sum(p.input_tokens or 0 for p in self.predictions),
            sum(p.output_tokens or 0 for p in self.predictions),
        )


def score_system(
    label: str, system: str, fixtures: list[GoldFixture], predictions: list[Prediction]
) -> SystemScore:
    by_id = {prediction.fixture_id: prediction for prediction in predictions}
    scored = SystemScore(label=label, system=system, predictions=list(predictions))
    for fixture in fixtures:
        prediction = by_id.get(fixture.id)
        if prediction is None:
            continue
        scored.documents.append(score_document(fixture, prediction))
    return scored


def unknown_sectors(predictions: list[Prediction]) -> set[str]:
    """Off-vocabulary sectors the model produced: prompt work, not model bugs."""
    return {
        sector
        for prediction in predictions
        for sector in prediction.sectors
        if not is_in_vocabulary(sector)
    }
