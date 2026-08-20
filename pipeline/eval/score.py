"""Turning predictions into the numbers the scorecard prints.

All arithmetic lives in metrics.py; this module only decides *what is compared to
what*, which is where the judgement calls are:

* **Techniques are scored twice**, at sub-technique and parent granularity, never
  merged. §7 sets its >0.85 target on the parent score.
* **Targets are scored as two fields, not pairs.** Gold (AU, water) against a
  predicted (AU, null) is one hit and one omission; scoring the pair jointly
  would record a total miss on both.
* **Only recall is reported on the implicit subset.** Predictions carry no
  explicit/implicit label, so a false positive cannot be attributed to it.
  Recall is well defined there; precision is not.
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

    # fp is left at 0 on purpose: unlabelled, not zero. Read `.recall` only.
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
        """Documents where the pipeline produced no report at all. Their gold
        items are already counted as false negatives; this list says *why*."""
        return [p for p in self.predictions if not p.succeeded]

    @property
    def evidence_quote_validity(self) -> float | None:
        """§7's fourth metric: of every quote the model wrote, how many are
        real spans of the document. Denominator is all emitted mentions.

        Undefined for the baseline, which writes no quotes -- it cites IDs
        copied out of the document. Returning 0.0 there would print as "every
        quote was invalid", the opposite of what is true.
        """
        if self.system != "llm":
            return None
        valid = sum(p.evidence_quotes_valid for p in self.predictions)
        emitted = sum(p.techniques_emitted for p in self.predictions)
        return rate(valid, emitted)

    @property
    def closed_world_pass_rate(self) -> float | None:
        """Share of emitted technique IDs that exist in ATT&CK. The complement
        is the hallucinated-ID rate guardrail 2 is there to absorb."""
        passed = sum(p.techniques_closed_world_ok for p in self.predictions)
        emitted = sum(p.techniques_emitted for p in self.predictions)
        return rate(passed, emitted)

    @property
    def actor_review_rate(self) -> float | None:
        """Share of actor mentions that went to the review queue instead of
        report_actor. High means the reference data is stale more often than
        it means the model is wrong."""
        unresolved = sum(p.actors_unresolved for p in self.predictions)
        emitted = sum(p.actors_emitted for p in self.predictions)
        return rate(unresolved, emitted)

    @property
    def chunked_documents(self) -> int:
        """Documents that exceeded the context budget (§5.3). The number that
        explains most of the gap in a cross-backend comparison."""
        return sum(1 for p in self.predictions if p.chunks > 1)

    @property
    def failed_chunks(self) -> int:
        """Chunks that produced nothing on a document that still merged. Unlike
        a whole-document failure this does not show up as a status, so it would
        otherwise be invisible under-extraction."""
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
    """Off-vocabulary sectors the model produced, for the scorecard's
    "vocabulary gaps" note -- these are prompt work, not model failures."""
    return {
        sector
        for prediction in predictions
        for sector in prediction.sectors
        if not is_in_vocabulary(sector)
    }
