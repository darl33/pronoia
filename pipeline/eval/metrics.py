"""Set-based precision / recall / F1 (DESIGN.md §7).

Hand-written and dependency-free: every metric here reduces to comparing two
sets and counting the three ways they disagree, which a reader can check in a
minute. An eval framework would add a vocabulary and hidden averaging defaults
in exchange for nothing.

Three conventions are load-bearing, so they are stated rather than inherited:

1. **Zero denominators.** Predicting nothing scores 1.0 only when there was
   nothing to find. Silence on a document with three actors is 0.0.
2. **Micro is the headline.** Pooling tp/fp/fn before dividing gives every gold
   item equal weight; macro is dominated by one-item documents. Macro is
   reported beside it, since a large gap means performance depends on length.
3. **A failed extraction is scored, not skipped.** No rows written means every
   gold item is a false negative -- what the dataset would actually look like,
   and the honest treatment for §7's cross-backend comparison, where a small
   local model fails outright more often than it extracts badly.
"""

from __future__ import annotations

from collections.abc import Iterable, Set
from dataclasses import dataclass


@dataclass(frozen=True)
class Counts:
    """One confusion-matrix triple. Addable, so micro-averaging is `sum(...)`."""

    tp: int = 0
    fp: int = 0
    fn: int = 0

    def __add__(self, other: "Counts") -> "Counts":
        if not isinstance(other, Counts):
            return NotImplemented
        return Counts(self.tp + other.tp, self.fp + other.fp, self.fn + other.fn)

    def __radd__(self, other: "Counts | int") -> "Counts":
        # sum() starts from the integer 0, so bare sum(counts) works too.
        return self if other == 0 else self.__add__(other)

    @property
    def predicted(self) -> int:
        """How many items the system emitted."""
        return self.tp + self.fp

    @property
    def support(self) -> int:
        """How many items the gold annotation contains."""
        return self.tp + self.fn

    @property
    def precision(self) -> float:
        """Of what was predicted, how much was right. No predictions is 1.0 only
        when the gold set was empty too -- silence on a document with answers is
        not precision."""
        if self.predicted == 0:
            return 1.0 if self.fn == 0 else 0.0
        return self.tp / self.predicted

    @property
    def recall(self) -> float:
        """Of what was there, how much was found. Mirror of `precision`: an empty
        gold set is vacuously recalled unless the system invented items."""
        if self.support == 0:
            return 1.0 if self.fp == 0 else 0.0
        return self.tp / self.support

    @property
    def f1(self) -> float:
        """Harmonic mean. 0.0 when both terms are 0 (the formula's 0/0)."""
        precision, recall = self.precision, self.recall
        if precision + recall == 0:
            return 0.0
        return 2 * precision * recall / (precision + recall)

    @property
    def degenerate(self) -> bool:
        """Nothing to predict, nothing predicted: 1.0 by convention, not by
        performance, so `macro_f1` excludes it rather than inflating on it."""
        return self.predicted == 0 and self.support == 0


def score_sets(predicted: Set[str], gold: Set[str]) -> Counts:
    """The whole metric, in three set operations.

    Membership is exact string equality, so every normalization (granularity,
    actor canonicalization, sector vocabulary) happens in the caller where it is
    visible. Fuzzy matching hidden in a scorer is how eval numbers stop meaning
    anything.
    """
    return Counts(
        tp=len(predicted & gold),
        fp=len(predicted - gold),
        fn=len(gold - predicted),
    )


def micro(counts: Iterable[Counts]) -> Counts:
    """Pool first, divide once (convention 2)."""
    return sum(counts, Counts())


def macro_f1(counts: Iterable[Counts]) -> float | None:
    """Mean per-document F1, excluding degenerate documents. None when they all
    were: 0.0 and 1.0 would both be lies."""
    scored = [c.f1 for c in counts if not c.degenerate]
    if not scored:
        return None
    return sum(scored) / len(scored)


def rate(numerator: int, denominator: int) -> float | None:
    """Plain ratio for the diagnostic lines. None, not 0.0, on an empty
    denominator: "no quotes emitted" and "every quote invalid" are opposite
    findings and must not print identically."""
    if denominator == 0:
        return None
    return numerator / denominator


# ---------- technique granularity (DESIGN.md §7) ----------


def parent_technique(technique_id: str) -> str:
    """'T1566.001' -> 'T1566'; 'T1566' -> 'T1566'.

    Parent scoring exists because sub-technique choice is often a judgement the
    source does not settle (is a mailed link T1566.001 or .002?) while the parent
    claim is not. §7 sets its target at parent granularity for that reason; both
    are reported so the gap shows how much error is granularity, not substance.
    """
    return technique_id.split(".", 1)[0]


def to_parents(technique_ids: Set[str]) -> set[str]:
    """Roll up to parents. Collapsing is the point: predicting T1566.001 and
    T1566.002 against a gold T1566 is one correct claim, not a hit plus a miss."""
    return {parent_technique(tid) for tid in technique_ids}
