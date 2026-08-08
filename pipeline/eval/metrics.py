"""Set-based precision / recall / F1 (DESIGN.md §7).

Deliberately hand-written and dependency-free. Every metric in the scorecard
reduces to one operation -- compare a predicted set against a gold set and
count the three ways they can disagree -- and that is small enough that
importing an eval framework would add a dependency, a vocabulary, and a set of
hidden averaging defaults in exchange for nothing. The point of this file is
that a reader can check the arithmetic in a minute.

Three conventions are load-bearing, so they are stated rather than inherited:

1. **Zero denominators.** Precision with no predictions is 1.0 only when there
   was also nothing to find. A system that predicts nothing on a document that
   had three actors has not earned perfect precision; it has earned 0.0 and a
   recall of 0.0. See `Counts.precision`.

2. **Micro is the headline.** Per-document averaging (macro) is dominated by
   documents with one or two gold items, where a single miss swings F1 from
   1.0 to 0.0, and by the degenerate empty/empty documents that convention 1
   has to invent an answer for. Micro pools tp/fp/fn across the corpus first
   and divides once, so every gold item carries the same weight regardless of
   which document it came from. Macro is reported alongside it because a large
   gap between the two is itself informative: it means performance depends on
   document length.

3. **A failed extraction is scored, not skipped.** If the model returns
   unparseable JSON the pipeline writes no rows, so the prediction set is
   empty and every gold item counts as a false negative. That is what the
   dataset would actually look like, and it is the honest treatment for the
   §7 cross-backend comparison, where a smaller local model fails outright
   more often than it extracts badly.
"""

from __future__ import annotations

from collections.abc import Iterable, Set
from dataclasses import dataclass


@dataclass(frozen=True)
class Counts:
    """One confusion-matrix cell triple. Addable, so micro-averaging across
    documents or field types is `sum(...)` rather than a bespoke function."""

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
        """Of what was predicted, how much was right.

        No predictions is the only interesting edge: it is 1.0 when the gold
        set was also empty (correctly staying silent) and 0.0 otherwise
        (silence on a document that had answers is not precision).
        """
        if self.predicted == 0:
            return 1.0 if self.fn == 0 else 0.0
        return self.tp / self.predicted

    @property
    def recall(self) -> float:
        """Of what was there, how much was found.

        Mirror of `precision`: an empty gold set is vacuously fully recalled,
        but only if nothing was predicted either -- otherwise the system
        invented items and 0.0 is the honest score.
        """
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
        """True when there was nothing to predict and nothing was predicted.

        Such a document carries no signal: the scores are 1.0 by convention,
        not by performance. Macro-averaging excludes it (see `macro_f1`) so a
        gold set with many empty fields cannot inflate its own numbers.
        """
        return self.predicted == 0 and self.support == 0


def score_sets(predicted: Set[str], gold: Set[str]) -> Counts:
    """The whole metric, in three set operations.

    Membership is exact string equality, so every normalization decision
    (technique granularity, actor canonicalization, sector vocabulary) has to
    happen before this call and be visible in the caller. That is on purpose:
    fuzzy matching hidden inside a scorer is how eval numbers stop meaning
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
    """Mean of per-document F1, excluding degenerate documents.

    None when every document was degenerate -- there is no number to report,
    and returning 0.0 or 1.0 there would both be lies.
    """
    scored = [c.f1 for c in counts if not c.degenerate]
    if not scored:
        return None
    return sum(scored) / len(scored)


def rate(numerator: int, denominator: int) -> float | None:
    """Plain ratio for the diagnostic lines (evidence-quote validity, etc.).

    None rather than 0.0 on an empty denominator: "no technique mentions were
    emitted, so there is no validity rate" and "every quote was invalid" are
    opposite findings and must not print identically.
    """
    if denominator == 0:
        return None
    return numerator / denominator


# ---------- technique granularity (DESIGN.md §7) ----------


def parent_technique(technique_id: str) -> str:
    """'T1566.001' -> 'T1566'; 'T1566' -> 'T1566'.

    Parent-level scoring exists because sub-technique choice is often a
    judgement call the source text does not settle (is a malicious link in a
    mail T1566.001 or T1566.002?), while the parent claim -- this report
    describes phishing -- is unambiguous. §7 sets the >0.85 F1 target at
    parent granularity for that reason, and both are reported so the gap
    between them shows how much of the error is granularity rather than
    substance.
    """
    return technique_id.split(".", 1)[0]


def to_parents(technique_ids: Set[str]) -> set[str]:
    """Roll a set up to parents. Collapsing is the point: a prediction of both
    T1566.001 and T1566.002 against a gold T1566 is one correct parent claim,
    not one hit and one false positive."""
    return {parent_technique(tid) for tid in technique_ids}
