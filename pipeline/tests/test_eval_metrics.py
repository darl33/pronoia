"""The metric arithmetic (eval/metrics.py) and every convention the scorecard
depends on: zero denominators, micro vs macro, technique granularity. These are
the numbers §7 reports, so they are pinned rather than rediscovered from code.
"""

from __future__ import annotations

import pytest

from eval.metrics import (
    Counts,
    macro_f1,
    micro,
    parent_technique,
    rate,
    score_sets,
    to_parents,
)


def test_perfect_match():
    counts = score_sets({"a", "b"}, {"a", "b"})
    assert (counts.tp, counts.fp, counts.fn) == (2, 0, 0)
    assert counts.precision == counts.recall == counts.f1 == 1.0


def test_no_overlap():
    counts = score_sets({"a"}, {"b"})
    assert (counts.tp, counts.fp, counts.fn) == (0, 1, 1)
    assert counts.precision == counts.recall == counts.f1 == 0.0


def test_partial_match():
    # predicted {a,b,c} vs gold {a,b,d}: 2 hits, 1 invented, 1 missed
    counts = score_sets({"a", "b", "c"}, {"a", "b", "d"})
    assert (counts.tp, counts.fp, counts.fn) == (2, 1, 1)
    assert counts.precision == pytest.approx(2 / 3)
    assert counts.recall == pytest.approx(2 / 3)
    assert counts.f1 == pytest.approx(2 / 3)


def test_f1_is_the_harmonic_mean():
    counts = Counts(tp=3, fp=1, fn=3)  # P = 0.75, R = 0.5
    assert counts.precision == 0.75
    assert counts.recall == 0.5
    assert counts.f1 == pytest.approx(2 * 0.75 * 0.5 / 1.25)


# ---- the zero-denominator conventions ----


def test_silence_on_a_document_with_answers_scores_zero():
    """The convention that matters most: a failed extraction predicts nothing,
    and must not collect a vacuous precision of 1.0 for it."""
    counts = score_sets(set(), {"a", "b"})
    assert (counts.tp, counts.fp, counts.fn) == (0, 0, 2)
    assert counts.precision == 0.0
    assert counts.recall == 0.0
    assert counts.f1 == 0.0
    assert not counts.degenerate


def test_inventing_items_against_an_empty_gold_set_scores_zero():
    counts = score_sets({"a"}, set())
    assert counts.precision == 0.0
    assert counts.recall == 0.0
    assert not counts.degenerate


def test_correct_silence_is_vacuously_perfect_but_degenerate():
    counts = score_sets(set(), set())
    assert counts.precision == counts.recall == counts.f1 == 1.0
    # ...and therefore excluded from the macro mean: 1.0 by convention, not by
    # performance.
    assert counts.degenerate


# ---- aggregation ----


def test_counts_add_and_sum():
    assert Counts(1, 2, 3) + Counts(10, 20, 30) == Counts(11, 22, 33)
    assert sum([Counts(1, 0, 0), Counts(0, 1, 0), Counts(0, 0, 1)]) == Counts(1, 1, 1)


def test_micro_and_macro_answer_different_questions():
    """Micro pools first; macro averages per-document F1. Same two documents,
    different numbers -- which is why the scorecard prints both."""
    document_a = score_sets({"a", "b"}, {"a", "b"})   # F1 1.0
    document_b = score_sets(set(), {"c", "d", "e"})   # F1 0.0

    pooled = micro([document_a, document_b])
    assert (pooled.tp, pooled.fp, pooled.fn) == (2, 0, 3)
    assert pooled.precision == 1.0
    assert pooled.recall == pytest.approx(0.4)
    assert pooled.f1 == pytest.approx(2 * 1.0 * 0.4 / 1.4)   # 0.5714

    assert macro_f1([document_a, document_b]) == pytest.approx(0.5)


def test_macro_excludes_degenerate_documents():
    scored = score_sets({"a"}, {"a"})           # F1 1.0
    empty = score_sets(set(), set())            # degenerate
    missed = score_sets(set(), {"b"})           # F1 0.0

    # The degenerate document must not drag the mean toward 1.0.
    assert macro_f1([scored, empty, missed]) == pytest.approx(0.5)
    assert macro_f1([empty, empty]) is None


def test_rate_distinguishes_no_data_from_zero():
    assert rate(0, 4) == 0.0      # every quote was invalid
    assert rate(0, 0) is None     # no quotes were emitted -- a different finding
    assert rate(3, 4) == 0.75


# ---- technique granularity (§7) ----


def test_parent_technique_rollup():
    assert parent_technique("T1566.001") == "T1566"
    assert parent_technique("T1566") == "T1566"


def test_sub_technique_disagreement_is_a_parent_level_hit():
    """The reason §7 reports both. Predicting the wrong sub-technique of the
    right parent is a total miss at sub granularity and correct at parent."""
    predicted, gold = {"T1566.002"}, {"T1566.001"}

    assert score_sets(predicted, gold).f1 == 0.0
    assert score_sets(to_parents(predicted), to_parents(gold)).f1 == 1.0


def test_parent_rollup_collapses_rather_than_multiplying_errors():
    """Two sub-techniques of one parent against a parent-level gold annotation
    is one right answer, not one hit and one false positive."""
    counts = score_sets(to_parents({"T1566.001", "T1566.002"}), to_parents({"T1566"}))
    assert (counts.tp, counts.fp, counts.fn) == (1, 0, 0)
