"""Guardrail 3 (DESIGN.md §5.2): a technique mention whose evidence quote is
not a verbatim span of clean_text is dropped."""

from __future__ import annotations

import pytest

from enrich.evidence import MIN_QUOTE_CHARS, EvidenceIndex
from tests.fixtures import SYNTHETIC_REPORT, SYNTHETIC_REPORT_WRAPPED


@pytest.fixture
def index():
    return EvidenceIndex(SYNTHETIC_REPORT)


# ---- the bad case: fabricated evidence is dropped ----


def test_fabricated_quote_is_dropped(index):
    """The core case: the model describes a technique the report doesn't
    contain, and invents a plausible sentence to support it."""
    result = index.check(
        "The actor deployed ransomware across the domain controllers overnight."
    )
    assert not result.ok
    assert result.reason == "quote does not appear in clean_text"


def test_paraphrase_of_a_real_sentence_is_dropped(index):
    """The report really does describe spear-phishing -- but this quote is a
    paraphrase, not a span. Paraphrase is exactly what the guardrail exists to
    catch, because it is where a real claim and a fabricated one look alike."""
    result = index.check("The operators were sent spear-phishing emails with a malicious attachment")
    assert not result.ok


def test_recased_quote_is_dropped(index):
    """Verbatim means verbatim. A re-cased span means the model retyped the
    sentence rather than copying it, so we can no longer tell what it read."""
    result = index.check("THE OPERATORS RECEIVED SPEAR-PHISHING EMAILS")
    assert not result.ok


def test_elided_quote_is_dropped(index):
    """Both halves appear in the report, but an ellipsis lets a model join
    unrelated spans and imply a claim the document never makes."""
    result = index.check("The operators received spear-phishing emails ... deployed ransomware")
    assert not result.ok
    assert "elision" in result.reason


def test_short_generic_quote_is_dropped(index):
    """'The actor' does appear in the report, and supports nothing."""
    result = index.check("The actor")
    assert not result.ok
    assert f"{MIN_QUOTE_CHARS}-char floor" in result.reason


def test_empty_quote_is_dropped(index):
    assert not index.check("").ok


# ---- the good case: real evidence survives ----


def test_verbatim_quote_is_accepted(index):
    assert index.check("The operators received spear-phishing emails").ok


def test_quote_spanning_a_line_break_is_accepted():
    """html_to_clean_text splits on block elements, so a real quote routinely
    straddles a newline in clean_text while the model returns it as one line.
    Forgiving whitespace here is what keeps the guardrail from being a
    false-positive machine on real vendor HTML."""
    index = EvidenceIndex(SYNTHETIC_REPORT_WRAPPED)
    assert index.check("carrying a malicious spreadsheet attachment").ok


def test_typographic_quote_variants_are_accepted():
    """A CMS renders smart quotes; a model retypes ASCII ones. Same span."""
    index = EvidenceIndex('a scheduled task named “WaterSyncUpdate” that re-launched it')
    assert index.check('a scheduled task named "WaterSyncUpdate" that re-launched it').ok


def test_non_breaking_space_is_accepted():
    """NBSP survives the HTML->text path; a model returns a plain space."""
    index = EvidenceIndex("Command-and-control traffic was directed to the staging host")
    assert index.check("Command-and-control traffic was directed to the staging host").ok
