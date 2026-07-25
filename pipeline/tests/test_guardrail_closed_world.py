"""Guardrail 2 (DESIGN.md §5.2): a technique ID not present in
attack_technique is dropped and logged."""

from __future__ import annotations

import pytest

from enrich.techniques import TechniqueIndex

# Stand-in for the loaded ATT&CK table; the real one has ~800 entries.
KNOWN = {"T1566", "T1566.001", "T1053.005", "T1059.001", "T1071.001"}


@pytest.fixture
def index():
    return TechniqueIndex(KNOWN)


def test_hallucinated_subtechnique_is_dropped(index):
    """The canonical failure: T1566.001 through .003 exist, so .009 looks
    entirely plausible to a reader and to the model that produced it."""
    result = index.check("T1566.009")
    assert not result.ok
    assert "closed world" in result.reason


def test_hallucinated_technique_is_dropped(index):
    result = index.check("T9999")
    assert not result.ok
    assert "closed world" in result.reason


def test_malformed_id_is_dropped_with_a_distinct_reason(index):
    """Separating 'made up an ID' from 'emitted something that isn't an ID'
    keeps the drop log useful when diagnosing a prompt regression."""
    for junk in ["spearphishing", "T-1566", "1566.001", "TA0001", ""]:
        result = index.check(junk)
        assert not result.ok, junk
        assert result.reason == "not a well-formed ATT&CK technique ID", junk


def test_known_ids_are_accepted(index):
    for technique_id in KNOWN:
        assert index.check(technique_id).ok, technique_id


def test_lookup_is_case_insensitive_and_whitespace_tolerant(index):
    assert index.check(" t1566.001 ").ok


def test_parent_is_not_implied_by_a_known_subtechnique():
    """T1053.005 being known must not make T1053 pass. §7 scores techniques at
    both granularities separately, so silently promoting one to the other would
    corrupt the eval as well as the data."""
    index = TechniqueIndex({"T1053.005"})
    assert not index.check("T1053").ok
