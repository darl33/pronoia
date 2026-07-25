"""The guardrails composed: a single schema-valid Extraction carrying one good
and one bad instance of each failure mode, run through validate_extraction.

This is the test that would catch a guardrail being implemented correctly but
never wired into the write path.
"""

from __future__ import annotations

import uuid

import pytest

from enrich.actors import ActorIndex
from enrich.contract import Extraction
from enrich.techniques import TechniqueIndex
from enrich.validate import validate_extraction
from tests.fixtures import SYNTHETIC_REPORT

FAKEBEAR_ID = uuid.uuid4()

ACTOR_ROWS = [
    {"id": FAKEBEAR_ID, "canonical_name": "FAKEBEAR", "aliases": ["Test Panda"]},
]
KNOWN_TECHNIQUES = {"T1566.001", "T1053.005", "T1059.001"}

MIXED_EXTRACTION = Extraction.model_validate(
    {
        "summary": "A synthetic campaign against water utilities in AU and NZ.",
        "report_date": "2026-02-01",
        "confidence": "medium",
        "actors": [
            {"name": "FAKEBEAR", "attribution_confidence": "confirmed_by_source"},
            {"name": "Nonexistent Bear", "attribution_confidence": "suspected"},
        ],
        "techniques": [
            # good: real ID, verbatim quote
            {
                "technique_id": "T1566.001",
                "evidence_quote": "The operators received spear-phishing emails",
            },
            # bad: hallucinated ID (guardrail 2)
            {
                "technique_id": "T1566.009",
                "evidence_quote": "carrying a malicious spreadsheet attachment",
            },
            # bad: real ID, fabricated quote (guardrail 3)
            {
                "technique_id": "T1059.001",
                "evidence_quote": "The actor deployed a bespoke Go implant on every host.",
            },
            # good: real ID, verbatim quote
            {
                "technique_id": "T1053.005",
                "evidence_quote": "creating a scheduled task named",
            },
        ],
        "targets": [{"country": "AU", "sector": "water"}, {"country": "NZ", "sector": "water"}],
        "iocs": [
            {"kind": "ipv4", "value": "192.0.2.44"},
            {"kind": "domain", "value": "updates.watersync.example"},
            # bad: a URL wearing a hash's label (§6)
            {"kind": "sha256", "value": "https://updates.watersync.example/payload.bin"},
        ],
    }
)


@pytest.fixture
def validated():
    return validate_extraction(
        MIXED_EXTRACTION,
        clean_text=SYNTHETIC_REPORT,
        technique_index=TechniqueIndex(KNOWN_TECHNIQUES),
        actor_index=ActorIndex(ACTOR_ROWS),
    )


def test_only_supported_techniques_survive(validated):
    assert {t.technique_id for t in validated.techniques} == {"T1566.001", "T1053.005"}


def test_each_surviving_technique_kept_its_quote(validated):
    for technique in validated.techniques:
        assert technique.evidence_quote


def test_hallucinated_id_and_fabricated_quote_are_dropped_for_different_reasons(validated):
    by_guardrail = {d.guardrail for d in validated.drops}
    assert "closed_world_technique" in by_guardrail
    assert "evidence_quote" in by_guardrail

    closed_world = [d for d in validated.drops if d.guardrail == "closed_world_technique"]
    assert closed_world[0].value == "T1566.009"

    evidence = [d for d in validated.drops if d.guardrail == "evidence_quote"]
    assert evidence[0].value.startswith("T1059.001")


def test_known_actor_resolves_and_unknown_one_is_queued(validated):
    assert [a.actor_id for a in validated.actors] == [FAKEBEAR_ID]
    assert [u.raw_name for u in validated.review_queue] == ["Nonexistent Bear"]


def test_queued_actor_keeps_its_attribution_confidence(validated):
    """The review queue has to carry enough to write report_actor later if a
    human accepts the name."""
    assert validated.review_queue[0].attribution_confidence == "suspected"


def test_only_defanged_iocs_survive(validated):
    stored = {(i.kind, i.value_defanged) for i in validated.iocs}
    assert stored == {
        ("ipv4", "192[.]0[.]2[.]44"),
        ("domain", "updates[.]watersync[.]example"),
    }


def test_no_fanged_value_appears_anywhere_in_the_result(validated):
    """§6: the fanged form is never stored or emitted -- including in the drop
    records, which get logged."""
    surfaces = [i.value_defanged for i in validated.iocs]
    surfaces += [f"{d.guardrail} {d.value} {d.reason}" for d in validated.drops]
    blob = " ".join(surfaces)

    assert "https://updates.watersync.example" not in blob
    assert "updates.watersync.example" not in blob
    assert "192.0.2.44" not in blob


def test_targets_pass_through_unchanged(validated):
    countries = {t.country for t in validated.extraction.targets}
    assert countries == {"AU", "NZ"}
