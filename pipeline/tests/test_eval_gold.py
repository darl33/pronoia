"""Gold-set loading and validation (eval/gold.py).

The loader's job is to make a bad annotation loud. A gold set that silently
disagrees with the pipeline's vocabulary produces a depressed score that looks
exactly like a model failure, which is the single most expensive way for an
eval to be wrong.
"""

from __future__ import annotations

import json

import pytest

from enrich.actors import ActorIndex
from enrich.techniques import TechniqueIndex
from eval.gold import GOLD_DIR, load_gold_set
from eval.vocab import normalize_sector

ACTOR_ROWS = [
    {"id": "actor-volt", "canonical_name": "Volt Typhoon", "aliases": ["BRONZE SILHOUETTE"]},
    {"id": "actor-fin7", "canonical_name": "FIN7", "aliases": ["Carbon Spider"]},
]

TECHNIQUE_IDS = {
    "T1078", "T1133", "T1059.001", "T1082", "T1021.001", "T1090",
    "T1190", "T1486", "T1567.002", "T1566.001", "T1053.005",
}


@pytest.fixture
def indexes():
    return TechniqueIndex(TECHNIQUE_IDS), ActorIndex(ACTOR_ROWS)


def test_shipped_gold_set_loads_clean(indexes):
    technique_index, actor_index = indexes
    gold_set = load_gold_set(
        GOLD_DIR, technique_index=technique_index, actor_index=actor_index
    )

    assert [f.id for f in gold_set.fixtures] == [
        "0001-volt-typhoon-utilities",
        "0002-fin7-health-ransomware",
    ]
    assert len(gold_set.placeholders) == 3
    assert gold_set.defects == []


def test_worked_example_annotation(indexes):
    technique_index, actor_index = indexes
    gold_set = load_gold_set(
        GOLD_DIR, technique_index=technique_index, actor_index=actor_index
    )
    fixture = gold_set.fixtures[0]

    assert fixture.text.strip(), "the sibling .txt must be loaded onto the fixture"
    assert fixture.technique_ids() == {
        "T1078", "T1133", "T1059.001", "T1082", "T1021.001", "T1090"
    }
    # Exactly one technique is cited by ID in the prose; the rest is the
    # implicit subset the baseline structurally cannot reach.
    assert fixture.implicit_technique_ids() == fixture.technique_ids() - {"T1090"}
    assert fixture.countries() == {"AU"}
    assert fixture.sectors() == {"water and sewerage", "energy"}


def test_explicit_flag_matches_the_document_text(indexes):
    """The annotation that carries the whole baseline comparison: if a
    technique is marked explicit, its ID has to actually be in the text."""
    technique_index, actor_index = indexes
    gold_set = load_gold_set(
        GOLD_DIR, technique_index=technique_index, actor_index=actor_index
    )

    for fixture in gold_set.fixtures:
        for technique in fixture.annotation.techniques:
            written = technique.technique_id in fixture.text
            assert written == technique.explicit_in_text, (
                f"{fixture.id}: {technique.technique_id} is marked "
                f"explicit_in_text={technique.explicit_in_text} but "
                f"{'is' if written else 'is not'} written in the document"
            )


def test_placeholders_are_never_scored(indexes):
    technique_index, actor_index = indexes
    gold_set = load_gold_set(
        GOLD_DIR, technique_index=technique_index, actor_index=actor_index
    )

    assert all(f.status == "placeholder" for f in gold_set.placeholders)
    assert all(not f.annotation.actors for f in gold_set.placeholders)
    # An empty annotation scored as real would report a fabricated recall of 1.0.
    assert not any(f.id.startswith("0003") for f in gold_set.fixtures)


# ---- defects: annotations the pipeline's reference data cannot express ----


def _write_fixture(directory, payload, text="Some report text for the fixture."):
    (directory / payload["document"]["text_file"]).write_text(text, encoding="utf-8")
    (directory / f"{payload['id']}.json").write_text(json.dumps(payload), encoding="utf-8")


def _payload(fixture_id, **annotation):
    return {
        "id": fixture_id,
        "status": "annotated",
        "document": {
            "text_file": f"{fixture_id}.txt",
            "title": "Test",
            "source_kind": "synthetic",
        },
        "annotation": {"actors": [], "techniques": [], "targets": [], **annotation},
    }


def test_unknown_technique_is_reported_as_a_gold_defect(tmp_path, indexes):
    technique_index, actor_index = indexes
    _write_fixture(tmp_path, _payload(
        "bad-technique",
        techniques=[{"technique_id": "T9999.999", "explicit_in_text": False}],
    ))

    gold_set = load_gold_set(tmp_path, technique_index=technique_index, actor_index=actor_index)
    assert len(gold_set.defects) == 1
    assert "T9999.999" in gold_set.defects[0]


def test_unresolvable_actor_is_reported_as_a_gold_defect(tmp_path, indexes):
    technique_index, actor_index = indexes
    _write_fixture(tmp_path, _payload(
        "bad-actor", actors=[{"name": "Nobody In Particular"}]
    ))

    gold_set = load_gold_set(tmp_path, technique_index=technique_index, actor_index=actor_index)
    assert len(gold_set.defects) == 1
    assert "does not resolve" in gold_set.defects[0]


def test_actor_alias_resolves(tmp_path, indexes):
    """Gold may use an alias: both sides go through the same ActorIndex, which
    is what guardrail 4 exists to make true."""
    technique_index, actor_index = indexes
    _write_fixture(tmp_path, _payload("alias", actors=[{"name": "Carbon Spider"}]))

    gold_set = load_gold_set(tmp_path, technique_index=technique_index, actor_index=actor_index)
    assert gold_set.defects == []


def test_off_vocabulary_sector_is_reported(tmp_path, indexes):
    technique_index, actor_index = indexes
    _write_fixture(tmp_path, _payload("bad-sector", targets=[{"sector": "aerospace parts"}]))

    gold_set = load_gold_set(tmp_path, technique_index=technique_index, actor_index=actor_index)
    assert len(gold_set.defects) == 1
    assert "controlled vocabulary" in gold_set.defects[0]


def test_unknown_key_is_rejected(tmp_path, indexes):
    payload = _payload("typo")
    payload["annotations"] = []  # plural: a plausible hand-edit typo
    _write_fixture(tmp_path, payload)

    with pytest.raises(Exception, match="annotations"):
        load_gold_set(tmp_path)


def test_inline_text_is_rejected(tmp_path):
    payload = _payload("inline")
    payload["text"] = "the document"
    _write_fixture(tmp_path, payload)

    with pytest.raises(ValueError, match="sibling .txt"):
        load_gold_set(tmp_path)


def test_missing_text_file_is_rejected(tmp_path):
    payload = _payload("orphan")
    (tmp_path / "orphan.json").write_text(json.dumps(payload), encoding="utf-8")

    with pytest.raises(FileNotFoundError, match="orphan.txt"):
        load_gold_set(tmp_path)


def test_target_needs_a_country_or_a_sector(tmp_path):
    _write_fixture(tmp_path, _payload("empty-target", targets=[{}]))

    with pytest.raises(Exception, match="country, a sector, or both"):
        load_gold_set(tmp_path)


# ---- sector normalization: applied to both sides before scoring ----


@pytest.mark.parametrize(
    "surface,expected",
    [
        ("Health Care", "health care"),
        ("healthcare", "health care"),
        ("Healthcare sector", "health care"),
        ("energy", "energy"),
        ("Energy Sector", "energy"),
        ("telecommunications", "communications"),
        ("aviation", "transport"),
        ("water", "water and sewerage"),
        ("defence industry", "defence industry"),   # not truncated to "defence"
        ("aerospace parts", "aerospace parts"),     # off-vocabulary, left alone
    ],
)
def test_normalize_sector(surface, expected):
    assert normalize_sector(surface) == expected
