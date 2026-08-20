"""The non-LLM baseline (eval/baseline.py).

These pin the baseline's *weaknesses* as much as its behaviour: it exists to be
beaten (§7), and one that quietly got stronger -- matching technique names, or
learning to tell a victim from an attacker -- would shrink the measured LLM lift
without anyone noticing.
"""

from __future__ import annotations

import pytest

from enrich.actors import ActorIndex
from enrich.techniques import TechniqueIndex
from eval.baseline import KeywordBaseline
from eval.gold import GOLD_DIR, load_gold_set
from eval.score import score_document
from tests.test_eval_gold import ACTOR_ROWS, TECHNIQUE_IDS


@pytest.fixture
def fixtures():
    gold_set = load_gold_set(
        GOLD_DIR,
        technique_index=TechniqueIndex(TECHNIQUE_IDS),
        actor_index=ActorIndex(ACTOR_ROWS),
    )
    return {fixture.id: fixture for fixture in gold_set.fixtures}


@pytest.fixture
def baseline():
    return KeywordBaseline(ACTOR_ROWS, TechniqueIndex(TECHNIQUE_IDS))


def test_finds_only_technique_ids_written_in_the_document(baseline, fixtures):
    """The defining limitation. 0001 describes six techniques and writes one
    ID; the baseline gets that one and nothing else."""
    fixture = fixtures["0001-volt-typhoon-utilities"]
    prediction = baseline.predict(fixture)

    assert prediction.techniques == {"T1090"}
    assert prediction.techniques == {
        t.technique_id for t in fixture.annotation.techniques if t.explicit_in_text
    }


def test_recovers_a_published_attack_table(baseline, fixtures):
    """And the other shape: an advisory that publishes its own ATT&CK table
    hands the baseline three of five techniques for free."""
    prediction = baseline.predict(fixtures["0002-fin7-health-ransomware"])
    assert prediction.techniques == {"T1190", "T1486", "T1567.002"}


def test_implicit_techniques_are_structurally_unreachable(baseline, fixtures):
    """The number §7's lift column is measured against: zero, by construction."""
    for fixture in fixtures.values():
        prediction = baseline.predict(fixture)
        assert not (prediction.techniques & fixture.implicit_technique_ids())


def test_closed_world_filter_applies_to_the_baseline_too(fixtures):
    """Both systems get guardrail 2, so the comparison isolates extraction
    quality rather than rewarding the LLM for post-processing."""
    narrow = KeywordBaseline(ACTOR_ROWS, TechniqueIndex({"T1090"}))
    prediction = narrow.predict(fixtures["0002-fin7-health-ransomware"])

    assert prediction.techniques == set()
    assert prediction.techniques_emitted == 3  # found in text, then dropped


def test_resolves_matched_names_to_canonical_names(baseline, fixtures):
    """Alias matching has to land in the same vocabulary the LLM path reports
    in, or the two systems are scored against different gold sets."""
    assert baseline.predict(fixtures["0001-volt-typhoon-utilities"]).actors == {"Volt Typhoon"}
    assert baseline.predict(fixtures["0002-fin7-health-ransomware"]).actors == {"FIN7"}


def test_alias_in_text_resolves_to_the_canonical_name(baseline):
    class _Fixture:
        id = "synthetic"
        text = "Activity described here has been linked to BRONZE SILHOUETTE by two vendors."

    assert baseline.predict(_Fixture()).actors == {"Volt Typhoon"}


def test_cannot_tell_a_victim_from_relay_infrastructure(baseline, fixtures):
    """The precision failure §7 predicts. 0001's gold targets are AU only; NZ
    appears solely as the location of relay infrastructure, and the baseline
    has no way to know the difference."""
    fixture = fixtures["0001-volt-typhoon-utilities"]
    prediction = baseline.predict(fixture)

    assert "AU" in prediction.countries
    assert "NZ" in prediction.countries
    assert fixture.countries() == {"AU"}

    counts = score_document(fixture, prediction).counts["targets: countries"]
    assert counts.tp == 1 and counts.fp >= 1


def test_lowercase_us_is_not_a_country(baseline):
    """The abbreviation table is case-sensitive on purpose: a case-insensitive
    'US' matches the pronoun and would put a country on nearly every
    document."""
    class _Fixture:
        id = "synthetic"
        text = "The vendor told us that the campaign continued for several months."

    assert baseline.predict(_Fixture()).countries == set()


def test_finds_countries_and_sectors_from_the_vocabulary(baseline, fixtures):
    prediction = baseline.predict(fixtures["0002-fin7-health-ransomware"])
    assert {"US", "CA"} <= prediction.countries
    assert "health care" in prediction.sectors
