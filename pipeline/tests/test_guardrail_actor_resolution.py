"""Guardrail 4 (DESIGN.md §5.2): free-text actor names resolve against
canonical names and aliases, or go to the review queue -- never silently into
the dataset."""

from __future__ import annotations

import uuid

import pytest

from enrich.actors import ActorIndex

SANDWORM = uuid.uuid4()
APT1 = uuid.uuid4()

ROWS = [
    {
        "id": SANDWORM,
        "canonical_name": "Sandworm Team",
        "aliases": ["APT44", "Voodoo Bear", "IRIDIUM", "Seashell Blizzard"],
    },
    {"id": APT1, "canonical_name": "APT1", "aliases": ["Comment Crew", "PLA Unit 61398"]},
]


@pytest.fixture
def index():
    return ActorIndex(ROWS)


# ---- the bad case: unknown names are routed to review, not invented ----


def test_unknown_actor_is_not_resolved(index):
    result = index.resolve("FAKEBEAR")
    assert not result.resolved
    assert result.actor_id is None


def test_unresolved_name_carries_its_near_miss_for_the_reviewer(index):
    """The review queue row should tell a human what it almost matched, so
    triaging a genuine new alias is cheap."""
    result = index.resolve("Sandworm Squad")
    assert not result.resolved
    assert result.best_match_name == "Sandworm Team"
    assert 0.0 < result.best_match_score <= 0.9


def test_a_different_group_is_not_fuzzy_matched_onto_a_known_one(index):
    """APT1 and APT41 are one character apart and are unrelated groups. This is
    the case that makes a loose fuzzy threshold actively dangerous rather than
    merely noisy."""
    result = index.resolve("APT41")
    assert not result.resolved


def test_empty_name_is_not_resolved(index):
    assert not index.resolve("   ").resolved


# ---- the good case: real names and aliases resolve ----


def test_canonical_name_resolves(index):
    result = index.resolve("Sandworm Team")
    assert result.actor_id == SANDWORM
    assert result.method == "exact"


def test_alias_resolves_to_the_same_actor(index):
    """The whole point of the alias table: two vendors' names for one group
    have to become one row or the §8 correlation queries are meaningless."""
    assert index.resolve("APT44").actor_id == SANDWORM
    assert index.resolve("Seashell Blizzard").actor_id == SANDWORM


def test_resolution_is_case_and_whitespace_insensitive(index):
    result = index.resolve("  sandworm   team ")
    assert result.actor_id == SANDWORM
    assert result.method == "exact"


def test_close_typo_resolves_by_fuzzy_match(index):
    result = index.resolve("Sandwrom Team")
    assert result.actor_id == SANDWORM
    assert result.method == "fuzzy"
    assert result.best_match_score > 0.9
