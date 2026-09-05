"""The non-LLM baseline (DESIGN.md §7): regex for technique IDs the document
cites by ID, alias string matching for actors.

Built to be beaten, and its weaknesses are the argument. It shares the
closed-world check and the target vocabulary with the real path so the
comparison isolates extraction. Rationale: docs/DECISIONS.md#baseline
"""

from __future__ import annotations

import re

from eval.gold import GoldFixture
from eval.predict import Prediction
from eval.vocab import find_countries, find_sectors

# ATT&CK ID as written in prose -- same shape enrich/techniques.py accepts.
TECHNIQUE_ID_RE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")

# Shorter aliases are dropped: MISP carries fragments like "APT" that match
# half of English, and a baseline tagging every document is noise, not a floor.
MIN_ALIAS_CHARS = 4


def _boundary(term: str) -> str:
    """\\b fails next to a leading '(' or a trailing '.', both of which occur
    in MISP alias strings. Lookarounds for a word character are equivalent
    where \\b works and correct where it doesn't."""
    return rf"(?<!\w){re.escape(term)}(?!\w)"


class KeywordBaseline:
    """Built once per run from the same reference data the pipeline loads."""

    def __init__(self, actor_rows, technique_index):
        self._technique_index = technique_index

        # name -> canonical name, so both systems answer in one vocabulary.
        self._canonical_by_name: dict[str, str] = {}
        for row in actor_rows:
            canonical = row["canonical_name"]
            for name in [canonical, *(row["aliases"] or [])]:
                if not name or len(name) < MIN_ALIAS_CHARS or name.isdigit():
                    continue
                # First writer wins, mirroring ActorIndex.
                self._canonical_by_name.setdefault(name.casefold(), canonical)

        # One longest-first alternation, not ~5k searches per document.
        # Longest-first matters: "APT 28" must win over "APT 2".
        names = sorted(self._canonical_by_name, key=len, reverse=True)
        self._actor_re = re.compile("|".join(_boundary(name) for name in names), re.IGNORECASE)

    def predict(self, fixture: GoldFixture) -> Prediction:
        text = fixture.text

        emitted = TECHNIQUE_ID_RE.findall(text)
        techniques = {
            technique_id
            for technique_id in emitted
            if self._technique_index.check(technique_id).ok
        }

        actors = {
            self._canonical_by_name[match.group(0).casefold()]
            for match in self._actor_re.finditer(text)
        }

        return Prediction(
            fixture_id=fixture.id,
            system="baseline",
            actors=actors,
            techniques=techniques,
            countries=find_countries(text),
            sectors=find_sectors(text),
            # Recorded for shape parity only; the scorecard prints these as
            # n/a rather than as achievements (docs/DECISIONS.md#baseline).
            techniques_emitted=len(emitted),
            techniques_closed_world_ok=len(techniques),
            actors_emitted=len(actors),
        )
