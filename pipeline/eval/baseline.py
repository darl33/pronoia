"""The non-LLM baseline (DESIGN.md §7).

> a non-LLM baseline (regex for technique IDs explicitly cited in text + alias
> string matching for actors) to demonstrate the LLM's lift on *implicit*
> technique description. Cheap to build, makes the comparison honest.

It is built to be beaten, and its weaknesses are the argument. Three of them
are worth naming because each one predicts a specific column in the scorecard:

* **Techniques.** It finds a technique only where the document writes the ID
  out. Vendor reports mostly describe behaviour ("the operator scheduled a
  task that relaunched the loader hourly") and never name T1053.005, so the
  baseline's technique recall is roughly the fraction of the gold set marked
  `explicit_in_text`. The gap between that and the model's recall on the
  implicit subset is the number §7 wants.
* **Actors.** Alias matching is strong here, and it should be: this is the one
  field where a string search is close to the right algorithm, and if the LLM
  does not beat it by much, that is a true finding rather than a broken
  baseline.
* **Targets.** It cannot tell a victim from an attacker. "Russian
  state-sponsored actors targeting Ukrainian energy" yields RU and UA both,
  where the gold set has only UA. Precision suffers exactly where the §5.2
  attribution-discipline rule in the prompt is doing work.

It shares the closed-world technique check and the country/sector vocabulary
with the real path, so the comparison isolates extraction quality rather than
rewarding the LLM for post-processing the baseline does not get.
"""

from __future__ import annotations

import re

from eval.gold import GoldFixture
from eval.predict import Prediction
from eval.vocab import find_countries, find_sectors

# ATT&CK enterprise ID as written in prose. Same shape the closed-world
# guardrail accepts (enrich/techniques.py), matched rather than anchored.
TECHNIQUE_ID_RE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")

# Aliases shorter than this are dropped: MISP carries fragments like "APT" and
# bare group numbers that match half of English. A baseline is allowed to be
# dumb, but a baseline that tags every document with six actors is noise, not
# a floor to measure against.
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

        # name -> canonical name, so the baseline's output is in the same
        # vocabulary as the LLM path's (which reports resolved canonical
        # names). Matching an alias and reporting the alias would score as a
        # miss against a canonical-name gold set for the wrong reason.
        self._canonical_by_name: dict[str, str] = {}
        for row in actor_rows:
            canonical = row["canonical_name"]
            for name in [canonical, *(row["aliases"] or [])]:
                if not name or len(name) < MIN_ALIAS_CHARS or name.isdigit():
                    continue
                # First writer wins, mirroring ActorIndex: MISP aliases collide
                # across clusters and rebinding by load order would make the
                # baseline's answers depend on JSON key order.
                self._canonical_by_name.setdefault(name.casefold(), canonical)

        # One alternation, longest-first, rather than a loop of ~5k searches
        # per document. Longest-first matters: "APT 28" must win over "APT 2"
        # where both are known aliases.
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
            # The baseline cites IDs verbatim from the document, so its
            # "evidence" is trivially valid and its closed-world pass rate is
            # whatever ATT&CK says about the IDs the author wrote. Both are
            # recorded for shape parity; neither is an interesting number, and
            # the scorecard says so rather than printing them as achievements.
            techniques_emitted=len(emitted),
            techniques_closed_world_ok=len(techniques),
            actors_emitted=len(actors),
        )
