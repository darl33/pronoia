"""Guardrail 4 (DESIGN.md §5.2): actor name resolution.

Free-text names resolve against threat_actor canonical names and aliases --
exact first, then difflib above FUZZY_THRESHOLD. Unresolved names go to
actor_review_queue, never into report_actor.

Rationale: docs/DECISIONS.md#g4-actor-resolution
"""

from __future__ import annotations

from dataclasses import dataclass
from difflib import SequenceMatcher

FUZZY_THRESHOLD = 0.9


@dataclass(frozen=True)
class ActorResolution:
    """`actor_id` is set iff the name resolved. On a miss, `best_match_*` carry
    the closest candidate so the review queue row shows a reviewer what the
    near-miss was."""

    actor_id: object | None
    matched_on: str | None = None  # the canonical name or alias that matched
    method: str | None = None      # 'exact' | 'fuzzy'
    best_match_actor_id: object | None = None
    best_match_name: str | None = None
    best_match_score: float | None = None

    @property
    def resolved(self) -> bool:
        return self.actor_id is not None


def _normalize(name: str) -> str:
    return " ".join(name.strip().casefold().split())


class ActorIndex:
    """Resolution index built once per run from the threat_actor table."""

    def __init__(self, rows):
        """`rows` yields mappings with id, canonical_name, aliases."""
        self._exact: dict[str, object] = {}
        self._names: list[tuple[str, str, object]] = []  # (normalized, display, actor_id)

        for row in rows:
            actor_id = row["id"]
            for name in [row["canonical_name"], *(row["aliases"] or [])]:
                if not name:
                    continue
                normalized = _normalize(name)
                if not normalized:
                    continue
                # First writer wins: MISP aliases collide across clusters, and
                # rebinding by load order would be worse than staying stable.
                self._exact.setdefault(normalized, actor_id)
                self._names.append((normalized, name, actor_id))

    def __len__(self) -> int:
        return len(self._exact)

    def resolve(self, raw_name: str) -> ActorResolution:
        normalized = _normalize(raw_name)
        if not normalized:
            return ActorResolution(actor_id=None)

        actor_id = self._exact.get(normalized)
        if actor_id is not None:
            return ActorResolution(actor_id=actor_id, matched_on=normalized, method="exact")

        best_score = 0.0
        best_display: str | None = None
        best_id: object | None = None
        matcher = SequenceMatcher()
        matcher.set_seq2(normalized)
        for candidate, display, candidate_id in self._names:
            matcher.set_seq1(candidate)
            # Cheap upper bounds; skip the full ratio() when they rule it out.
            if matcher.real_quick_ratio() <= best_score or matcher.quick_ratio() <= best_score:
                continue
            score = matcher.ratio()
            if score > best_score:
                best_score, best_display, best_id = score, display, candidate_id

        if best_score > FUZZY_THRESHOLD:
            return ActorResolution(
                actor_id=best_id,
                matched_on=best_display,
                method="fuzzy",
                best_match_score=best_score,
            )

        return ActorResolution(
            actor_id=None,
            best_match_actor_id=best_id,
            best_match_name=best_display,
            best_match_score=best_score or None,
        )
