"""Guardrail 2 (DESIGN.md §5.2): closed-world technique IDs.

Every ID the model emits is checked against attack_technique and dropped if
absent. Rationale: docs/DECISIONS.md#g2-closed-world
"""

from __future__ import annotations

import re
from dataclasses import dataclass

# ATT&CK enterprise technique / sub-technique form, e.g. T1566 or T1566.001.
_TECHNIQUE_ID_RE = re.compile(r"^T\d{4}(\.\d{3})?$")


@dataclass(frozen=True)
class TechniqueCheck:
    ok: bool
    reason: str | None = None


class TechniqueIndex:
    """The closed world: exactly the technique IDs present in the DB."""

    def __init__(self, technique_ids: set[str]):
        self._known = {tid.upper() for tid in technique_ids}

    def __len__(self) -> int:
        return len(self._known)

    def check(self, technique_id: str) -> TechniqueCheck:
        candidate = technique_id.strip().upper()

        # Before membership only so the log distinguishes a malformed ID from
        # a well-formed one that does not exist.
        if not _TECHNIQUE_ID_RE.match(candidate):
            return TechniqueCheck(False, "not a well-formed ATT&CK technique ID")
        if candidate not in self._known:
            return TechniqueCheck(False, "not present in attack_technique (closed world)")

        return TechniqueCheck(True)
