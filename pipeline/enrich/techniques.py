"""Guardrail 2 (DESIGN.md §5.2): closed-world technique IDs.

The model is told to emit only ATT&CK technique IDs, but telling it isn't the
control -- the control is that every ID is checked against the attack_technique
table afterwards and dropped if absent. Inventing plausible-looking IDs
(T1566.004, T1071.005) is the single most common hallucination class in this
task, and a set membership test kills all of it.
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

        # Checked before membership only so the log line distinguishes "made up
        # an ID" from "emitted something that isn't an ATT&CK ID at all".
        if not _TECHNIQUE_ID_RE.match(candidate):
            return TechniqueCheck(False, "not a well-formed ATT&CK technique ID")
        if candidate not in self._known:
            return TechniqueCheck(False, "not present in attack_technique (closed world)")

        return TechniqueCheck(True)
