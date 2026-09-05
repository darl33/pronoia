"""Guardrail 3 (DESIGN.md §5.2): evidence quotes as hallucination checks.

A technique mention's quote must appear in clean_text after normalization, or
the mention is dropped. What normalization forgives, and what it refuses to:
docs/DECISIONS.md#g3-evidence-quotes
"""

from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass

from ingest.sanitize import normalize_whitespace

MIN_QUOTE_CHARS = 20

# Applied to both haystack and needle -- canonicalization, not a looser match.
_CHARACTER_FOLDS = str.maketrans(
    {
        "‘": "'",  # left single quote
        "’": "'",  # right single quote / apostrophe
        "‚": "'",
        "“": '"',  # left double quote
        "”": '"',  # right double quote
        "„": '"',
        "–": "-",  # en dash
        "—": "-",  # em dash
        "−": "-",  # minus sign
        "­": "",   # soft hyphen
        "​": "",   # zero-width space
        "﻿": "",   # BOM / zero-width no-break space
    }
)

_ELLIPSIS_RE = re.compile(r"…|\.\.\.")


def canonicalize(text: str) -> str:
    """The single normalization applied to both sides of the comparison."""
    folded = unicodedata.normalize("NFKC", text).translate(_CHARACTER_FOLDS)
    return normalize_whitespace(folded)


@dataclass(frozen=True)
class EvidenceCheck:
    ok: bool
    reason: str | None = None


class EvidenceIndex:
    """Canonicalized view of one document's clean_text, reused across every
    technique mention in that document's extraction."""

    def __init__(self, clean_text: str):
        self._haystack = canonicalize(clean_text)

    def check(self, quote: str) -> EvidenceCheck:
        needle = canonicalize(quote)

        if len(needle) < MIN_QUOTE_CHARS:
            return EvidenceCheck(
                False,
                f"quote is {len(needle)} chars, below the {MIN_QUOTE_CHARS}-char floor",
            )
        if _ELLIPSIS_RE.search(needle):
            return EvidenceCheck(False, "quote contains an elision; not a verbatim span")
        if needle not in self._haystack:
            return EvidenceCheck(False, "quote does not appear in clean_text")

        return EvidenceCheck(True)
