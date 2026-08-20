"""Guardrail 3 (DESIGN.md §5.2): evidence quotes as hallucination checks.

Every technique mention carries a quote, and that quote must appear as a
substring of clean_text after normalization or the mention is dropped. This
converts an unfalsifiable claim ("the report describes spearphishing") into a
checkable one.

Forgiven, because the HTML->text path and vendor CMSes introduce them while a
model re-typing the sentence will not: whitespace runs, NFKC-foldable Unicode,
and typographic variants with an ASCII equivalent (curly quotes, dashes).

Not forgiven: case, because verbatim means verbatim and re-casing is paraphrase;
and elision, because a quote is not evidence of what sits inside its "...".

The length floor is a weaker second check: a span short enough to occur
incidentally ("the attacker") is not evidence even when it is present.
"""

from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass

from ingest.sanitize import normalize_whitespace

MIN_QUOTE_CHARS = 20

# Applied to both haystack and needle, so these are canonicalizations rather
# than a relaxation of the match: the same input always lands on the same form.
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
