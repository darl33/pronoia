"""Guardrail 3 (DESIGN.md §5.2): evidence quotes as hallucination checks.

Every technique mention must carry a quote. Post-validation, that quote must
appear as a substring of the document's clean_text after normalization; if it
doesn't, the mention is dropped. This is the guardrail that converts an
unfalsifiable claim ("the report describes spearphishing") into a checkable
one: either the span is in the source document or the model invented it.

Normalization policy -- what we forgive, and why:

  * whitespace runs, including newlines introduced by html_to_clean_text's
    block-element splitting. A quote spanning a line break in the source is
    still a real quote.
  * NFKC-foldable Unicode: non-breaking spaces, fullwidth punctuation. These
    survive the HTML->text path and differ from what a model reproduces.
  * typographic variants of characters that have an ASCII equivalent: curly
    quotes, en/em dashes, ellipsis. Vendor CMSes apply smart-quote
    substitution; a model re-typing the sentence produces the ASCII form.

  * case is NOT forgiven. Verbatim means verbatim; a model that re-cases a
    sentence is paraphrasing it.
  * elision is NOT forgiven. A quote containing "..." collapses to a single
    span that will not be found, which is the correct outcome -- an elided
    quote is not evidence of what sits inside the elision.

The floor on quote length is a second, weaker check: a span short enough to
occur incidentally ("the attacker") is not evidence for a technique claim even
when it does appear in the text.
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
