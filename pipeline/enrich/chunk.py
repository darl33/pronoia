"""Context budget: split a long document, merge what comes back (DESIGN.md §5.3).

Chunks are contiguous slices of clean_text, so quotes copied from a chunk stay
verbatim in the whole document and guardrail 3 keeps working. Breaks prefer
paragraph boundaries; there is no overlap. Merging is a union with dedup for the
list fields; the three scalars each lose something.

Rationale for all of it: docs/DECISIONS.md#context-budget
"""

from __future__ import annotations

import re

from enrich.contract import SUMMARY_MAX_CHARS, Extraction

# Deliberately below the ~4.0 of real prose, so estimates err small.
CHARS_PER_TOKEN = 3.5

# Held back for guardrail 1's retry, which re-sends the document.
RETRY_RESERVE_TOKENS = 500

# Under this the budget is misconfigured, not the document long.
MIN_BUDGET_CHARS = 1000

# Break tiers, largest structural unit first; the hard slice is last resort.
_BOUNDARIES = (
    r"\n\s*\n",        # paragraph
    r"(?<=[.!?])\s+",  # sentence
    r"\s+",            # word
)


class BudgetTooSmall(Exception):
    """MAX_INPUT_TOKENS leaves no usable room for the document."""


def estimate_tokens(text: str) -> int:
    return int(len(text) / CHARS_PER_TOKEN)


def document_budget_chars(max_input_tokens: int, *, prompt_overhead_chars: int) -> int:
    """Characters of document that fit in one call, after prompt overhead and
    the retry reserve."""
    overhead_tokens = estimate_tokens(" " * prompt_overhead_chars) + RETRY_RESERVE_TOKENS
    budget_chars = int((max_input_tokens - overhead_tokens) * CHARS_PER_TOKEN)

    if budget_chars < MIN_BUDGET_CHARS:
        raise BudgetTooSmall(
            f"MAX_INPUT_TOKENS={max_input_tokens} leaves {budget_chars} characters for "
            f"the document after {overhead_tokens} tokens of prompt overhead and retry "
            f"reserve. Raise MAX_INPUT_TOKENS above "
            f"{int(overhead_tokens + MIN_BUDGET_CHARS / CHARS_PER_TOKEN)}."
        )
    return budget_chars


def split_text(text: str, max_chars: int) -> list[str]:
    """Contiguous slices of at most `max_chars`; `[text]` when it already fits.

    Slices, never split-and-rejoined: guardrail 3 depends on it.
    """
    if len(text) <= max_chars:
        return [text]
    return [chunk for chunk in _split(text, max_chars, 0) if chunk.strip()]


def _split(text: str, max_chars: int, tier: int) -> list[str]:
    if len(text) <= max_chars:
        return [text]

    if tier >= len(_BOUNDARIES):
        # Last resort: text with no whitespace for max_chars characters.
        return [text[i : i + max_chars] for i in range(0, len(text), max_chars)]

    offsets = sorted({0, *(m.end() for m in re.finditer(_BOUNDARIES[tier], text)), len(text)})
    if len(offsets) <= 2:
        return _split(text, max_chars, tier + 1)

    chunks: list[str] = []
    start = previous = 0
    for offset in offsets[1:]:
        # Break at the last boundary that fit, not this one.
        if offset - start > max_chars and previous > start:
            chunks.append(text[start:previous])
            start = previous
        previous = offset
    chunks.append(text[start:])

    # A single over-budget segment drops to the next tier.
    return [piece for chunk in chunks for piece in _split(chunk, max_chars, tier + 1)]


# ---------- merging ----------

# Weakest to strongest; index order is what min()/max() below rely on.
_CONFIDENCE = ("low", "medium", "high")
_ATTRIBUTION = ("suspected", "likely", "confirmed_by_source")


def merge_extractions(extractions: list[Extraction]) -> Extraction:
    """Union with dedup for the list fields; summary concatenates, report_date
    takes the first stated, confidence takes the lowest. Each scalar rule is a
    documented loss: docs/DECISIONS.md#context-budget"""
    if not extractions:
        raise ValueError("nothing to merge")
    if len(extractions) == 1:
        return extractions[0]

    actors = {}
    for extraction in extractions:
        for actor in extraction.actors:
            key = actor.name.casefold()
            existing = actors.get(key)
            # Strongest attribution the source stated anywhere.
            if existing is None or _ATTRIBUTION.index(actor.attribution_confidence) > _ATTRIBUTION.index(
                existing.attribution_confidence
            ):
                actors[key] = actor

    techniques = {}
    for extraction in extractions:
        for technique in extraction.techniques:
            # First quote wins, matching validate.py.
            techniques.setdefault(technique.technique_id, technique)

    targets = {}
    for extraction in extractions:
        for target in extraction.targets:
            targets.setdefault((target.country, target.sector), target)

    iocs = {}
    for extraction in extractions:
        for indicator in extraction.iocs:
            iocs.setdefault((indicator.kind, indicator.value), indicator)

    return Extraction(
        summary=_merge_summaries(extractions),
        report_date=next(
            (e.report_date for e in extractions if e.report_date is not None), None
        ),
        confidence=min(extractions, key=lambda e: _CONFIDENCE.index(e.confidence)).confidence,
        actors=list(actors.values()),
        techniques=list(techniques.values()),
        targets=list(targets.values()),
        iocs=list(iocs.values()),
    )


def _merge_summaries(extractions: list[Extraction]) -> str:
    """Join in order, truncating at a sentence boundary where possible."""
    cap = SUMMARY_MAX_CHARS
    joined = " ".join(e.summary.strip() for e in extractions if e.summary.strip())
    if len(joined) <= cap:
        return joined

    truncated = joined[:cap]
    sentence_end = max(truncated.rfind(". "), truncated.rfind("! "), truncated.rfind("? "))
    if sentence_end > cap // 2:
        return truncated[: sentence_end + 1]
    return truncated[: cap - 1].rstrip() + "…"
