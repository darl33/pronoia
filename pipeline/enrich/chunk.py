"""Context budget: split a long document, merge what comes back (DESIGN.md §5.3).

Chunks are contiguous slices, never split-and-rejoined text, so a span the model
copies out of a chunk is still verbatim in the whole `clean_text`. Without that,
guardrail 3 would drop the model's *honest* quotes on exactly the long documents
this exists to rescue.

Breaks land on paragraph boundaries first, so an evidence sentence is rarely
severed. No overlap: it would double-bill boundary sentences on precisely the
small backends being chunked, to insure against a boundary that
paragraph-splitting already avoids.

Chunking degrades rather than fixes. No call sees the whole document, so
cross-chunk reasoning is gone and the summary becomes a concatenation.
"""

from __future__ import annotations

import re

from enrich.contract import SUMMARY_MAX_CHARS, Extraction

# Low on purpose: English prose runs nearer 4.0, so 3.5 over-estimates cost and
# errs toward chunks that are too small. The other direction is a context-length
# error mid-batch. No generic tokenizer exists for the runtimes the adapter reaches.
CHARS_PER_TOKEN = 3.5

# Room for the retry prompt (guardrail 1 re-sends the document with the
# validation error appended); otherwise a document that just fits overflows on
# the retry, turning a recoverable schema failure into a context error.
RETRY_RESERVE_TOKENS = 500

# Below this a chunk is too small to carry a technique description and its
# evidence quote, so the configuration is wrong rather than the document long.
MIN_BUDGET_CHARS = 1000

# Largest structural unit first. The tiers exist so the hard slice below, the
# only break that can cut a sentence, is reached only by pathological input.
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
    """Characters of document that fit in one call. Overhead is measured from
    the real prompt files, not guessed: they charge against the same window."""
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
    """Contiguous slices of at most `max_chars`. `[text]` when it already fits --
    a no-op on hosted backends, which is what keeps their §7 scores stable."""
    if len(text) <= max_chars:
        return [text]
    return [chunk for chunk in _split(text, max_chars, 0) if chunk.strip()]


def _split(text: str, max_chars: int, tier: int) -> list[str]:
    if len(text) <= max_chars:
        return [text]

    if tier >= len(_BOUNDARIES):
        # Only reachable on text with no whitespace for max_chars characters,
        # e.g. a base64 blob that survived sanitization.
        return [text[i : i + max_chars] for i in range(0, len(text), max_chars)]

    offsets = sorted({0, *(m.end() for m in re.finditer(_BOUNDARIES[tier], text)), len(text)})
    if len(offsets) <= 2:
        return _split(text, max_chars, tier + 1)

    chunks: list[str] = []
    start = previous = 0
    for offset in offsets[1:]:
        # Break at the last boundary that still fit, not at this one -- breaking
        # here is what would exceed the budget.
        if offset - start > max_chars and previous > start:
            chunks.append(text[start:previous])
            start = previous
        previous = offset
    chunks.append(text[start:])

    # A single segment can still be over budget (one enormous paragraph); it
    # gets the next tier down.
    return [piece for chunk in chunks for piece in _split(chunk, max_chars, tier + 1)]


# ---------- merging ----------

# Ordered weakest to strongest, so max()/min() over the index means something.
_CONFIDENCE = ("low", "medium", "high")
_ATTRIBUTION = ("suspected", "likely", "confirmed_by_source")


def merge_extractions(extractions: list[Extraction]) -> Extraction:
    """Union with dedup (§5.3). Only the four list fields are genuine unions;
    the scalars cannot be, and each is a loss:

    * `summary` is a concatenation -- no call saw the document, so it is no
      longer an abstract of one. The most visible cost of chunking.
    * `report_date` takes the first stated; a later date usually refers to
      prior reporting.
    * `confidence` takes the *lowest*: a record assembled from fragments cannot
      honestly beat its least confident fragment.
    """
    if not extractions:
        raise ValueError("nothing to merge")
    if len(extractions) == 1:
        return extractions[0]

    actors = {}
    for extraction in extractions:
        for actor in extraction.actors:
            key = actor.name.casefold()
            existing = actors.get(key)
            # Strongest attribution the source stated anywhere: §5.2's rule
            # forbids inferring beyond the source, not reading it at its word.
            if existing is None or _ATTRIBUTION.index(actor.attribution_confidence) > _ATTRIBUTION.index(
                existing.attribution_confidence
            ):
                actors[key] = actor

    techniques = {}
    for extraction in extractions:
        for technique in extraction.techniques:
            # First quote wins, matching validate.py: report_technique holds
            # one quote per (report_id, technique_id).
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
    """Join in order, truncating at a sentence boundary where possible: this is
    the one field rendered as prose in the UI (§9.2), so a mid-sentence cut shows."""
    cap = SUMMARY_MAX_CHARS
    joined = " ".join(e.summary.strip() for e in extractions if e.summary.strip())
    if len(joined) <= cap:
        return joined

    truncated = joined[:cap]
    sentence_end = max(truncated.rfind(". "), truncated.rfind("! "), truncated.rfind("? "))
    if sentence_end > cap // 2:
        return truncated[: sentence_end + 1]
    return truncated[: cap - 1].rstrip() + "…"
