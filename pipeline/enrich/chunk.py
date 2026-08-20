"""Context budget: splitting a long document and merging what comes back
(DESIGN.md §5.3).

> Vendor threat reports run long and model context varies by two orders of
> magnitude across the backends above (200k on a hosted frontier model, 8k on a
> small local one). The extraction path takes a configurable `MAX_INPUT_TOKENS`
> and chunks `clean_text` past that threshold, merging per-chunk extractions by
> union with dedup. Without this, "swap the env var to a local model" fails on
> exactly the richest documents rather than degrading.

Two properties this module is built around, both of which other guardrails
depend on:

**Every chunk is a contiguous slice of `clean_text`.** Chunks are produced by
slicing, never by splitting and rejoining, so any span the model copies out of
a chunk is still a verbatim span of the whole document. That is what keeps
guardrail 3 (evidence quotes) working unchanged on a chunked document — the
quote is checked against the full `clean_text` afterwards, and it has to be
findable there.

**Breaks land on the largest available boundary.** Paragraph first, then
sentence, then whitespace, and only then a hard cut. A technique is normally
described within one paragraph, so paragraph-level breaks mean an evidence
sentence is almost never severed. There is deliberately no overlap between
chunks: overlap would pay for every boundary sentence twice on exactly the
backends that are being chunked *because* they are small, and the merge is a
union anyway, so the only thing overlap buys is insurance against a boundary
that paragraph-splitting already avoids.

Chunking is a degradation path, not a feature. What it costs is stated in
`merge_extractions`: the model never sees the whole document at once, so
cross-chunk reasoning is gone and the summary becomes a concatenation.
"""

from __future__ import annotations

import re

from enrich.contract import SUMMARY_MAX_CHARS, Extraction

# Chars per token, deliberately low. English prose runs nearer 4.0 across every
# tokenizer here, so 3.5 systematically *over*-estimates the token cost of a
# chunk and errs toward chunks that are too small. The failure mode on the
# other side is a context-length error mid-batch on a local model, which is the
# exact thing this module exists to prevent, and there is no generic tokenizer
# available: the OpenAI-compatible adapter reaches runtimes whose tokenizer we
# cannot know from here.
CHARS_PER_TOKEN = 3.5

# Reserved for the retry prompt (guardrail 1 re-sends the document with the
# validation error appended). Without the reserve, a document that just fits
# would overflow on the retry -- turning a recoverable schema failure into an
# unrecoverable context error.
RETRY_RESERVE_TOKENS = 500

# Below this a chunk is too small to carry a technique description and its
# evidence quote, so the configuration is wrong rather than the document long.
MIN_BUDGET_CHARS = 1000

# Tried in order, largest structural unit first. The last resort is a hard
# slice, which is why the tiers exist: it is the only one that can cut a
# sentence, and it should only ever be reached by pathological input.
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
    """How many characters of document fit in one call.

    The overhead is measured from the actual prompt files rather than guessed
    at: the system prompt and the user template are both several hundred tokens
    and both count against the same window the document does.
    """
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
    """Split `text` into contiguous slices of at most `max_chars` each.

    Returns `[text]` unchanged when it already fits, which is the common case
    on a hosted backend and must stay a no-op there.
    """
    if len(text) <= max_chars:
        return [text]
    return [chunk for chunk in _split(text, max_chars, 0) if chunk.strip()]


def _split(text: str, max_chars: int, tier: int) -> list[str]:
    if len(text) <= max_chars:
        return [text]

    if tier >= len(_BOUNDARIES):
        # Hard cut. Only reachable on text with no whitespace at all for
        # max_chars characters, e.g. a base64 blob that survived sanitization.
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
    """Union with dedup (§5.3), field by field.

    Only `actors`, `techniques`, `targets` and `iocs` are genuine unions. The
    three scalars cannot be, and each one is a documented loss:

    * `summary` becomes a concatenation of the per-chunk summaries, truncated
      to the contract's 600-character cap. It is no longer a single abstract of
      the document, because no model call ever saw the document. This is the
      most visible cost of chunking and the reason it is a fallback rather than
      a default.
    * `report_date` takes the first non-null in document order. Reports state
      the date of the activity early, and a later chunk mentioning a different
      date is usually referring to prior reporting.
    * `confidence` takes the *lowest* across chunks. Each call judged its own
      fragment; the confidence of a document assembled from fragments cannot
      honestly exceed the least confident of them.
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
            # Keep the strongest attribution the source stated anywhere. The
            # discipline rule in §5.2 is about not inferring beyond the source,
            # not about picking its weakest phrasing: if one chunk carries "we
            # attribute this to X", the source did assert that.
            if existing is None or _ATTRIBUTION.index(actor.attribution_confidence) > _ATTRIBUTION.index(
                existing.attribution_confidence
            ):
                actors[key] = actor

    techniques = {}
    for extraction in extractions:
        for technique in extraction.techniques:
            # First quote wins, matching validate.py -- report_technique is
            # keyed (report_id, technique_id) and holds one quote.
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
    """Join in document order and truncate at a sentence boundary if possible.

    Cutting mid-sentence would be the one place a chunked document produces
    visibly broken prose in the UI, and `summary` is rendered in the serif face
    reserved for model-written text (§9.2), so it is the most read field there.
    """
    cap = SUMMARY_MAX_CHARS
    joined = " ".join(e.summary.strip() for e in extractions if e.summary.strip())
    if len(joined) <= cap:
        return joined

    truncated = joined[:cap]
    sentence_end = max(truncated.rfind(". "), truncated.rfind("! "), truncated.rfind("? "))
    if sentence_end > cap // 2:
        return truncated[: sentence_end + 1]
    return truncated[: cap - 1].rstrip() + "…"
