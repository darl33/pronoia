"""Guardrail 1 (DESIGN.md §5.2): structured-output enforcement, and the
document-level extraction path that chunks past the context budget (§5.3).

Strip fences, validate, retry once with the error appended, give up after two
attempts. Rationale: docs/DECISIONS.md#g1-structured-output
Chunking and merge: docs/DECISIONS.md#context-budget
"""

from __future__ import annotations

import json
import re
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime, timezone

from pydantic import ValidationError

from enrich.chunk import document_budget_chars, merge_extractions, split_text
from enrich.client import DEFAULT_MAX_TOKENS, CompletionClient, EnrichmentError
from enrich.contract import Extraction

MAX_ATTEMPTS = 2

_FENCE_RE = re.compile(r"^\s*```(?:json|JSON)?\s*\n(?P<body>.*?)\n?\s*```\s*$", re.DOTALL)


def strip_code_fences(text: str) -> str:
    """Remove a single fence wrapping the *whole* response. Prose around a
    fenced block is a contract violation, not something to salvage."""
    match = _FENCE_RE.match(text)
    return match.group("body") if match else text.strip()


@dataclass
class Attempt:
    attempt: int
    status: str  # 'ok' | 'invalid_json' | 'schema_fail' | 'api_error'
    started_at: datetime
    finished_at: datetime
    raw_response: str | None
    error: str | None = None
    extraction: Extraction | None = None
    # Recorded and logged, never branched on -- the guardrail decides on the
    # parse result alone.
    input_tokens: int | None = None
    output_tokens: int | None = None
    stop_reason: str | None = None


@dataclass
class ExtractionOutcome:
    attempts: list[Attempt] = field(default_factory=list)

    @property
    def succeeded(self) -> bool:
        return self.attempts and self.attempts[-1].status == "ok"

    @property
    def final(self) -> Attempt:
        return self.attempts[-1]


def parse_extraction(raw_response: str) -> tuple[Extraction | None, str, str | None]:
    """Returns (extraction, status, error). invalid_json means the model did not
    emit JSON; schema_fail means it emitted JSON that is not this contract."""
    cleaned = strip_code_fences(raw_response)

    try:
        json.loads(cleaned)
    except (json.JSONDecodeError, ValueError) as exc:
        return None, "invalid_json", str(exc)

    try:
        return Extraction.model_validate_json(cleaned), "ok", None
    except ValidationError as exc:
        return None, "schema_fail", str(exc)


def _retry_prompt(user_prompt: str, status: str, error: str) -> str:
    label = "was not valid JSON" if status == "invalid_json" else "did not match the contract"
    return (
        f"{user_prompt}\n\n"
        f"Your previous response {label}. The validation error was:\n\n"
        f"{error}\n\n"
        "Return only the corrected JSON object, with no fences and no prose."
    )


def run_extraction(
    client: CompletionClient,
    system_prompt: str,
    user_prompt: str,
    max_attempts: int = MAX_ATTEMPTS,
    max_tokens: int = DEFAULT_MAX_TOKENS,
) -> ExtractionOutcome:
    outcome = ExtractionOutcome()
    prompt = user_prompt

    for attempt_number in range(1, max_attempts + 1):
        started_at = datetime.now(timezone.utc)

        try:
            completion = client.complete(system_prompt, prompt, max_tokens=max_tokens)
        except EnrichmentError as exc:
            outcome.attempts.append(
                Attempt(
                    attempt=attempt_number,
                    status="api_error",
                    started_at=started_at,
                    finished_at=datetime.now(timezone.utc),
                    raw_response=None,
                    error=str(exc),
                )
            )
            return outcome

        extraction, status, error = parse_extraction(completion.text)
        outcome.attempts.append(
            Attempt(
                attempt=attempt_number,
                status=status,
                started_at=started_at,
                finished_at=datetime.now(timezone.utc),
                raw_response=completion.text,
                error=error,
                extraction=extraction,
                input_tokens=completion.input_tokens,
                output_tokens=completion.output_tokens,
                stop_reason=completion.stop_reason,
            )
        )

        if status == "ok":
            return outcome

        prompt = _retry_prompt(user_prompt, status, error or "")

    return outcome


# ---------- document level: the context budget (DESIGN.md §5.3) ----------


@dataclass
class ChunkOutcome:
    outcome: ExtractionOutcome
    # None when the document fit in one call; stored as NULL chunk_index.
    index: int | None


@dataclass
class DocumentOutcome:
    """One document's result, however many model calls it took.

    A partially-failed chunked document still merges the chunks that worked, so
    `failed_chunks` is what makes that under-extraction visible.
    """

    chunks: list[ChunkOutcome] = field(default_factory=list)
    extraction: Extraction | None = None

    @property
    def succeeded(self) -> bool:
        return self.extraction is not None

    @property
    def chunk_count(self) -> int:
        return len(self.chunks)

    @property
    def was_chunked(self) -> bool:
        return self.chunk_count > 1

    @property
    def failed_chunks(self) -> list[ChunkOutcome]:
        return [chunk for chunk in self.chunks if not chunk.outcome.succeeded]

    @property
    def attempts(self) -> list[tuple[int | None, Attempt]]:
        """Every model call for this document, tagged with its chunk -- one
        enrichment_run row per entry."""
        return [
            (chunk.index, attempt) for chunk in self.chunks for attempt in chunk.outcome.attempts
        ]

    @property
    def status(self) -> str:
        """'ok' if anything came back usable, else the last failure's status."""
        if self.succeeded:
            return "ok"
        return self.chunks[-1].outcome.final.status if self.chunks else "api_error"

    @property
    def error(self) -> str | None:
        for chunk in reversed(self.chunks):
            if chunk.outcome.final.error:
                return chunk.outcome.final.error
        return None

    @property
    def input_tokens(self) -> int | None:
        return _sum_tokens(self.attempts, "input_tokens")

    @property
    def output_tokens(self) -> int | None:
        return _sum_tokens(self.attempts, "output_tokens")

    @property
    def truncated(self) -> bool:
        from enrich.client import TRUNCATION_STOP_REASONS

        return any(
            chunk.outcome.final.stop_reason in TRUNCATION_STOP_REASONS for chunk in self.chunks
        )


def _sum_tokens(attempts, attribute: str) -> int | None:
    """None, not 0, when no attempt reported usage -- some runtimes omit it."""
    values = [getattr(attempt, attribute) for _, attempt in attempts]
    known = [value for value in values if value is not None]
    return sum(known) if known else None


def extract_document(
    client: CompletionClient,
    system: str,
    render_user: Callable[[str], str],
    clean_text: str,
    *,
    max_input_tokens: int,
    max_attempts: int = MAX_ATTEMPTS,
    max_tokens: int = DEFAULT_MAX_TOKENS,
) -> DocumentOutcome:
    """Extract one document, chunking first if it exceeds the budget.

    `render_user` is a callable because each chunk needs its own enclosure, and
    rendering it empty measures the prompt overhead exactly. A document that
    fits is a single call, identical to `run_extraction`.
    """
    budget = document_budget_chars(
        max_input_tokens, prompt_overhead_chars=len(system) + len(render_user(""))
    )
    chunks = split_text(clean_text, budget)

    document = DocumentOutcome()
    extractions: list[Extraction] = []

    for position, chunk in enumerate(chunks):
        outcome = run_extraction(
            client, system, render_user(chunk), max_attempts=max_attempts, max_tokens=max_tokens
        )
        document.chunks.append(
            ChunkOutcome(outcome=outcome, index=position if len(chunks) > 1 else None)
        )
        if outcome.succeeded and outcome.final.extraction is not None:
            extractions.append(outcome.final.extraction)

    if extractions:
        document.extraction = merge_extractions(extractions)
    return document
