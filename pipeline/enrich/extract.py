"""Guardrail 1 (DESIGN.md §5.2): structured-output enforcement.

The prompt asks for JSON only. That request is not the control -- models wrap
JSON in markdown fences, prepend "Here is the extraction:", or emit a field
that isn't in the contract. The control is: strip fences defensively, run
`Extraction.model_validate_json`, and on failure record `invalid_json` or
`schema_fail` on the enrichment_run and retry *once* with the validation error
appended to the prompt. Two failures = give up, keep the audit trail.

Capped at two attempts on purpose. A model that fails the contract twice with
the error text in front of it is not going to succeed on the third try, and an
uncapped retry loop against a paid API is how a pipeline quietly bankrupts
itself. The failed attempts are rows in enrichment_run either way, so a
recurring schema failure is visible in the data rather than only in logs.
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
    """Remove a single wrapping markdown fence, if present.

    Only a fence enclosing the *whole* response is stripped. A response with
    prose around a fenced block is a contract violation, not something to
    salvage -- salvaging it would hide the failure from the eval in §7.
    """
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
    # Carried from CompletionResult (DESIGN.md §5.3) for cost tracking and
    # truncation detection. Recorded and logged, never branched on: the
    # guardrail decides on the parse result alone, whatever the provider says.
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
    """Returns (extraction, status, error). Splitting invalid_json from
    schema_fail is what makes the failure mode legible in enrichment_run:
    the first says the model didn't emit JSON, the second says it emitted JSON
    that isn't this contract."""
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
    # None when the document fit in one call. NULL in enrichment_run then means
    # "not chunked", which is the common case and shouldn't look like chunk 0.
    index: int | None


@dataclass
class DocumentOutcome:
    """One document's result, however many model calls it took.

    A partially-failed chunked document still produces an extraction from the
    chunks that worked. That is the degradation §5.3 asks for -- the
    alternative is discarding four good chunks because the fifth returned bad
    JSON -- but it under-extracts silently unless someone says so, which is
    what `failed_chunks` is for. It is logged by the pipeline and reported per
    backend in the §7 scorecard.
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
        """Every model call made for this document, tagged with its chunk.

        Flattened for the audit trail: guardrail 1 requires one enrichment_run
        row per attempt, and chunking multiplies attempts rather than replacing
        them.
        """
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
    """None, not 0, when no attempt reported usage -- some OpenAI-compatible
    runtimes omit the usage block entirely, and reporting a cost of zero for
    a run that cost something is worse than reporting nothing."""
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
    """Extract one document, chunking it first if it exceeds the budget.

    `render_user` is passed as a callable rather than a rendered string because
    each chunk needs its own enclosure -- and rendering the template with an
    empty document measures the prompt overhead exactly, instead of estimating
    it. Keeping the prompt files out of this module is deliberate: guardrail 1
    stays portable across prompts and providers.

    On a hosted backend this is a single call and behaves exactly as
    `run_extraction` did, which is the property that matters -- the primary
    backend's §7 scores must not move because a fallback path was added for a
    different backend.
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
