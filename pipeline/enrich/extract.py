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
from dataclasses import dataclass, field
from datetime import datetime, timezone

from pydantic import ValidationError

from enrich.client import EnrichmentClient, EnrichmentError
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
    client: EnrichmentClient,
    system_prompt: str,
    user_prompt: str,
    max_attempts: int = MAX_ATTEMPTS,
) -> ExtractionOutcome:
    outcome = ExtractionOutcome()
    prompt = user_prompt

    for attempt_number in range(1, max_attempts + 1):
        started_at = datetime.now(timezone.utc)

        try:
            raw_response = client.complete(system_prompt, prompt)
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

        extraction, status, error = parse_extraction(raw_response)
        outcome.attempts.append(
            Attempt(
                attempt=attempt_number,
                status=status,
                started_at=started_at,
                finished_at=datetime.now(timezone.utc),
                raw_response=raw_response,
                error=error,
                extraction=extraction,
            )
        )

        if status == "ok":
            return outcome

        prompt = _retry_prompt(user_prompt, status, error or "")

    return outcome
