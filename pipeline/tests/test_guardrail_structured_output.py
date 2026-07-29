"""Guardrail 1 (DESIGN.md §5.2): structured-output enforcement.

Fences are stripped, `model_validate_json` decides, failures are recorded as
`invalid_json` or `schema_fail` and retried exactly once with the validation
error appended, and two failures give up while keeping the audit trail.
"""

from __future__ import annotations

import json

from enrich.client import CompletionResult
from enrich.extract import parse_extraction, run_extraction, strip_code_fences

VALID_PAYLOAD = {
    "summary": "A synthetic campaign against water utilities.",
    "report_date": "2026-02-01",
    "confidence": "high",
    "actors": [{"name": "FAKEBEAR", "attribution_confidence": "confirmed_by_source"}],
    "techniques": [
        {"technique_id": "T1566.001", "evidence_quote": "The operators received spear-phishing emails"}
    ],
    "targets": [{"country": "AU", "sector": "water"}],
    "iocs": [{"kind": "ipv4", "value": "192.0.2.44"}],
}


class ScriptedClient:
    """Returns canned responses in order and records the prompts it was given,
    so a test can assert on what the retry actually sent."""

    model = "scripted-test-model"

    def __init__(self, responses):
        self._responses = list(responses)
        self.prompts: list[str] = []

    def complete(self, system: str, user: str, *, max_tokens: int = 16000) -> CompletionResult:
        self.prompts.append(user)
        return CompletionResult(
            text=self._responses.pop(0),
            input_tokens=None,
            output_tokens=None,
            stop_reason="end_turn",
        )


# ---- fence stripping ----


def test_strips_json_fence():
    assert strip_code_fences('```json\n{"a": 1}\n```') == '{"a": 1}'


def test_strips_bare_fence():
    assert strip_code_fences('```\n{"a": 1}\n```') == '{"a": 1}'


def test_leaves_unfenced_json_alone():
    assert strip_code_fences('  {"a": 1}  ') == '{"a": 1}'


def test_does_not_salvage_json_buried_in_prose():
    """A response with prose around the JSON is a contract violation. Digging
    the object out would hide the failure from the §7 eval; it should fail,
    get one corrective retry, and be recorded either way."""
    raw = 'Here is the extraction:\n```json\n{"a": 1}\n```\nLet me know if you need more.'
    _, status, _ = parse_extraction(raw)
    assert status == "invalid_json"


# ---- classification ----


def test_valid_payload_parses():
    extraction, status, error = parse_extraction(json.dumps(VALID_PAYLOAD))
    assert status == "ok"
    assert error is None
    assert extraction.confidence == "high"


def test_fenced_valid_payload_parses():
    extraction, status, _ = parse_extraction(f"```json\n{json.dumps(VALID_PAYLOAD)}\n```")
    assert status == "ok"
    assert extraction is not None


def test_non_json_is_classified_invalid_json():
    _, status, error = parse_extraction("I'm sorry, I can't help with that.")
    assert status == "invalid_json"
    assert error


def test_wrong_shape_is_classified_schema_fail():
    """Valid JSON, wrong contract -- a different failure with a different fix,
    so enrichment_run has to be able to tell them apart."""
    _, status, error = parse_extraction(json.dumps({"summary": "x", "confidence": "extremely high"}))
    assert status == "schema_fail"
    assert error


def test_unknown_field_is_a_schema_fail():
    payload = VALID_PAYLOAD | {"threat_level": "midnight"}
    _, status, _ = parse_extraction(json.dumps(payload))
    assert status == "schema_fail"


# ---- the retry loop ----


def test_malformed_json_is_retried_once_and_recovers():
    client = ScriptedClient(["not json at all", json.dumps(VALID_PAYLOAD)])
    outcome = run_extraction(client, "system", "user")

    assert [a.status for a in outcome.attempts] == ["invalid_json", "ok"]
    assert outcome.succeeded
    assert outcome.final.extraction.summary == VALID_PAYLOAD["summary"]


def test_retry_prompt_carries_the_validation_error():
    """The retry has to tell the model what was wrong, or it is just a second
    roll of the same dice."""
    client = ScriptedClient(
        [json.dumps({"summary": "x", "confidence": "nope"}), json.dumps(VALID_PAYLOAD)]
    )
    outcome = run_extraction(client, "system", "user")

    assert len(client.prompts) == 2
    retry_prompt = client.prompts[1]
    assert retry_prompt.startswith("user")
    assert "did not match the contract" in retry_prompt
    assert "confidence" in retry_prompt
    assert outcome.succeeded


def test_two_failures_give_up_and_keep_the_audit_trail():
    client = ScriptedClient(["still not json", "{ also not json"])
    outcome = run_extraction(client, "system", "user")

    assert not outcome.succeeded
    assert len(outcome.attempts) == 2  # capped, never a third call
    assert [a.attempt for a in outcome.attempts] == [1, 2]
    assert all(a.status == "invalid_json" for a in outcome.attempts)
    # Both raw responses survive for enrichment_run.raw_response.
    assert [a.raw_response for a in outcome.attempts] == ["still not json", "{ also not json"]


def test_first_attempt_success_makes_no_second_call():
    client = ScriptedClient([json.dumps(VALID_PAYLOAD)])
    outcome = run_extraction(client, "system", "user")

    assert len(outcome.attempts) == 1
    assert len(client.prompts) == 1
    assert outcome.succeeded


def test_api_error_is_recorded_and_not_retried():
    """An API failure is not a contract failure -- retrying it here would
    double-spend the budget on top of the SDK's own retries."""

    class FailingClient:
        model = "failing-test-model"

        def complete(self, system, user, *, max_tokens=16000):
            from enrich.client import EnrichmentError

            raise EnrichmentError("boom")

    outcome = run_extraction(FailingClient(), "system", "user")
    assert [a.status for a in outcome.attempts] == ["api_error"]
    assert not outcome.succeeded
