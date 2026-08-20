"""The context budget: splitting, merging, and document-level extraction (§5.3).

The property asserted most often is that **every chunk is a contiguous slice**.
Guardrail 3 checks quotes against the whole `clean_text`, so a chunk that is not
a literal substring would drop the model's honest quotes -- a silent, total loss
of the technique field on the long documents chunking exists to rescue.
"""

from __future__ import annotations

import json

import pytest

from enrich.chunk import (
    BudgetTooSmall,
    document_budget_chars,
    merge_extractions,
    split_text,
)
from enrich.client import CompletionResult
from enrich.contract import SUMMARY_MAX_CHARS, Extraction
from enrich.extract import extract_document

PARAGRAPH = (
    "The operators authenticated to the remote administration portal using "
    "credentials that were valid and unexpired. There was no exploitation and "
    "no malware on the perimeter device."
)


def _document(paragraphs: int) -> str:
    return "\n\n".join(f"Section {i}. {PARAGRAPH}" for i in range(paragraphs))


# ---- splitting ----


def test_short_text_is_not_split():
    """Must stay a no-op on hosted backends: the primary backend's §7 scores
    cannot move because a fallback path was added for a different one."""
    text = _document(2)
    assert split_text(text, 100_000) == [text]


def test_chunks_are_contiguous_slices_of_the_document():
    text = _document(20)
    chunks = split_text(text, 500)

    assert len(chunks) > 1
    assert "".join(chunks) == text          # nothing lost, nothing reordered
    for chunk in chunks:
        assert chunk in text                # every quote from a chunk is a real span


def test_chunks_respect_the_budget():
    text = _document(30)
    assert all(len(chunk) <= 400 for chunk in split_text(text, 400))


def test_breaks_land_on_paragraph_boundaries():
    """A technique is normally described within one paragraph, so this is what
    keeps evidence sentences intact."""
    text = _document(12)
    for chunk in split_text(text, 600):
        assert chunk.strip().startswith("Section")
        assert chunk.strip().endswith("device.")


def test_falls_back_to_sentence_boundaries_inside_a_huge_paragraph():
    text = " ".join(f"Sentence number {i} describes some observed behaviour." for i in range(80))
    chunks = split_text(text, 300)

    assert "".join(chunks) == text
    assert all(len(chunk) <= 300 for chunk in chunks)
    # No sentence was cut: every chunk ends at a full stop.
    assert all(chunk.strip().endswith(".") for chunk in chunks)


def test_hard_cuts_only_as_a_last_resort():
    """Text with no whitespace at all -- a base64 blob that survived
    sanitization. It has to be cut somewhere, and it must not hang or lose
    bytes."""
    text = "A" * 5000
    chunks = split_text(text, 512)

    assert "".join(chunks) == text
    assert all(len(chunk) <= 512 for chunk in chunks)


# ---- budget ----


def test_budget_subtracts_measured_prompt_overhead():
    generous = document_budget_chars(50_000, prompt_overhead_chars=1_000)
    tight = document_budget_chars(50_000, prompt_overhead_chars=20_000)

    assert generous > tight
    # Both leave less room than the raw token figure would suggest, because the
    # prompt and the retry reserve are charged against the same window.
    assert generous < 50_000 * 3.5


def test_unusable_budget_raises_with_the_variable_that_fixes_it():
    with pytest.raises(BudgetTooSmall, match="MAX_INPUT_TOKENS"):
        document_budget_chars(600, prompt_overhead_chars=1_000)


# ---- merging ----


def _extraction(**overrides) -> Extraction:
    payload = {
        "summary": "A campaign was observed.",
        "report_date": None,
        "confidence": "high",
        "actors": [],
        "techniques": [],
        "targets": [],
        "iocs": [],
    }
    payload.update(overrides)
    return Extraction.model_validate(payload)


def test_single_extraction_passes_through_untouched():
    extraction = _extraction()
    assert merge_extractions([extraction]) is extraction


def test_lists_are_unioned_and_deduped():
    first = _extraction(
        actors=[{"name": "Volt Typhoon", "attribution_confidence": "suspected"}],
        techniques=[{"technique_id": "T1078", "evidence_quote": "valid, unexpired credentials"}],
        targets=[{"country": "AU", "sector": "energy"}],
        iocs=[{"kind": "ipv4", "value": "192.0.2.1"}],
    )
    second = _extraction(
        actors=[{"name": "volt typhoon", "attribution_confidence": "confirmed_by_source"}],
        techniques=[{"technique_id": "T1090", "evidence_quote": "relayed through home routers"}],
        targets=[{"country": "AU", "sector": "energy"}, {"country": "NZ", "sector": None}],
        iocs=[{"kind": "ipv4", "value": "192.0.2.1"}, {"kind": "ipv4", "value": "192.0.2.9"}],
    )

    merged = merge_extractions([first, second])

    assert len(merged.actors) == 1                       # deduped case-insensitively
    assert {t.technique_id for t in merged.techniques} == {"T1078", "T1090"}
    assert len(merged.targets) == 2
    assert len(merged.iocs) == 2


def test_strongest_attribution_wins():
    """If any chunk carries 'we attribute this to X', the source did assert it.
    §5.2's discipline rule is about not inferring beyond the source, not about
    picking its weakest phrasing."""
    merged = merge_extractions([
        _extraction(actors=[{"name": "FIN7", "attribution_confidence": "suspected"}]),
        _extraction(actors=[{"name": "FIN7", "attribution_confidence": "confirmed_by_source"}]),
    ])
    assert merged.actors[0].attribution_confidence == "confirmed_by_source"


def test_first_evidence_quote_wins_for_a_repeated_technique():
    """report_technique holds one quote per (report, technique), and validate.py
    keeps the first surviving one -- the merge must not disagree."""
    merged = merge_extractions([
        _extraction(techniques=[{"technique_id": "T1078", "evidence_quote": "the first quote here"}]),
        _extraction(techniques=[{"technique_id": "T1078", "evidence_quote": "a later quote here"}]),
    ])
    assert merged.techniques[0].evidence_quote == "the first quote here"


def test_confidence_is_the_lowest_across_chunks():
    """A document assembled from fragments cannot honestly be more confident
    than its least confident fragment."""
    merged = merge_extractions([
        _extraction(confidence="high"),
        _extraction(confidence="low"),
        _extraction(confidence="medium"),
    ])
    assert merged.confidence == "low"


def test_report_date_takes_the_first_stated():
    merged = merge_extractions([
        _extraction(report_date=None),
        _extraction(report_date="2026-03-01"),
        _extraction(report_date="2019-01-01"),
    ])
    assert merged.report_date.isoformat() == "2026-03-01"


def test_merged_summary_respects_the_contract_cap():
    long_summary = "This sentence describes part of the campaign in detail. " * 5
    merged = merge_extractions([_extraction(summary=long_summary) for _ in range(4)])

    assert len(merged.summary) <= SUMMARY_MAX_CHARS
    # Still a valid Extraction -- the merge must not produce something the
    # contract would reject.
    Extraction.model_validate(merged.model_dump(mode="json"))


# ---- document-level extraction ----


class _ScriptedClient:
    """Returns one canned response per call, in order."""

    model = "test-model"

    def __init__(self, responses):
        self._responses = list(responses)
        self.prompts: list[str] = []

    def complete(self, system, user, *, max_tokens=1000):
        self.prompts.append(user)
        self.max_tokens = max_tokens
        payload = self._responses.pop(0)
        text = payload if isinstance(payload, str) else json.dumps(payload)
        return CompletionResult(text=text, input_tokens=10, output_tokens=5, stop_reason="end_turn")


def _payload(summary, technique_id):
    return {
        "summary": summary,
        "report_date": None,
        "confidence": "high",
        "actors": [],
        "techniques": [{"technique_id": technique_id, "evidence_quote": "a quote of sufficient length"}],
        "targets": [],
        "iocs": [],
    }


def _render(text: str) -> str:
    return f"<<<REPORT\n{text}\nREPORT>>>"


def test_short_document_is_one_call_and_is_not_marked_chunked():
    client = _ScriptedClient([_payload("Only call.", "T1078")])
    outcome = extract_document(client, "system", _render, _document(1), max_input_tokens=50_000)

    assert len(client.prompts) == 1
    assert outcome.succeeded and not outcome.was_chunked
    assert outcome.attempts[0][0] is None  # chunk_index NULL: not chunked


def test_long_document_is_chunked_and_merged():
    client = _ScriptedClient([
        _payload("First half.", "T1078"),
        _payload("Second half.", "T1090"),
        _payload("Third.", "T1082"),
        _payload("Fourth.", "T1133"),
    ])
    outcome = extract_document(client, "system", _render, _document(20), max_input_tokens=800)

    assert outcome.was_chunked
    assert len(client.prompts) == outcome.chunk_count
    assert {t.technique_id for t in outcome.extraction.techniques} >= {"T1078", "T1090"}
    # Every attempt is tagged with its chunk, so the audit trail stays readable.
    assert [index for index, _ in outcome.attempts] == list(range(outcome.chunk_count))


def test_a_failed_chunk_does_not_discard_the_rest():
    """The degradation §5.3 asks for -- but counted, because it is otherwise
    silent under-extraction."""
    client = _ScriptedClient([
        _payload("Good.", "T1078"),
        "not json at all",          # both attempts for this chunk fail
        "still not json",
        _payload("Also good.", "T1090"),
        _payload("Fine.", "T1082"),
        _payload("Fine.", "T1133"),
    ])
    outcome = extract_document(client, "system", _render, _document(20), max_input_tokens=800)

    assert outcome.succeeded
    assert len(outcome.failed_chunks) == 1
    assert {t.technique_id for t in outcome.extraction.techniques} >= {"T1078", "T1090"}


def test_all_chunks_failing_is_a_failed_document():
    client = _ScriptedClient(["nope"] * 20)
    outcome = extract_document(client, "system", _render, _document(20), max_input_tokens=800)

    assert not outcome.succeeded
    assert outcome.extraction is None
    assert outcome.status == "invalid_json"
    assert len(outcome.failed_chunks) == outcome.chunk_count


def test_token_usage_is_summed_across_chunks():
    client = _ScriptedClient([_payload(f"Part {i}.", "T1078") for i in range(10)])
    outcome = extract_document(client, "system", _render, _document(20), max_input_tokens=800)

    assert outcome.input_tokens == 10 * outcome.chunk_count
    assert outcome.output_tokens == 5 * outcome.chunk_count


def test_output_cap_reaches_the_client():
    """The other half of the context budget: a small backend's output cap has
    to arrive at the call, not just its input budget."""
    client = _ScriptedClient([_payload("One.", "T1078")])
    extract_document(
        client, "system", _render, _document(1), max_input_tokens=50_000, max_tokens=2048
    )
    assert client.max_tokens == 2048
