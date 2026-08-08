"""The one adapter that reaches most of the BYO universe (DESIGN.md §5.3).

One client stands in for Ollama, vLLM, LM Studio, OpenRouter and Groq, so its
response parsing is load-bearing in a way a per-vendor client's would not be.
Canned responses, no network.
"""

from __future__ import annotations

import httpx
import pytest

from enrich.client import (
    EnrichmentError,
    OpenAICompatibleClient,
    OpenAICompatibleEmbeddingClient,
)


def _canned(monkeypatch, method: str, payload: dict, status: int = 200):
    """Replace httpx.post/get with something that returns `payload`."""
    captured: dict = {}

    def fake(url, **kwargs):
        captured["url"] = url
        captured["json"] = kwargs.get("json")
        captured["headers"] = kwargs.get("headers")
        return httpx.Response(
            status, json=payload, request=httpx.Request(method.upper(), url)
        )

    monkeypatch.setattr(httpx, method, fake)
    return captured


CHAT_RESPONSE = {
    "choices": [{"message": {"content": '{"summary": "x"}'}, "finish_reason": "stop"}],
    "usage": {"prompt_tokens": 1200, "completion_tokens": 340},
}


def test_completion_carries_usage_and_stop_reason(monkeypatch):
    """§5.3: 'a bare str return discards the signals you need for cost tracking
    and truncation detection'."""
    captured = _canned(monkeypatch, "post", CHAT_RESPONSE)
    client = OpenAICompatibleClient(base_url="http://localhost:11434/v1", model="llama3.2")

    result = client.complete("system", "user", max_tokens=4096)

    assert result.text == '{"summary": "x"}'
    assert result.input_tokens == 1200
    assert result.output_tokens == 340
    assert result.stop_reason == "stop"
    assert result.truncated is False
    assert captured["url"] == "http://localhost:11434/v1/chat/completions"
    assert captured["json"]["max_tokens"] == 4096


def test_length_finish_reason_is_recognized_as_truncation(monkeypatch):
    payload = {"choices": [{"message": {"content": "{"}, "finish_reason": "length"}]}
    _canned(monkeypatch, "post", payload)
    client = OpenAICompatibleClient(base_url="http://localhost:11434/v1", model="llama3.2")

    assert client.complete("system", "user").truncated is True


def test_missing_usage_block_is_not_an_error(monkeypatch):
    """Several local runtimes omit `usage` entirely. Losing cost telemetry must
    not lose the extraction."""
    payload = {"choices": [{"message": {"content": "{}"}, "finish_reason": "stop"}]}
    _canned(monkeypatch, "post", payload)
    client = OpenAICompatibleClient(base_url="http://localhost:8000/v1", model="local")

    result = client.complete("system", "user")
    assert result.text == "{}"
    assert result.input_tokens is None


def test_unexpected_shape_becomes_an_enrichment_error(monkeypatch):
    """Recorded as api_error on the enrichment_run, not an uncaught traceback
    that kills the batch."""
    _canned(monkeypatch, "post", {"error": "model not found"})
    client = OpenAICompatibleClient(base_url="http://localhost:11434/v1", model="nope")

    with pytest.raises(EnrichmentError):
        client.complete("system", "user")


def test_api_key_is_sent_as_a_bearer_token(monkeypatch):
    captured = _canned(monkeypatch, "post", CHAT_RESPONSE)
    client = OpenAICompatibleClient(
        base_url="https://api.groq.com/openai/v1", model="llama-3.3-70b-versatile", api_key="gsk_x"
    )
    client.complete("system", "user")

    assert captured["headers"]["Authorization"] == "Bearer gsk_x"


# ---- embeddings ----


def test_dimension_is_measured_not_guessed(monkeypatch):
    """report.embedding_dim has to be true, or storing provenance is theatre."""
    _canned(monkeypatch, "post", {"data": [{"index": 0, "embedding": [0.1] * 768}]})
    client = OpenAICompatibleEmbeddingClient(
        base_url="http://localhost:11434/v1", model="nomic-embed-text"
    )

    assert client.dimension == 768


def test_batch_is_reordered_by_index(monkeypatch):
    """A permuted batch would attach every vector to the wrong report, and the
    only symptom would be bad search results months later."""
    _canned(
        monkeypatch,
        "post",
        {"data": [{"index": 1, "embedding": [2.0]}, {"index": 0, "embedding": [1.0]}]},
    )
    client = OpenAICompatibleEmbeddingClient(base_url="http://x/v1", model="e")

    assert client.embed(["first", "second"]) == [[1.0], [2.0]]


def test_dimensions_parameter_is_only_sent_when_configured(monkeypatch):
    """Ollama rejects an unknown `dimensions` key, so it is opt-in per provider."""
    captured = _canned(monkeypatch, "post", {"data": [{"index": 0, "embedding": [0.0]}]})

    OpenAICompatibleEmbeddingClient(base_url="http://x/v1", model="e").embed(["t"])
    assert "dimensions" not in captured["json"]

    OpenAICompatibleEmbeddingClient(
        base_url="http://x/v1", model="e", request_dimension=1024
    ).embed(["t"])
    assert captured["json"]["dimensions"] == 1024
