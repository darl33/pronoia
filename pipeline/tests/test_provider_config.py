"""Provider resolution (DESIGN.md §5.4): one key is sufficient, an unknown
prefix names its own fix, and embeddings degrade instead of blocking.

Local discovery is monkeypatched so the suite passes identically with and
without Ollama running.
"""

from __future__ import annotations

import pytest

from enrich import config as cfg

ENV_VARS = (
    "LLM_API_KEY",
    "LLM_BASE_URL",
    "LLM_MODEL",
    "ANTHROPIC_API_KEY",
    "OPENAI_API_KEY",
    "EMBEDDING_BASE_URL",
    "EMBEDDING_MODEL",
    "EMBEDDING_API_KEY",
    "EMBEDDING_DIM",
    "MAX_INPUT_TOKENS",
    "MAX_OUTPUT_TOKENS",
)


@pytest.fixture(autouse=True)
def clean_env(monkeypatch):
    """Start every test from "nothing configured", and with no local runtime.

    Without the discover_local stub these tests would pass or fail depending on
    whether the developer happens to have Ollama running.
    """
    for name in ENV_VARS:
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setattr(cfg, "discover_local", lambda: None)
    monkeypatch.setattr(cfg, "probe_openai_compatible", lambda *a, **k: None)


# ---- key prefix inference (§5.4 "provider inferred from the key") ----


@pytest.mark.parametrize(
    "key, expected",
    [
        ("sk-ant-api03-xxxx", "anthropic"),
        ("sk-proj-xxxx", "openai"),
        ("sk-xxxx", "openai"),
        ("gsk_xxxx", "groq"),
        ("sk-or-v1-xxxx", "openrouter"),
    ],
)
def test_key_prefix_selects_provider(monkeypatch, key, expected):
    monkeypatch.setenv("LLM_API_KEY", key)
    assert cfg.resolve_completion().provider == expected


def test_a_key_alone_is_a_complete_configuration(monkeypatch):
    """§5.4: 'a key implies a working configuration'."""
    monkeypatch.setenv("LLM_API_KEY", "sk-ant-api03-xxxx")
    resolved = cfg.resolve_completion()

    assert resolved.base_url == cfg.ANTHROPIC.base_url
    assert resolved.model == cfg.ANTHROPIC.default_model
    assert resolved.native_sdk is True


def test_longer_prefixes_win_over_shorter_ones():
    """'sk-ant-' and 'sk-proj-' both start with 'sk-'. A shortest-first table
    would silently route every Anthropic key to OpenAI, so the ordering is the
    invariant, not an implementation detail."""
    assert cfg.match_key_prefix("sk-ant-xxx") is cfg.ANTHROPIC
    assert cfg.match_key_prefix("sk-or-v1-xxx") is cfg.OPENROUTER
    assert cfg.match_key_prefix("sk-xxx") is cfg.OPENAI


def test_vendor_named_key_variables_are_accepted(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-api03-xxxx")
    assert cfg.resolve_completion().provider == "anthropic"


def test_llm_api_key_wins_over_vendor_variables(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-api03-xxxx")
    monkeypatch.setenv("LLM_API_KEY", "gsk_xxxx")
    assert cfg.resolve_completion().provider == "groq"


def test_blank_values_count_as_unset(monkeypatch):
    """`.env` files are full of `LLM_MODEL=` placeholders."""
    monkeypatch.setenv("LLM_API_KEY", "sk-ant-api03-xxxx")
    monkeypatch.setenv("LLM_MODEL", "   ")
    assert cfg.resolve_completion().model == cfg.ANTHROPIC.default_model


# ---- overrides ----


def test_explicit_base_url_and_model_override_the_inference(monkeypatch):
    monkeypatch.setenv("LLM_API_KEY", "sk-ant-api03-xxxx")
    monkeypatch.setenv("LLM_BASE_URL", "http://gateway.internal/v1")
    monkeypatch.setenv("LLM_MODEL", "some-proxied-model")
    resolved = cfg.resolve_completion()

    assert resolved.base_url == "http://gateway.internal/v1"
    assert resolved.model == "some-proxied-model"
    # An explicit endpoint means a compatible proxy, not the vendor SDK.
    assert resolved.native_sdk is False


# ---- the two failure messages that have to be actionable ----


def test_unrecognized_key_prefix_names_llm_base_url(monkeypatch):
    """§5.4: 'Unrecognized prefix is not an error, it just means you must set
    LLM_BASE_URL yourself, and the error message says exactly that.'"""
    monkeypatch.setenv("LLM_API_KEY", "wat-this-is-not-a-known-prefix")

    with pytest.raises(cfg.ConfigError) as excinfo:
        cfg.resolve_completion()
    assert "LLM_BASE_URL" in str(excinfo.value)


def test_no_key_and_no_local_runtime_names_every_way_out(monkeypatch):
    with pytest.raises(cfg.ConfigError) as excinfo:
        cfg.resolve_completion()

    message = str(excinfo.value)
    assert "LLM_API_KEY" in message
    assert "LLM_BASE_URL" in message
    assert "11434" in message  # the Ollama probe target


# ---- zero-key local path (§5.4) ----


def test_local_discovery_needs_no_configuration_at_all(monkeypatch):
    monkeypatch.setattr(
        cfg, "discover_local", lambda: ("http://localhost:11434/v1", ["llama3.2", "mxbai-embed-large"])
    )
    resolved = cfg.resolve_completion()

    assert resolved.provider == "local"
    assert resolved.api_key is None
    assert resolved.base_url == "http://localhost:11434/v1"
    # An embedding model is not a completion model.
    assert resolved.model == "llama3.2"


# ---- embeddings degrade, never block (§5.4) ----


def test_anthropic_with_no_embedding_provider_degrades_to_none(monkeypatch):
    """Anthropic has no embeddings API (§5.3), so this is the default one-key
    path: extraction works, embedding is skipped, nothing raises."""
    monkeypatch.setenv("LLM_API_KEY", "sk-ant-api03-xxxx")
    completion = cfg.resolve_completion()

    assert cfg.resolve_embedding(completion) is None


def test_openai_key_also_configures_embeddings(monkeypatch):
    monkeypatch.setenv("LLM_API_KEY", "sk-xxxx")
    completion = cfg.resolve_completion()
    embedding = cfg.resolve_embedding(completion)

    assert embedding is not None
    assert embedding.model == cfg.OPENAI.default_embedding_model
    # text-embedding-3-* honour `dimensions`, so ask for the width the schema
    # already has instead of degrading against a 1536-wide default.
    assert embedding.request_dimension == cfg.REPORT_EMBEDDING_DIM


def test_anthropic_completions_can_borrow_a_local_embedding_provider(monkeypatch):
    monkeypatch.setenv("LLM_API_KEY", "sk-ant-api03-xxxx")
    monkeypatch.setattr(
        cfg, "discover_local", lambda: ("http://localhost:11434/v1", ["llama3.2", "mxbai-embed-large"])
    )
    embedding = cfg.resolve_embedding(cfg.resolve_completion())

    assert embedding is not None
    assert embedding.model == "mxbai-embed-large"
    # Nothing to send `dimensions` to; take the endpoint's native width.
    assert embedding.request_dimension is None


def test_embedding_resolution_never_raises(monkeypatch):
    """The whole point of §5.4's 'embeddings degrade instead of blocking'."""
    monkeypatch.setenv("EMBEDDING_BASE_URL", "http://nothing-is-listening.invalid/v1")
    monkeypatch.setenv("LLM_API_KEY", "sk-ant-api03-xxxx")

    assert cfg.resolve_embedding(cfg.resolve_completion()) is None


# ---- token budgets (§5.3): input and output share one window ----


def test_hosted_backend_gets_the_large_budgets(monkeypatch):
    monkeypatch.setenv("LLM_API_KEY", "sk-ant-api03-xxxx")
    config = cfg.resolve_completion()

    assert config.max_input_tokens == 150_000
    assert config.max_output_tokens == cfg.HOSTED_MAX_OUTPUT_TOKENS


def test_openai_compatible_backend_gets_the_conservative_pair(monkeypatch):
    """The pair has to fit one window: an 8k local model cannot serve 6k of
    input and 16k of output, and asking for it is a hard error on vLLM and a
    silent clamp on Ollama."""
    monkeypatch.setenv("LLM_BASE_URL", "http://localhost:8000/v1")
    monkeypatch.setenv("LLM_MODEL", "qwen3:8b")
    config = cfg.resolve_completion()

    assert config.max_input_tokens == cfg.LOCAL_MAX_INPUT_TOKENS
    assert config.max_output_tokens == cfg.LOCAL_MAX_OUTPUT_TOKENS
    assert config.max_input_tokens + config.max_output_tokens <= 8192


def test_both_budgets_are_overridable(monkeypatch):
    monkeypatch.setenv("LLM_API_KEY", "sk-ant-api03-xxxx")
    monkeypatch.setenv("MAX_INPUT_TOKENS", "12000")
    monkeypatch.setenv("MAX_OUTPUT_TOKENS", "3000")
    config = cfg.resolve_completion()

    assert (config.max_input_tokens, config.max_output_tokens) == (12000, 3000)


@pytest.mark.parametrize("bad", ["not-a-number", "0", "-1"])
def test_a_bad_budget_override_warns_and_falls_back(monkeypatch, bad):
    """A typo in a tuning knob must not stop a batch that runs fine on the
    default."""
    monkeypatch.setenv("LLM_API_KEY", "sk-ant-api03-xxxx")
    monkeypatch.setenv("MAX_OUTPUT_TOKENS", bad)

    assert cfg.resolve_completion().max_output_tokens == cfg.HOSTED_MAX_OUTPUT_TOKENS
