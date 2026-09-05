"""Provider resolution (DESIGN.md §5.4): zero-to-three env vars in, a working
config out.

Completions resolve as: explicit LLM_BASE_URL, else the LLM_API_KEY prefix,
else a localhost probe. resolve_embedding never raises -- embeddings degrade to
None so the one-key promise holds.

Rationale: docs/DECISIONS.md#key-inference
Embeddings degrading rather than blocking: docs/DECISIONS.md#embeddings-degrade
Token budgets: docs/DECISIONS.md#context-budget
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass

import httpx

log = logging.getLogger("enrich.config")

# Must equal the VECTOR(n) in db/migrations. Changing both together: see the
# README section "Changing the embedding model".
REPORT_EMBEDDING_DIM = 1024

# §5.4 zero-key path; both speak OpenAI-compatible /v1, so one probe covers them.
LOCAL_PROBE_URLS = ("http://localhost:11434", "http://localhost:8000")
PROBE_TIMEOUT_SECONDS = 1.5

DEFAULT_ANTHROPIC_MODEL = "claude-sonnet-5"

# Per-backend token budgets; documents over the input figure are chunked
# (§5.3). The local pair must fit one 8k window together, since input and
# output share it. Overridable with MAX_INPUT_TOKENS / MAX_OUTPUT_TOKENS.
# Why these numbers: docs/DECISIONS.md#context-budget
LOCAL_MAX_INPUT_TOKENS = 6_000
HOSTED_MAX_INPUT_TOKENS = 100_000
LOCAL_MAX_OUTPUT_TOKENS = 2_048
HOSTED_MAX_OUTPUT_TOKENS = 16_000


class ConfigError(Exception):
    """Config could not be resolved.

    Every message must name the environment variable that fixes it. A config
    error the reader can't act on is worse than no message at all.
    """


@dataclass(frozen=True)
class Provider:
    name: str
    base_url: str
    default_model: str
    # None means the provider has no embeddings API (Anthropic).
    default_embedding_model: str | None
    # Accepts an OpenAI-style `dimensions` parameter; sending it elsewhere 400s.
    embedding_supports_dimensions: bool = False
    # Not reached through the OpenAI-compatible adapter (Anthropic's Messages API).
    native_sdk: bool = False
    # Well below the vendor's real window; the budget is a character estimate.
    max_input_tokens: int = HOSTED_MAX_INPUT_TOKENS
    max_output_tokens: int = HOSTED_MAX_OUTPUT_TOKENS


# Starting points, all overridden by LLM_MODEL. The point is that a bare key is
# enough for a first run.
ANTHROPIC = Provider(
    name="anthropic",
    base_url="https://api.anthropic.com",
    default_model=DEFAULT_ANTHROPIC_MODEL,
    default_embedding_model=None,
    native_sdk=True,
    max_input_tokens=150_000,
    max_output_tokens=HOSTED_MAX_OUTPUT_TOKENS,
)
OPENAI = Provider(
    name="openai",
    base_url="https://api.openai.com/v1",
    default_model="gpt-4.1-mini",
    default_embedding_model="text-embedding-3-small",
    embedding_supports_dimensions=True,
)
GROQ = Provider(
    name="groq",
    base_url="https://api.groq.com/openai/v1",
    default_model="llama-3.3-70b-versatile",
    default_embedding_model=None,
)
OPENROUTER = Provider(
    name="openrouter",
    base_url="https://openrouter.ai/api/v1",
    default_model="anthropic/claude-sonnet-5",
    default_embedding_model=None,
)

PROVIDERS = (ANTHROPIC, OPENAI, GROQ, OPENROUTER)
PROVIDERS_BY_NAME = {provider.name: provider for provider in PROVIDERS}

# Longest-prefix-first, asserted below: 'sk-ant-' and 'sk-proj-' both start
# with 'sk-', so shortest-first would resolve Anthropic keys to OpenAI.
KEY_PREFIXES: tuple[tuple[str, Provider], ...] = (
    ("sk-or-v1-", OPENROUTER),
    ("sk-proj-", OPENAI),
    ("sk-ant-", ANTHROPIC),
    ("gsk_", GROQ),
    ("sk-", OPENAI),
)
assert [len(prefix) for prefix, _ in KEY_PREFIXES] == sorted(
    (len(prefix) for prefix, _ in KEY_PREFIXES), reverse=True
), "KEY_PREFIXES must be longest-first or overlapping prefixes resolve to the wrong provider"

# Synthetic provider names for the two configurations that are not one of the
# vendors above.
OPENAI_COMPATIBLE = "openai_compatible"  # explicit LLM_BASE_URL
LOCAL = "local"  # discovered by probing localhost


@dataclass(frozen=True)
class CompletionConfig:
    provider: str
    base_url: str
    model: str
    api_key: str | None
    native_sdk: bool
    source: str  # how this was resolved, in words, for `pronoia doctor`
    # Documents over this are chunked; defaults conservative so a hand-built
    # config degrades safely.
    max_input_tokens: int = LOCAL_MAX_INPUT_TOKENS
    max_output_tokens: int = LOCAL_MAX_OUTPUT_TOKENS


@dataclass(frozen=True)
class EmbeddingConfig:
    provider: str
    base_url: str
    model: str
    api_key: str | None
    source: str
    # Requested vector width, or None to take the endpoint's native one.
    request_dimension: int | None


# ---------- environment ----------


def _env(name: str) -> str | None:
    """Empty and whitespace-only count as unset -- `.env` files are full of
    `LLM_MODEL=` placeholders, and an empty string that reads as "configured"
    is the worst failure mode for a config system that guesses."""
    value = os.environ.get(name, "").strip()
    return value or None


def api_key() -> str | None:
    """The one required input (§5.4). Vendor-named variables are accepted after
    it so an environment that already exports one keeps working."""
    return _env("LLM_API_KEY") or _env("ANTHROPIC_API_KEY") or _env("OPENAI_API_KEY")


def match_key_prefix(key: str) -> Provider | None:
    for prefix, provider in KEY_PREFIXES:
        if key.startswith(prefix):
            return provider
    return None


def _positive_int_env(name: str, default: int) -> int:
    """The env override if set and positive, else the default. A bad value warns
    and falls back -- a typo in a tuning knob should not stop a batch."""
    override = _env(name)
    if override is None:
        return default
    try:
        value = int(override)
    except ValueError:
        log.warning("%s=%r is not an integer; using %d", name, override, default)
        return default
    if value <= 0:
        log.warning("%s=%d is not positive; using %d", name, value, default)
        return default
    return value


def resolve_max_input_tokens(default: int) -> int:
    return _positive_int_env("MAX_INPUT_TOKENS", default)


def resolve_max_output_tokens(default: int) -> int:
    return _positive_int_env("MAX_OUTPUT_TOKENS", default)


# ---------- discovery ----------


def probe_openai_compatible(
    root_url: str, api_key_: str | None = None, timeout: float = PROBE_TIMEOUT_SECONDS
) -> list[str] | None:
    """Model ids advertised at /v1/models, or None.

    Broad except on purpose: refused, DNS, 404, 401 all mean the same thing to
    the caller, and a startup probe that raises defeats the point of probing.
    """
    url = root_url.rstrip("/")
    if not url.endswith("/v1"):
        url += "/v1"
    headers = {"Authorization": f"Bearer {api_key_}"} if api_key_ else {}
    try:
        response = httpx.get(f"{url}/models", headers=headers, timeout=timeout)
        response.raise_for_status()
        payload = response.json()
    except Exception:  # noqa: BLE001 -- see docstring
        return None

    data = payload.get("data") if isinstance(payload, dict) else None
    if not isinstance(data, list):
        return None
    return [item["id"] for item in data if isinstance(item, dict) and item.get("id")]


def discover_local() -> tuple[str, list[str]] | None:
    """Probe the §5.4 local runtimes; return (base_url, model_ids) or None."""
    for root in LOCAL_PROBE_URLS:
        models = probe_openai_compatible(root)
        if models:
            return root.rstrip("/") + "/v1", models
    return None


def _looks_like_embedding_model(model_id: str) -> bool:
    return "embed" in model_id.lower()


def _pick_completion_model(model_ids: list[str]) -> str:
    """First advertised model that isn't obviously an embedding model."""
    for model_id in model_ids:
        if not _looks_like_embedding_model(model_id):
            return model_id
    return model_ids[0]


def _pick_embedding_model(model_ids: list[str]) -> str | None:
    for model_id in model_ids:
        if _looks_like_embedding_model(model_id):
            return model_id
    return None


# ---------- completions ----------


def _resolve_model_for(base_url: str, override: str | None, api_key_: str | None) -> str:
    if override:
        return override
    models = probe_openai_compatible(base_url, api_key_)
    if models:
        return _pick_completion_model(models)
    raise ConfigError(
        f"{base_url} did not advertise any models at /v1/models, so there is no "
        "default to pick. Set LLM_MODEL to the model this endpoint serves."
    )


def resolve_completion() -> CompletionConfig:
    """Resolve slot 1 (§5.3). Raises ConfigError naming the fix."""
    key = api_key()
    base_url_override = _env("LLM_BASE_URL")
    model_override = _env("LLM_MODEL")

    if key:
        provider = match_key_prefix(key)
        if provider is not None:
            # An explicit base URL means a proxy in front of the vendor, so it
            # also switches off the native SDK path.
            return CompletionConfig(
                provider=provider.name,
                base_url=base_url_override or provider.base_url,
                model=model_override or provider.default_model,
                api_key=key,
                native_sdk=provider.native_sdk and base_url_override is None,
                source=f"LLM_API_KEY prefix -> {provider.name}",
                max_input_tokens=resolve_max_input_tokens(provider.max_input_tokens),
                max_output_tokens=resolve_max_output_tokens(provider.max_output_tokens),
            )

        if base_url_override:
            return CompletionConfig(
                provider=OPENAI_COMPATIBLE,
                base_url=base_url_override,
                model=_resolve_model_for(base_url_override, model_override, key),
                api_key=key,
                native_sdk=False,
                source="LLM_BASE_URL (key prefix not recognized)",
                max_input_tokens=resolve_max_input_tokens(LOCAL_MAX_INPUT_TOKENS),
                max_output_tokens=resolve_max_output_tokens(LOCAL_MAX_OUTPUT_TOKENS),
            )

        known = ", ".join(prefix for prefix, _ in KEY_PREFIXES)
        raise ConfigError(
            f"LLM_API_KEY does not start with a known provider prefix ({known}), "
            "so there is no base URL to infer. This is not necessarily a bad key: "
            "set LLM_BASE_URL to the OpenAI-compatible endpoint it belongs to "
            "(and LLM_MODEL if that endpoint does not advertise a usable default)."
        )

    if base_url_override:
        return CompletionConfig(
            provider=OPENAI_COMPATIBLE,
            base_url=base_url_override,
            model=_resolve_model_for(base_url_override, model_override, None),
            api_key=None,
            native_sdk=False,
            source="LLM_BASE_URL (no key)",
            max_input_tokens=resolve_max_input_tokens(LOCAL_MAX_INPUT_TOKENS),
            max_output_tokens=resolve_max_output_tokens(LOCAL_MAX_OUTPUT_TOKENS),
        )

    local = discover_local()
    if local is None:
        raise ConfigError(
            "no LLM is configured and no local runtime answered. Any one of these "
            "fixes it: set LLM_API_KEY (sk-ant-... for Anthropic, sk-... for "
            "OpenAI, gsk_... for Groq); or start Ollama on "
            f"{LOCAL_PROBE_URLS[0]} or vLLM on {LOCAL_PROBE_URLS[1]}; or set "
            "LLM_BASE_URL to any OpenAI-compatible /v1 endpoint."
        )

    base_url, model_ids = local
    return CompletionConfig(
        provider=LOCAL,
        base_url=base_url,
        model=model_override or _pick_completion_model(model_ids),
        api_key=None,
        native_sdk=False,
        source=f"local discovery at {base_url}",
        max_input_tokens=resolve_max_input_tokens(LOCAL_MAX_INPUT_TOKENS),
        max_output_tokens=resolve_max_output_tokens(LOCAL_MAX_OUTPUT_TOKENS),
    )


# ---------- embeddings ----------


def _embedding_config(
    *, provider: str, base_url: str, model: str, api_key_: str | None, source: str,
    supports_dimensions: bool,
) -> EmbeddingConfig:
    override = _env("EMBEDDING_DIM")
    request_dimension: int | None = None
    if override is not None:
        try:
            request_dimension = int(override)
        except ValueError:
            log.warning("EMBEDDING_DIM=%r is not an integer; ignoring it", override)
    elif supports_dimensions:
        # Ask for the width the schema already has, rather than degrading
        # against the provider's wider default.
        request_dimension = REPORT_EMBEDDING_DIM
    return EmbeddingConfig(
        provider=provider,
        base_url=base_url,
        model=model,
        api_key=api_key_,
        source=source,
        request_dimension=request_dimension,
    )


def resolve_embedding(completion: CompletionConfig) -> EmbeddingConfig | None:
    """Resolve slot 2 (§5.3), or None if nothing resolves.

    Never raises -- §5.4: embeddings degrade rather than block. None means
    "leave report.embedding NULL and carry on".

    Reads the same EMBEDDING_* vars the Rust /search endpoint does, so a swap
    stays one config change consumed in two languages.
    """
    base_url_override = _env("EMBEDDING_BASE_URL")
    model_override = _env("EMBEDDING_MODEL")
    key_override = _env("EMBEDDING_API_KEY")

    if base_url_override:
        model = model_override or _pick_embedding_model(
            probe_openai_compatible(base_url_override, key_override) or []
        )
        if model is None:
            log.warning(
                "EMBEDDING_BASE_URL=%s advertises no embedding model; set "
                "EMBEDDING_MODEL to name one. Continuing without embeddings.",
                base_url_override,
            )
            return None
        return _embedding_config(
            provider=OPENAI_COMPATIBLE,
            base_url=base_url_override,
            model=model,
            api_key_=key_override,
            source="EMBEDDING_BASE_URL",
            supports_dimensions=_env("EMBEDDING_DIM") is not None,
        )

    # Reuse the completion provider when it actually has an embeddings API.
    provider = PROVIDERS_BY_NAME.get(completion.provider)
    if provider is not None and provider.default_embedding_model:
        return _embedding_config(
            provider=provider.name,
            base_url=completion.base_url,
            model=model_override or provider.default_embedding_model,
            api_key_=key_override or completion.api_key,
            source=f"reused completion provider ({provider.name})",
            supports_dimensions=provider.embedding_supports_dimensions,
        )

    if completion.provider in (LOCAL, OPENAI_COMPATIBLE):
        model = model_override or _pick_embedding_model(
            probe_openai_compatible(completion.base_url, key_override or completion.api_key) or []
        )
        if model is not None:
            return _embedding_config(
                provider=completion.provider,
                base_url=completion.base_url,
                model=model,
                api_key_=key_override or completion.api_key,
                source=f"reused completion endpoint ({completion.base_url})",
                supports_dimensions=_env("EMBEDDING_DIM") is not None,
            )

    # Last resort: completion provider has no embeddings API, so look for a
    # local one -- Ollama for embeddings plus a hosted key for extraction is an
    # ordinary setup that should need no configuration.
    local = discover_local()
    if local is not None:
        base_url, model_ids = local
        model = model_override or _pick_embedding_model(model_ids)
        if model is not None:
            return _embedding_config(
                provider=LOCAL,
                base_url=base_url,
                model=model,
                api_key_=key_override,
                source=f"local discovery at {base_url}",
                supports_dimensions=_env("EMBEDDING_DIM") is not None,
            )

    log.info(
        "no embedding provider resolved; reports will be written with a NULL "
        "embedding and semantic search stays disabled. Set EMBEDDING_BASE_URL "
        "(and EMBEDDING_MODEL) to enable it."
    )
    return None
