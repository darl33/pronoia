"""Provider resolution (DESIGN.md §5.4): zero-to-three env vars in, a working
config out. §5.3 made swapping possible; this makes it easy.

Completions resolve in this order: explicit LLM_BASE_URL, else infer from the
LLM_API_KEY prefix, else probe localhost. Each provider carries a default base
URL and model, so a key alone is a working configuration.

Two rules the module exists to enforce: an unrecognized key prefix raises a
ConfigError naming LLM_BASE_URL rather than crashing, and resolve_embedding
never raises at all -- embeddings degrade to None so the one-key promise holds.
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass

import httpx

log = logging.getLogger("enrich.config")

# Must equal the VECTOR(n) in db/migrations; §5.3 fixes it at first migration.
# README "Changing the embedding model" covers changing them together.
REPORT_EMBEDDING_DIM = 1024

# §5.4 zero-key path. Both speak OpenAI-compatible /v1, so one probe covers
# Ollama and vLLM and neither needs a vendor client.
LOCAL_PROBE_URLS = ("http://localhost:11434", "http://localhost:8000")
PROBE_TIMEOUT_SECONDS = 1.5

DEFAULT_ANTHROPIC_MODEL = "claude-sonnet-5"

# Context budget (§5.3), in tokens of *input*, per backend. Chunking above this
# is what makes "swap the env var to a local model" degrade instead of failing
# on the richest documents. Overridable with MAX_INPUT_TOKENS.
#
# The local default is deliberately small: the OpenAI-compatible adapter
# reaches runtimes whose context window we cannot discover from here (/v1/models
# does not report it), and an 8k model is the common case an unconfigured
# reviewer has running. Chunking a document that would have fit costs an extra
# call; not chunking one that doesn't fit loses the document entirely.
LOCAL_MAX_INPUT_TOKENS = 6_000
HOSTED_MAX_INPUT_TOKENS = 100_000


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
    # None means the provider has no embeddings API at all. Anthropic is the
    # motivating case (§5.3) and the reason embeddings are a separate slot.
    default_embedding_model: str | None
    # True for providers whose embeddings endpoint accepts an OpenAI-style
    # `dimensions` request parameter. Only those can be asked for a vector
    # width that matches VECTOR(1024); sending it elsewhere is a 400.
    embedding_supports_dimensions: bool = False
    # True for the one provider we do not reach through the OpenAI-compatible
    # adapter. Anthropic's Messages API is not /v1/chat/completions.
    native_sdk: bool = False
    # Well below each vendor's real window: the budget is an estimate made from
    # a character heuristic (enrich/chunk.py), and the cost of being wrong is a
    # hard failure at the top of the range and one extra call near it.
    max_input_tokens: int = HOSTED_MAX_INPUT_TOKENS


# Starting points, all overridden by LLM_MODEL. The point is that a bare key is
# enough for a first run.
ANTHROPIC = Provider(
    name="anthropic",
    base_url="https://api.anthropic.com",
    default_model=DEFAULT_ANTHROPIC_MODEL,
    default_embedding_model=None,
    native_sdk=True,
    max_input_tokens=150_000,
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

# Ordered longest-prefix-first and asserted below: 'sk-ant-', 'sk-proj-' and
# 'sk-or-v1-' all start with 'sk-', so a shortest-first table would resolve
# every Anthropic key to OpenAI.
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
    # Documents longer than this are chunked (§5.3). Defaults to the
    # conservative local figure so a config built by hand degrades safely.
    max_input_tokens: int = LOCAL_MAX_INPUT_TOKENS


@dataclass(frozen=True)
class EmbeddingConfig:
    provider: str
    base_url: str
    model: str
    api_key: str | None
    source: str
    # Ask the endpoint for this vector width, or None to take its native width.
    # Only set for providers that accept the parameter (see Provider above).
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


def resolve_max_input_tokens(default: int) -> int:
    """MAX_INPUT_TOKENS if set and sane, else the backend's own default.

    A bad value is ignored with a warning rather than raising: this is a
    tuning knob, and a typo in it should not stop a batch that would otherwise
    run correctly on the default.
    """
    override = _env("MAX_INPUT_TOKENS")
    if override is None:
        return default
    try:
        value = int(override)
    except ValueError:
        log.warning("MAX_INPUT_TOKENS=%r is not an integer; using %d", override, default)
        return default
    if value <= 0:
        log.warning("MAX_INPUT_TOKENS=%d is not positive; using %d", value, default)
        return default
    return value


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
            # An explicit base URL means an OpenAI-compatible proxy in front of
            # the vendor, so it also switches off the native SDK path.
            return CompletionConfig(
                provider=provider.name,
                base_url=base_url_override or provider.base_url,
                model=model_override or provider.default_model,
                api_key=key,
                native_sdk=provider.native_sdk and base_url_override is None,
                source=f"LLM_API_KEY prefix -> {provider.name}",
                max_input_tokens=resolve_max_input_tokens(provider.max_input_tokens),
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
        # The endpoint can be asked for the width the schema already has, which
        # is the difference between OpenAI's 1536-wide default working out of
        # the box and silently degrading against VECTOR(1024).
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

    # Last resort: the completion provider has no embeddings API (Anthropic is
    # the case §5.3 names), so look for a local one. A reviewer running Ollama
    # for embeddings and a hosted key for extraction is a perfectly ordinary
    # setup and needs no configuration to work.
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
