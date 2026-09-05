"""Provider abstraction (DESIGN.md §5.3): two slots, not one.

CompletionClient (AnthropicClient + one OpenAI-compatible adapter) and
EmbeddingClient, separate because Anthropic has no embeddings API. `complete`
returns usage and stop reason but does not parse, validate or retry.

Rationale and adapter quirks: docs/DECISIONS.md#two-slots
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

import httpx

from enrich.config import (
    CompletionConfig,
    EmbeddingConfig,
    resolve_completion,
    resolve_embedding,
)

DEFAULT_MAX_TOKENS = 16000
DEFAULT_TIMEOUT_SECONDS = 300.0

# "The model was cut off", in both vendors' vocabularies. Not a guardrail
# branch -- it fails the JSON parse anyway -- but the fix differs.
TRUNCATION_STOP_REASONS = frozenset({"max_tokens", "length"})

Vector = list[float]


class EnrichmentError(Exception):
    """Provider call failed. Recorded as `api_error` on the enrichment_run."""


@dataclass(frozen=True)
class CompletionResult:
    text: str
    input_tokens: int | None
    output_tokens: int | None
    stop_reason: str | None

    @property
    def truncated(self) -> bool:
        return self.stop_reason in TRUNCATION_STOP_REASONS


class CompletionClient(Protocol):
    model: str

    def complete(
        self, system: str, user: str, *, max_tokens: int = DEFAULT_MAX_TOKENS
    ) -> CompletionResult:
        """Return the model's raw text plus usage and stop reason, unparsed."""
        ...


class EmbeddingClient(Protocol):
    model: str

    @property
    def dimension(self) -> int:
        """Width of the vectors this client produces."""
        ...

    def embed(self, texts: list[str]) -> list[Vector]:
        ...


# ---------- slot 1: completions ----------


class AnthropicClient:
    def __init__(self, *, model: str, api_key: str | None = None, base_url: str | None = None):
        import anthropic

        self.model = model
        options = {}
        if api_key:
            options["api_key"] = api_key
        if base_url:
            options["base_url"] = base_url
        self._client = anthropic.Anthropic(**options)

    def complete(
        self, system: str, user: str, *, max_tokens: int = DEFAULT_MAX_TOKENS
    ) -> CompletionResult:
        import anthropic

        try:
            response = self._client.messages.create(
                model=self.model,
                max_tokens=max_tokens,
                system=system,
                thinking={"type": "adaptive"},
                output_config={"effort": "medium"},
                messages=[{"role": "user", "content": user}],
            )
        except anthropic.APIError as exc:
            raise EnrichmentError(f"anthropic call failed: {exc}") from exc

        # Adaptive thinking puts thinking blocks in content; only text is the answer.
        text = "".join(block.text for block in response.content if block.type == "text")
        return CompletionResult(
            text=text,
            input_tokens=response.usage.input_tokens,
            output_tokens=response.usage.output_tokens,
            stop_reason=response.stop_reason,
        )

    def ping(self) -> str:
        """Cheap round-trip for `pronoia doctor` (§5.4).

        count_tokens, not a 1-token completion: same validation of key, model
        id and reachability, but free. A diagnostic that costs money is one
        people stop running.
        """
        import anthropic

        try:
            result = self._client.messages.count_tokens(
                model=self.model,
                messages=[{"role": "user", "content": "ping"}],
            )
        except anthropic.APIError as exc:
            raise EnrichmentError(f"anthropic call failed: {exc}") from exc
        return f"count_tokens ok ({result.input_tokens} tokens)"


class OpenAICompatibleClient:
    """Any endpoint speaking OpenAI's /v1/chat/completions."""

    def __init__(
        self,
        *,
        base_url: str,
        model: str,
        api_key: str | None = None,
        timeout: float = DEFAULT_TIMEOUT_SECONDS,
    ):
        self.model = model
        self._base_url = base_url.rstrip("/")
        self._headers = {"Authorization": f"Bearer {api_key}"} if api_key else {}
        self._timeout = timeout

    def complete(
        self, system: str, user: str, *, max_tokens: int = DEFAULT_MAX_TOKENS
    ) -> CompletionResult:
        # `max_tokens`, not `max_completion_tokens`: the spelling local
        # runtimes accept, and reaching those is why this adapter exists.
        payload = {
            "model": self.model,
            "max_tokens": max_tokens,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
        }
        body = self._post("/chat/completions", payload)

        try:
            choice = body["choices"][0]
            text = choice["message"]["content"] or ""
        except (KeyError, IndexError, TypeError) as exc:
            raise EnrichmentError(
                f"{self._base_url} returned an unexpected chat-completions shape: {exc}"
            ) from exc

        usage = body.get("usage") or {}
        return CompletionResult(
            text=text,
            input_tokens=usage.get("prompt_tokens"),
            output_tokens=usage.get("completion_tokens"),
            stop_reason=choice.get("finish_reason"),
        )

    def ping(self) -> str:
        models = self._get("/models").get("data") or []
        return f"/v1/models ok ({len(models)} model(s) advertised)"

    def _post(self, path: str, payload: dict) -> dict:
        try:
            response = httpx.post(
                f"{self._base_url}{path}",
                json=payload,
                headers=self._headers,
                timeout=self._timeout,
            )
            response.raise_for_status()
            return response.json()
        except httpx.HTTPError as exc:
            raise EnrichmentError(f"{self._base_url}{path} failed: {exc}") from exc
        except ValueError as exc:
            raise EnrichmentError(f"{self._base_url}{path} returned non-JSON: {exc}") from exc

    def _get(self, path: str) -> dict:
        try:
            response = httpx.get(
                f"{self._base_url}{path}", headers=self._headers, timeout=self._timeout
            )
            response.raise_for_status()
            return response.json()
        except httpx.HTTPError as exc:
            raise EnrichmentError(f"{self._base_url}{path} failed: {exc}") from exc
        except ValueError as exc:
            raise EnrichmentError(f"{self._base_url}{path} returned non-JSON: {exc}") from exc


# ---------- slot 2: embeddings ----------


class OpenAICompatibleEmbeddingClient:
    """Any endpoint speaking OpenAI's /v1/embeddings.

    That covers OpenAI itself, Ollama, vLLM, LM Studio and the rest -- and
    Anthropic not at all, which is the point of §5.3's second slot.
    """

    def __init__(
        self,
        *,
        base_url: str,
        model: str,
        api_key: str | None = None,
        request_dimension: int | None = None,
        timeout: float = DEFAULT_TIMEOUT_SECONDS,
    ):
        self.model = model
        self._base_url = base_url.rstrip("/")
        self._headers = {"Authorization": f"Bearer {api_key}"} if api_key else {}
        self._request_dimension = request_dimension
        self._timeout = timeout
        self._dimension: int | None = None

    @property
    def dimension(self) -> int:
        """Width of the vectors this endpoint actually returns.

        Measured once, not looked up by model name: the same name is served at
        different widths in practice, and a guessed embedding_dim would defeat
        the point of recording provenance.
        """
        if self._dimension is None:
            self._dimension = len(self.embed(["dimension probe"])[0])
        return self._dimension

    def embed(self, texts: list[str]) -> list[Vector]:
        payload: dict = {"model": self.model, "input": list(texts)}
        if self._request_dimension is not None:
            payload["dimensions"] = self._request_dimension

        try:
            response = httpx.post(
                f"{self._base_url}/embeddings",
                json=payload,
                headers=self._headers,
                timeout=self._timeout,
            )
            response.raise_for_status()
            body = response.json()
        except httpx.HTTPError as exc:
            raise EnrichmentError(f"{self._base_url}/embeddings failed: {exc}") from exc
        except ValueError as exc:
            raise EnrichmentError(f"{self._base_url}/embeddings returned non-JSON: {exc}") from exc

        try:
            # Providers may return out of order; a permuted batch would attach
            # every vector to the wrong report.
            items = sorted(body["data"], key=lambda item: item["index"])
            return [list(item["embedding"]) for item in items]
        except (KeyError, IndexError, TypeError) as exc:
            raise EnrichmentError(
                f"{self._base_url} returned an unexpected embeddings shape: {exc}"
            ) from exc

    def ping(self) -> str:
        return f"/v1/embeddings ok ({self.dimension} dimensions)"


# ---------- factories ----------


def build_completion_client(config: CompletionConfig) -> CompletionClient:
    if config.native_sdk:
        return AnthropicClient(model=config.model, api_key=config.api_key)
    return OpenAICompatibleClient(
        base_url=config.base_url, model=config.model, api_key=config.api_key
    )


def build_embedding_client(config: EmbeddingConfig) -> EmbeddingClient:
    return OpenAICompatibleEmbeddingClient(
        base_url=config.base_url,
        model=config.model,
        api_key=config.api_key,
        request_dimension=config.request_dimension,
    )


def get_completion_client() -> CompletionClient:
    return build_completion_client(resolve_completion())


def get_embedding_client(completion: CompletionConfig) -> EmbeddingClient | None:
    """None means "no embedding provider resolved", which is not an error (§5.4)."""
    config = resolve_embedding(completion)
    return None if config is None else build_embedding_client(config)
