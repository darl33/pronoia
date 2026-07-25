"""Provider abstraction (DESIGN.md §5.3): a ~50-line `EnrichmentClient`
protocol with `complete(system, user) -> str`, implemented for Anthropic and
selected via env var. No framework.

Deliberately thin. `complete` returns the model's raw text and nothing else --
the client does not parse, validate, or retry. Structured-output enforcement is
guardrail 1's job (enrich/extract.py), and keeping it out of here is what makes
the guardrail portable across providers instead of dependent on one provider's
JSON mode.
"""

from __future__ import annotations

import os
from typing import Protocol

DEFAULT_ANTHROPIC_MODEL = "claude-opus-4-8"
DEFAULT_MAX_TOKENS = 16000


class EnrichmentError(Exception):
    """Provider call failed. Recorded as `api_error` on the enrichment_run."""


class EnrichmentClient(Protocol):
    model: str

    def complete(self, system: str, user: str) -> str:
        """Return the model's raw text response, unparsed."""
        ...


class AnthropicClient:
    def __init__(self, model: str | None = None, max_tokens: int = DEFAULT_MAX_TOKENS):
        import anthropic

        self.model = model or os.environ.get("ENRICHMENT_MODEL", DEFAULT_ANTHROPIC_MODEL)
        self._max_tokens = max_tokens
        self._client = anthropic.Anthropic()

    def complete(self, system: str, user: str) -> str:
        import anthropic

        try:
            response = self._client.messages.create(
                model=self.model,
                max_tokens=self._max_tokens,
                system=system,
                thinking={"type": "adaptive"},
                output_config={"effort": "medium"},
                messages=[{"role": "user", "content": user}],
            )
        except anthropic.APIError as exc:
            raise EnrichmentError(f"anthropic call failed: {exc}") from exc

        # Adaptive thinking puts thinking blocks in content alongside the text;
        # only the text blocks are the answer.
        return "".join(block.text for block in response.content if block.type == "text")


def get_client() -> EnrichmentClient:
    provider = os.environ.get("LLM_PROVIDER", "anthropic").strip().lower()
    if provider == "anthropic":
        return AnthropicClient()
    raise EnrichmentError(
        f"unsupported LLM_PROVIDER {provider!r}; expected one of: anthropic"
    )
