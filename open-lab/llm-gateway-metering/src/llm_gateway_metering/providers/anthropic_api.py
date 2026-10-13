"""Claude via the first-party Anthropic API (``pip install .[anthropic]``).

Credentials: the SDK resolves ``ANTHROPIC_API_KEY`` (or other SDK-supported sources)
from the environment. The gateway never accepts or stores the key itself.
"""

from __future__ import annotations

from typing import Any, Iterable

from ..config import DEFAULT_FALLBACK_MODELS
from ._claude_messages import ClaudeMessagesProvider

FALLBACK_BETA = "server-side-fallback-2026-07-01"


class AnthropicProvider(ClaudeMessagesProvider):
    name = "anthropic"

    def __init__(self, client: Any, *, server_fallbacks: bool = True,
                 fallback_models: Iterable[str] = DEFAULT_FALLBACK_MODELS, fallback_hops: int = 1):
        super().__init__(client)
        self.server_fallbacks = server_fallbacks
        self.fallback_models = frozenset(fallback_models)
        self.hops = fallback_hops

    def uses_fallback(self, model: str) -> bool:
        """True when requests for ``model`` opt into server-side fallback."""
        return self.server_fallbacks and model in self.fallback_models

    def fallback_hops(self, model: str) -> int:
        """Extra attempts the API may run inside one call (the gateway reserves for them)."""
        return self.hops if self.uses_fallback(model) else 0

    @classmethod
    def from_config(cls, config) -> "AnthropicProvider":
        import anthropic

        client = anthropic.Anthropic(max_retries=0, timeout=config.timeout_s)
        return cls(client, server_fallbacks=config.anthropic_server_fallbacks,
                   fallback_models=config.anthropic_fallback_models, fallback_hops=config.anthropic_fallback_hops)

    def _create(self, params: dict[str, Any], timeout_s: float) -> Any:
        if self.uses_fallback(params["model"]):
            # On a safety-classifier refusal the API re-runs the request on Anthropic's
            # recommended fallback model inside the same call (beta).
            return self.client.beta.messages.create(**params, betas=[FALLBACK_BETA], fallbacks="default",
                                                    timeout=timeout_s)
        return self.client.messages.create(**params, timeout=timeout_s)
