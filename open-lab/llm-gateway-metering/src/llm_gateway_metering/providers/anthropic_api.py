"""Claude via the first-party Anthropic API (``pip install .[anthropic]``).

Credentials: the SDK resolves ``ANTHROPIC_API_KEY`` (or other SDK-supported sources)
from the environment. The gateway never accepts or stores the key itself.
"""

from __future__ import annotations

from typing import Any

from ._claude_messages import ClaudeMessagesProvider

FALLBACK_BETA = "server-side-fallback-2026-07-01"


class AnthropicProvider(ClaudeMessagesProvider):
    name = "anthropic"

    def __init__(self, client: Any, *, server_fallbacks: bool = True):
        super().__init__(client)
        self.server_fallbacks = server_fallbacks

    @classmethod
    def from_config(cls, config) -> "AnthropicProvider":
        import anthropic

        client = anthropic.Anthropic(max_retries=0, timeout=config.timeout_s)
        return cls(client, server_fallbacks=config.anthropic_server_fallbacks)

    def _create(self, params: dict[str, Any], timeout_s: float) -> Any:
        if self.server_fallbacks:
            # On a safety-classifier refusal the API re-runs the request on Anthropic's
            # recommended fallback model inside the same call (beta).
            return self.client.beta.messages.create(**params, betas=[FALLBACK_BETA], fallbacks="default",
                                                    timeout=timeout_s)
        return self.client.messages.create(**params, timeout=timeout_s)
