"""Anthropic (Claude) adapter for the memorization probe.

Used only if the ``anthropic`` package is installed and ``ANTHROPIC_API_KEY``
is set; nothing in this package imports it implicitly. Install with
``pip install "silicon-sample-validation[anthropic]"``.

Notes for the default model, Claude Haiku 5.5 (``claude-haiku-5-5``): sampling
parameters such as ``temperature`` must be left at their defaults (non-default
values are rejected), thinking is adaptive and on by default, and depth is
controlled with ``output_config.effort`` (default ``medium``; ``low`` is enough
for a one-number recall question). Thinking tokens count toward
``max_tokens``, so keep some headroom.
"""

from __future__ import annotations

import importlib.util
import os
from typing import Any

DEFAULT_MODEL = "claude-haiku-5-5"
REFUSAL_TEXT = ""  # parsed as "declined" by the probe


def anthropic_available() -> bool:
    """True when the SDK is importable and an API key is configured."""
    return importlib.util.find_spec("anthropic") is not None and bool(os.environ.get("ANTHROPIC_API_KEY"))


class AnthropicLLM:
    """Callable ``prompt -> text`` backed by the Claude Messages API.

    >>> llm = AnthropicLLM()                     # doctest: +SKIP
    >>> run_memorization_probe(llm, targets)     # doctest: +SKIP
    """

    def __init__(
        self,
        model: str = DEFAULT_MODEL,
        max_tokens: int = 2048,
        effort: str | None = "low",
        system: str | None = None,
        client: Any = None,
    ):
        if client is None:
            if not anthropic_available():
                raise RuntimeError(
                    "AnthropicLLM needs `pip install anthropic` and ANTHROPIC_API_KEY set; "
                    "use MockLLM for offline runs"
                )
            import anthropic

            client = anthropic.Anthropic()
        self.client = client
        self.model = model
        self.max_tokens = max_tokens
        self.effort = effort
        self.system = system
        self.last_response: Any = None

    def __call__(self, prompt: str) -> str:
        kwargs: dict[str, Any] = {
            "model": self.model,
            "max_tokens": self.max_tokens,
            "messages": [{"role": "user", "content": prompt}],
        }
        if self.system:
            kwargs["system"] = self.system
        if self.effort:
            kwargs["output_config"] = {"effort": self.effort}
        response = self.client.messages.create(**kwargs)
        self.last_response = response
        if getattr(response, "stop_reason", None) == "refusal":
            return REFUSAL_TEXT
        return "".join(
            block.text for block in response.content if getattr(block, "type", None) == "text"
        ).strip()
