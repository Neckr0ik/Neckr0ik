"""Claude on Amazon Bedrock via the SDK's Mantle client (``pip install .[bedrock]``).

Credentials come from the standard AWS chain (env vars, profile, instance role).
Model ids get the ``anthropic.`` prefix, e.g. ``claude-sonnet-5-5`` -> ``anthropic.claude-sonnet-5-5``.
"""

from __future__ import annotations

from typing import Any

from ._claude_messages import ClaudeMessagesProvider


class BedrockProvider(ClaudeMessagesProvider):
    name = "bedrock"

    @classmethod
    def from_config(cls, config) -> "BedrockProvider":
        if not config.aws_region:
            raise ValueError("Bedrock needs a region: set AWS_REGION or LLMGW_AWS_REGION")
        from anthropic import AnthropicBedrockMantle

        return cls(AnthropicBedrockMantle(aws_region=config.aws_region, max_retries=0, timeout=config.timeout_s))

    def model_id(self, model: str) -> str:
        # Leave ARNs, inference-profile ids (us./eu./global.) and already-prefixed ids alone.
        if model.startswith(("anthropic.", "arn:")) or model.split(".", 1)[0] in {"us", "eu", "apac", "global"}:
            return model
        return f"anthropic.{model}"

    def _create(self, params: dict[str, Any], timeout_s: float) -> Any:
        return self.client.messages.create(**params, timeout=timeout_s)
