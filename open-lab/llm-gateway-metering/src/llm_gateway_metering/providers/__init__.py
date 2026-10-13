"""Provider adapters behind one interface. Real SDKs are imported lazily."""

from .base import Provider
from .mock import MockProvider

__all__ = ["MockProvider", "Provider", "build_provider"]


def build_provider(config) -> Provider:
    """Construct the provider named by ``config.provider`` (mock | anthropic | bedrock | vertex)."""
    name = config.provider
    if name == "mock":
        return MockProvider()
    if name == "anthropic":
        from .anthropic_api import AnthropicProvider

        return AnthropicProvider.from_config(config)
    if name == "bedrock":
        from .bedrock import BedrockProvider

        return BedrockProvider.from_config(config)
    if name == "vertex":
        from .vertex import VertexProvider

        return VertexProvider.from_config(config)
    raise ValueError(f"unknown provider {name!r}")
