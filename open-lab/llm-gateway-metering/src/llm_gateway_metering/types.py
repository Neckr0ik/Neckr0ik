"""Plain data types shared by the gateway and the provider adapters."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class CompletionRequest:
    """What a caller asks for. ``org_id`` comes from authentication, never from the body."""

    org_id: str
    user_id: str
    feature: str
    messages: list[dict[str, Any]]
    system: str | None = None
    max_tokens: int | None = None
    metadata: dict[str, str] = field(default_factory=dict)


@dataclass(frozen=True)
class ProviderRequest:
    """What an adapter receives: already resolved model, limits and timeout."""

    model: str
    messages: list[dict[str, Any]]
    max_tokens: int
    system: str | None = None
    effort: str | None = None


@dataclass(frozen=True)
class ProviderResponse:
    text: str
    model: str
    input_tokens: int
    output_tokens: int
    stop_reason: str | None = None
    cache_creation_input_tokens: int = 0
    cache_read_input_tokens: int = 0
    request_id: str | None = None
    served_by_fallback: bool = False
