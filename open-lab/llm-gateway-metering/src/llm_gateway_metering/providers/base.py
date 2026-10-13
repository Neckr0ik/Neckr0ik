from __future__ import annotations

from typing import Protocol

from ..types import ProviderRequest, ProviderResponse


class Provider(Protocol):
    name: str

    def complete(self, request: ProviderRequest, *, timeout_s: float) -> ProviderResponse:
        """Run one completion. Raise ``ProviderError`` / ``ProviderTimeout`` on failure."""
