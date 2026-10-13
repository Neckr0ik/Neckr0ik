"""Deterministic offline provider for tests, demos and local development."""

from __future__ import annotations

import hashlib
import threading
import time
from typing import Iterable

from ..errors import ProviderTimeout
from ..estimate import estimate_input_tokens
from ..types import ProviderRequest, ProviderResponse


class MockProvider:
    """Same input always yields the same output and usage.

    * ``input_tokens`` uses the gateway's own estimator, so pre-flight estimates match.
    * ``output_tokens`` is ``min(max_tokens, output_tokens)``.
    * ``failures``: exceptions raised by the first N calls, in order (for retry tests).
    * ``delay_s``: simulated latency; exceeding ``timeout_s`` raises ``ProviderTimeout``.
    """

    name = "mock"

    def __init__(self, *, output_tokens: int = 16, delay_s: float = 0.0,
                 failures: Iterable[BaseException] = (), stop_reason: str = "end_turn"):
        self.output_tokens = output_tokens
        self.delay_s = delay_s
        self.stop_reason = stop_reason
        self._failures = list(failures)
        self._lock = threading.Lock()
        self.calls: list[ProviderRequest] = []

    @property
    def call_count(self) -> int:
        return len(self.calls)

    def complete(self, request: ProviderRequest, *, timeout_s: float) -> ProviderResponse:
        with self._lock:
            self.calls.append(request)
            failure = self._failures.pop(0) if self._failures else None
        if failure is not None:
            raise failure
        if self.delay_s:
            if self.delay_s > timeout_s:
                time.sleep(timeout_s)
                raise ProviderTimeout()
            time.sleep(self.delay_s)
        digest = hashlib.sha256(repr((request.model, request.system, request.messages)).encode()).hexdigest()[:12]
        out = min(request.max_tokens, self.output_tokens)
        return ProviderResponse(
            text=f"[mock {request.model} #{digest}] deterministic reply ({out} tokens)",
            model=request.model,
            input_tokens=estimate_input_tokens(request.messages, request.system),
            output_tokens=out,
            stop_reason=self.stop_reason,
            request_id=f"mock-{digest}",
        )
