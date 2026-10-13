"""Retry with exponential backoff and full jitter for retryable provider errors."""

from __future__ import annotations

import random
import time
from dataclasses import dataclass
from typing import Callable, TypeVar

from .errors import ProviderError

T = TypeVar("T")


@dataclass(frozen=True)
class RetryPolicy:
    max_attempts: int = 3
    base_s: float = 0.5
    max_s: float = 8.0
    jitter: bool = True

    def delay(self, attempt: int, retry_after: float | None, rng: random.Random) -> float:
        """Delay before attempt ``attempt + 1`` (``attempt`` is 1-based)."""
        ceiling = min(self.max_s, self.base_s * (2 ** (attempt - 1)))
        d = rng.uniform(0, ceiling) if self.jitter else ceiling
        if retry_after is not None:
            d = max(d, min(retry_after, self.max_s))
        return d


def call_with_retries(fn: Callable[[], T], policy: RetryPolicy, *,
                      sleep: Callable[[float], None] = time.sleep,
                      on_retry: Callable[[int, ProviderError, float], None] | None = None,
                      rng: random.Random | None = None) -> tuple[T, int]:
    """Run ``fn``; retry only ``ProviderError`` with ``retryable=True``. Returns ``(result, attempts)``."""
    rng = rng or random.Random()
    attempt = 0
    while True:
        attempt += 1
        try:
            return fn(), attempt
        except ProviderError as exc:
            if not exc.retryable or attempt >= policy.max_attempts:
                exc.attempts = attempt  # type: ignore[attr-defined]
                raise
            d = policy.delay(attempt, exc.retry_after, rng)
            if on_retry:
                on_retry(attempt, exc, d)
            sleep(d)
