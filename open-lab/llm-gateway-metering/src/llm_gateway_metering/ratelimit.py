"""Thread-safe token-bucket rate limiting keyed per org and per (org, user).

In-process only: run one gateway process per org shard, or put a shared limiter
(e.g. Redis) behind the same ``RateLimiter`` interface for multi-process deployments.
"""

from __future__ import annotations

import threading
import time
from typing import Callable

from .config import BucketConfig
from .errors import RateLimited


class TokenBucket:
    def __init__(self, capacity: float, refill_per_s: float, clock: Callable[[], float] = time.monotonic):
        if capacity <= 0 or refill_per_s <= 0:
            raise ValueError("capacity and refill_per_s must be > 0")
        self.capacity = float(capacity)
        self.refill_per_s = float(refill_per_s)
        self._clock = clock
        self._tokens = float(capacity)
        self._last = clock()
        self._lock = threading.Lock()

    def _refill(self) -> None:
        now = self._clock()
        elapsed = max(0.0, now - self._last)
        self._last = now
        self._tokens = min(self.capacity, self._tokens + elapsed * self.refill_per_s)

    def try_acquire(self, n: float = 1.0) -> tuple[bool, float]:
        """Return ``(ok, retry_after_s)``. Never blocks."""
        with self._lock:
            self._refill()
            if self._tokens >= n:
                self._tokens -= n
                return True, 0.0
            return False, (n - self._tokens) / self.refill_per_s

    def refund(self, n: float = 1.0) -> None:
        with self._lock:
            self._tokens = min(self.capacity, self._tokens + n)


class RateLimiter:
    """Checks the org bucket and the user bucket; both must admit the request."""

    def __init__(self, org: BucketConfig | None, user: BucketConfig | None,
                 clock: Callable[[], float] = time.monotonic, max_keys: int = 100_000):
        self._org_cfg, self._user_cfg = org, user
        self._clock = clock
        self._buckets: dict[tuple, TokenBucket] = {}
        self._lock = threading.Lock()
        self._max_keys = max_keys

    def _bucket(self, key: tuple, cfg: BucketConfig) -> TokenBucket:
        with self._lock:
            b = self._buckets.get(key)
            if b is None:
                if len(self._buckets) >= self._max_keys:  # crude bound on memory
                    self._buckets.clear()
                b = self._buckets[key] = TokenBucket(cfg.capacity, cfg.refill_per_s, self._clock)
            return b

    def check(self, org_id: str, user_id: str) -> None:
        org_b = self._bucket(("org", org_id), self._org_cfg) if self._org_cfg else None
        if org_b is not None:
            ok, wait = org_b.try_acquire()
            if not ok:
                raise RateLimited("org", wait)
        if self._user_cfg:
            ok, wait = self._bucket(("user", org_id, user_id), self._user_cfg).try_acquire()
            if not ok:
                if org_b is not None:
                    org_b.refund()  # don't charge the org for a request we rejected
                raise RateLimited("user", wait)
