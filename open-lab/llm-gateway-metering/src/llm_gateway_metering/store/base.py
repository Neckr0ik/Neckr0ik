"""Store interface. Implementations must make ``reserve`` atomic per (org, period)."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Protocol


@dataclass(frozen=True)
class Reservation:
    id: str
    org_id: str
    period: str
    units: float
    used_before: float
    reserved_before: float


@dataclass(frozen=True)
class UsageRecord:
    id: str
    org_id: str
    user_id: str
    feature: str
    provider: str
    model: str
    period: str
    input_tokens: int
    output_tokens: int
    cost_units: float
    latency_ms: int
    status: str  # ok | refused | error | timeout
    created_at: float
    cache_creation_input_tokens: int = 0
    cache_read_input_tokens: int = 0
    stop_reason: str | None = None
    error_type: str | None = None
    attempts: int = 1

    def as_row(self) -> dict:
        return asdict(self)


COLUMNS = tuple(UsageRecord.__dataclass_fields__)


class MeteringStore(Protocol):
    def reserve(self, org_id: str, period: str, units: float, limit: float, *, now: float, ttl_s: float) -> Reservation:
        """Atomically check ``used + reserved + units <= limit`` and hold ``units``.

        Raises ``QuotaExceeded`` without holding anything when the check fails.
        """

    def settle(self, reservation_id: str, record: UsageRecord) -> float:
        """Drop the reservation and persist the actual usage. Returns the period's new ``used`` total."""

    def release(self, reservation_id: str, record: UsageRecord | None = None) -> None:
        """Drop the reservation (failed call). Optionally persist a zero-cost record of the failure."""

    def totals(self, org_id: str, period: str, *, now: float) -> tuple[float, float]:
        """Return ``(used, reserved)`` for the period, ignoring expired reservations."""

    def report(self, org_id: str, period: str) -> dict:
        """Aggregates for the period: totals, by_user, by_feature, by_model."""

    def mark_warning(self, org_id: str, period: str, *, now: float) -> bool:
        """Record that the soft-warning fired. True only the first time per (org, period)."""

    def close(self) -> None: ...
