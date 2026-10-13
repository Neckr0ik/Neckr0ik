"""The gateway: validation -> rate limit -> quota reservation -> provider (with retries)
-> settle actual usage -> soft warning -> structured log."""

from __future__ import annotations

import logging
import re
import time
import uuid
from dataclasses import dataclass
from typing import Any, Callable

from .config import GatewayConfig
from .errors import GatewayError, InvalidRequest, ProviderError, ProviderTimeout, QuotaExceeded, RateLimited
from .estimate import estimate_input_tokens
from .logging_utils import log_event, pseudonymize
from .periods import period_for, validate_period
from .providers import Provider, build_provider
from .ratelimit import RateLimiter
from .retry import RetryPolicy, call_with_retries
from .store import MeteringStore, UsageRecord, open_store
from .types import CompletionRequest, ProviderRequest, ProviderResponse

_ID_RE = re.compile(r"^[A-Za-z0-9_.@:\-]{1,128}$")
_ROLES = {"user", "assistant"}


@dataclass(frozen=True)
class QuotaStatus:
    period: str
    used: float
    limit: float
    warn_ratio: float

    @property
    def remaining(self) -> float:
        return max(0.0, self.limit - self.used)

    @property
    def warning(self) -> bool:
        return self.limit > 0 and self.used >= self.warn_ratio * self.limit

    def to_dict(self) -> dict:
        return {"period": self.period, "used": self.used, "limit": self.limit,
                "remaining": self.remaining, "warn_ratio": self.warn_ratio, "warning": self.warning}


@dataclass(frozen=True)
class GatewayResponse:
    id: str
    text: str
    provider: str
    model: str
    stop_reason: str | None
    input_tokens: int
    output_tokens: int
    cost_units: float
    latency_ms: int
    attempts: int
    quota: QuotaStatus
    cache_creation_input_tokens: int = 0
    cache_read_input_tokens: int = 0

    def to_dict(self) -> dict:
        return {
            "id": self.id, "text": self.text, "provider": self.provider, "model": self.model,
            "stop_reason": self.stop_reason,
            "usage": {"input_tokens": self.input_tokens, "output_tokens": self.output_tokens,
                      "cache_creation_input_tokens": self.cache_creation_input_tokens,
                      "cache_read_input_tokens": self.cache_read_input_tokens,
                      "cost_units": self.cost_units},
            "latency_ms": self.latency_ms, "attempts": self.attempts, "quota": self.quota.to_dict(),
        }


class Gateway:
    def __init__(self, config: GatewayConfig, *, provider: Provider | None = None,
                 store: MeteringStore | None = None, clock: Callable[[], float] = time.time,
                 monotonic: Callable[[], float] = time.monotonic, sleep: Callable[[float], None] = time.sleep,
                 on_warning: Callable[[str, QuotaStatus], None] | None = None):
        self.config = config
        self.provider = provider or build_provider(config)
        self.store = store or open_store(config.db_path)
        self.clock = clock
        self._mono = monotonic
        self._sleep = sleep
        self.on_warning = on_warning
        self.limiter = RateLimiter(config.org_rate, config.user_rate, clock=monotonic)
        self.retry_policy = RetryPolicy(config.max_attempts, config.backoff_base_s, config.backoff_max_s)

    # -- helpers -----------------------------------------------------------
    def _uid(self, user_id: str) -> str:
        return pseudonymize(user_id, self.config.log_salt) if self.config.log_hash_user_ids else user_id

    def _fallback_hops(self, model: str) -> int:
        hops = getattr(self.provider, "fallback_hops", None)
        return int(hops(model)) if callable(hops) else 0

    def _reservation_units(self, model: str, est_in: int, max_tokens: int) -> float:
        """Worst case for one call: the requested model's attempt, plus one attempt per
        possible server-side fallback hop at the most expensive configured rate (the API
        picks the fallback model, and every hop re-reads the input)."""
        units = self.config.rate_for(model).cost(est_in, max_tokens)
        hops = self._fallback_hops(model)
        if hops:
            units += hops * self.config.max_rate().cost(est_in, max_tokens)
        return units

    def _cost(self, model: str, presp: ProviderResponse) -> float:
        """Charge every attempt the provider ran at that attempt's own model rate."""
        if presp.iterations:
            return sum(self.config.rate_for(it.model or model).cost(
                it.input_tokens, it.output_tokens, it.cache_creation_input_tokens, it.cache_read_input_tokens)
                for it in presp.iterations)
        return self.config.rate_for(model).cost(presp.input_tokens, presp.output_tokens,
                                                presp.cache_creation_input_tokens, presp.cache_read_input_tokens)

    def _settle(self, reservation, record: UsageRecord, base_log: dict) -> float:
        """Persist actual usage. One retry; if that fails too, release the reservation while
        still trying to write the record, and log ``metering_write_failed`` either way."""
        last: Exception | None = None
        for _ in range(2):
            try:
                return self.store.settle(reservation.id, record)
            except Exception as exc:  # store / driver errors
                last = exc
        recorded = True
        try:
            self.store.release(reservation.id, record)
        except Exception:
            recorded = False
        log_event("metering_write_failed", logging.ERROR, **base_log, period=record.period,
                  cost_units=record.cost_units, recorded_on_release=recorded,
                  error_type=type(last).__name__ if last else None)
        # Best local view of the pool: what was used before this request plus its cost.
        return reservation.used_before + record.cost_units

    @staticmethod
    def _validate(req: CompletionRequest) -> None:
        for label, value in (("org_id", req.org_id), ("user_id", req.user_id), ("feature", req.feature)):
            if not isinstance(value, str) or not _ID_RE.match(value):
                raise InvalidRequest(f"{label} must match {_ID_RE.pattern}")
        if not isinstance(req.messages, list) or not req.messages:
            raise InvalidRequest("messages must be a non-empty list")
        for m in req.messages:
            if not isinstance(m, dict) or m.get("role") not in _ROLES or "content" not in m:
                raise InvalidRequest("each message needs role 'user'|'assistant' and content")
        if req.messages[0]["role"] != "user":
            raise InvalidRequest("the first message must have role 'user'")
        if req.max_tokens is not None and (not isinstance(req.max_tokens, int) or req.max_tokens < 1):
            raise InvalidRequest("max_tokens must be a positive integer")
        if req.system is not None and not isinstance(req.system, str):
            raise InvalidRequest("system must be a string")

    def quota_status(self, org_id: str, period: str | None = None) -> QuotaStatus:
        org = self.config.org(org_id)
        period = period or period_for(self.clock())
        used, _ = self.store.totals(org_id, period, now=self.clock())
        return QuotaStatus(period, used, org.monthly_limit, org.warn_ratio)

    # -- main entry point --------------------------------------------------
    def complete(self, req: CompletionRequest) -> GatewayResponse:
        self._validate(req)
        org = self.config.org(req.org_id)
        feature = self.config.feature(req.feature)
        model = self.config.model_for(feature)
        max_tokens = min(req.max_tokens or feature.max_tokens, feature.max_tokens)
        rid = uuid.uuid4().hex
        base_log = {"request_id": rid, "org_id": req.org_id, "user": self._uid(req.user_id),
                    "feature": req.feature, "provider": self.provider.name, "model": model}

        try:
            self.limiter.check(req.org_id, req.user_id)
        except RateLimited as exc:
            log_event("request_rejected", logging.WARNING, **base_log, reason="rate_limited", scope=exc.scope)
            raise

        now = self.clock()
        period = period_for(now)
        est_in = estimate_input_tokens(req.messages, req.system)
        est_units = self._reservation_units(model, est_in, max_tokens)
        try:
            reservation = self.store.reserve(req.org_id, period, est_units, org.monthly_limit,
                                             now=now, ttl_s=self.config.reservation_ttl_s)
        except QuotaExceeded as exc:
            log_event("request_rejected", logging.WARNING, **base_log, reason="quota_exceeded", period=period,
                      used=exc.used, reserved=exc.reserved, requested=exc.requested, limit=exc.limit)
            raise

        preq = ProviderRequest(model=model, messages=req.messages, max_tokens=max_tokens,
                               system=req.system, effort=feature.effort)
        t0 = self._mono()

        def on_retry(attempt: int, exc: ProviderError, delay: float) -> None:
            log_event("provider_retry", logging.WARNING, **base_log, attempt=attempt, delay_s=round(delay, 3),
                      status_code=exc.status_code, error_type=exc.error_type)

        try:
            presp, attempts = call_with_retries(
                lambda: self.provider.complete(preq, timeout_s=self.config.timeout_s),
                self.retry_policy, sleep=self._sleep, on_retry=on_retry)
        except BaseException as exc:
            latency = int((self._mono() - t0) * 1000)
            status = "timeout" if isinstance(exc, ProviderTimeout) else "error"
            attempts = getattr(exc, "attempts", 1)
            err_type = getattr(exc, "error_type", type(exc).__name__)
            self.store.release(reservation.id, UsageRecord(
                id=rid, org_id=req.org_id, user_id=req.user_id, feature=req.feature, provider=self.provider.name,
                model=model, period=period, input_tokens=0, output_tokens=0, cost_units=0.0, latency_ms=latency,
                status=status, created_at=now, error_type=err_type, attempts=attempts))
            log_event("request_failed", logging.ERROR, **base_log, status=status, latency_ms=latency,
                      attempts=attempts, error_type=err_type, status_code=getattr(exc, "status_code", None))
            if isinstance(exc, GatewayError) or not isinstance(exc, Exception):
                raise
            raise ProviderError("unexpected provider failure", retryable=False, error_type=err_type) from None

        latency = int((self._mono() - t0) * 1000)
        cost = self._cost(model, presp)
        served_model = presp.model or model
        status = "refused" if presp.stop_reason == "refusal" else "ok"
        used = self._settle(reservation, UsageRecord(
            id=rid, org_id=req.org_id, user_id=req.user_id, feature=req.feature, provider=self.provider.name,
            model=served_model, period=period, input_tokens=presp.input_tokens, output_tokens=presp.output_tokens,
            cost_units=cost, latency_ms=latency, status=status, created_at=now,
            cache_creation_input_tokens=presp.cache_creation_input_tokens,
            cache_read_input_tokens=presp.cache_read_input_tokens, stop_reason=presp.stop_reason,
            attempts=attempts), base_log)
        quota = QuotaStatus(period, used, org.monthly_limit, org.warn_ratio)
        log_event("request_completed", **{**base_log, "model": served_model}, status=status, latency_ms=latency,
                  attempts=attempts, input_tokens=presp.input_tokens, output_tokens=presp.output_tokens,
                  cache_creation_input_tokens=presp.cache_creation_input_tokens,
                  cache_read_input_tokens=presp.cache_read_input_tokens, cost_units=cost, stop_reason=presp.stop_reason, fallback=presp.served_by_fallback,
                  provider_request_id=presp.request_id, period=period, quota_used=used)
        if quota.warning and self.store.mark_warning(req.org_id, period, now=now):
            log_event("quota_warning", logging.WARNING, org_id=req.org_id, period=period, used=used,
                      limit=org.monthly_limit, warn_ratio=org.warn_ratio)
            if self.on_warning:
                self.on_warning(req.org_id, quota)
        return GatewayResponse(id=rid, text=presp.text, provider=self.provider.name, model=served_model,
                               stop_reason=presp.stop_reason, input_tokens=presp.input_tokens,
                               output_tokens=presp.output_tokens, cost_units=cost, latency_ms=latency,
                               attempts=attempts, quota=quota,
                               cache_creation_input_tokens=presp.cache_creation_input_tokens,
                               cache_read_input_tokens=presp.cache_read_input_tokens)

    # -- reporting ---------------------------------------------------------
    def usage_report(self, org_id: str, period: str | None = None) -> dict[str, Any]:
        period = validate_period(period) if period else period_for(self.clock())
        org = self.config.org(org_id)
        report = self.store.report(org_id, period)
        status = QuotaStatus(period, report["used"], org.monthly_limit, org.warn_ratio)
        report.update(limit=org.monthly_limit, remaining=status.remaining, warn_ratio=org.warn_ratio,
                      warning=status.warning)
        return report

    def close(self) -> None:
        self.store.close()
