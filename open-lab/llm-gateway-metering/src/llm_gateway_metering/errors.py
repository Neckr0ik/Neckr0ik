"""Exception hierarchy. Messages never include prompts, keys or raw provider bodies."""

from __future__ import annotations


class GatewayError(Exception):
    """Base class for every error the gateway raises on purpose."""

    code = "gateway_error"
    http_status = 500

    def to_dict(self) -> dict:
        return {"type": self.code, "message": str(self)}


class InvalidRequest(GatewayError):
    code = "invalid_request"
    http_status = 400


class AuthError(GatewayError):
    code = "unauthorized"
    http_status = 401


class RateLimited(GatewayError):
    code = "rate_limited"
    http_status = 429

    def __init__(self, scope: str, retry_after: float):
        super().__init__(f"rate limit exceeded for {scope}; retry after {retry_after:.2f}s")
        self.scope = scope
        self.retry_after = retry_after

    def to_dict(self) -> dict:
        return {**super().to_dict(), "scope": self.scope, "retry_after": round(self.retry_after, 3)}


class QuotaExceeded(GatewayError):
    """Raised *before* the provider is called when the estimate would cross the hard cap."""

    code = "quota_exceeded"
    http_status = 402

    def __init__(self, org_id: str, period: str, used: float, reserved: float, requested: float, limit: float):
        super().__init__(
            f"monthly quota for org {org_id!r} ({period}) would be exceeded: "
            f"used={used:g} reserved={reserved:g} requested={requested:g} limit={limit:g}"
        )
        self.org_id = org_id
        self.period = period
        self.used = used
        self.reserved = reserved
        self.requested = requested
        self.limit = limit

    def to_dict(self) -> dict:
        return {
            **super().to_dict(),
            "period": self.period,
            "used": self.used,
            "reserved": self.reserved,
            "requested": self.requested,
            "limit": self.limit,
        }


class ProviderError(GatewayError):
    """Normalised provider failure. ``retryable`` drives the retry loop."""

    code = "provider_error"
    http_status = 502

    def __init__(self, message: str, *, retryable: bool, status_code: int | None = None,
                 retry_after: float | None = None, error_type: str | None = None):
        super().__init__(message)
        self.retryable = retryable
        self.status_code = status_code
        self.retry_after = retry_after
        self.error_type = error_type or type(self).__name__


class ProviderTimeout(ProviderError):
    code = "provider_timeout"
    http_status = 504

    def __init__(self, message: str = "provider request timed out"):
        super().__init__(message, retryable=True, error_type="timeout")
