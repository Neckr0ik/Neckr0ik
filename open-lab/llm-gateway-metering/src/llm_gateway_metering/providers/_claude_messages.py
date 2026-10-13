"""Shared request shaping, usage extraction and error mapping for Claude via the
Anthropic Python SDK (first-party API, Amazon Bedrock Mantle, Google Vertex AI).

The SDK's own retries are disabled (``max_retries=0``) so the gateway's retry policy is
the single source of truth and every attempt is visible in metering and logs.
"""

from __future__ import annotations

from typing import Any

from ..errors import ProviderError, ProviderTimeout
from ..types import ProviderRequest, ProviderResponse, UsageIteration

RETRYABLE_STATUS = {408, 409, 429, 500, 502, 503, 504, 529}


def build_params(req: ProviderRequest, model_id: str) -> dict[str, Any]:
    params: dict[str, Any] = {
        "model": model_id,
        "max_tokens": req.max_tokens,
        "messages": req.messages,
    }
    if req.system:
        params["system"] = req.system
    if req.effort:
        params["output_config"] = {"effort": req.effort}
    # No temperature/top_p/top_k and no explicit thinking config: current Claude models
    # reject non-default sampling params and run adaptive thinking by default.
    return params


def _get(obj: Any, name: str, default: Any = None) -> Any:
    if isinstance(obj, dict):
        return obj.get(name, default)
    return getattr(obj, name, default)


def parse_response(resp: Any) -> ProviderResponse:
    texts = [_get(b, "text", "") for b in (_get(resp, "content") or []) if _get(b, "type") == "text"]
    usage = _get(resp, "usage")
    in_tok = int(_get(usage, "input_tokens", 0) or 0)
    out_tok = int(_get(usage, "output_tokens", 0) or 0)
    cache_w = int(_get(usage, "cache_creation_input_tokens", 0) or 0)
    cache_r = int(_get(usage, "cache_read_input_tokens", 0) or 0)
    raw_iterations = _get(usage, "iterations") or []
    iterations = tuple(
        UsageIteration(type=str(_get(i, "type", "message")), model=_get(i, "model") or None,
                       input_tokens=int(_get(i, "input_tokens", 0) or 0),
                       output_tokens=int(_get(i, "output_tokens", 0) or 0),
                       cache_creation_input_tokens=int(_get(i, "cache_creation_input_tokens", 0) or 0),
                       cache_read_input_tokens=int(_get(i, "cache_read_input_tokens", 0) or 0))
        for i in raw_iterations)
    fallback = False
    if iterations:
        # With server-side fallbacks, top-level usage covers only the attempt that produced
        # the message; usage.iterations is the per-attempt source of truth. Meter all attempts
        # (the gateway charges each one at its own model's rate).
        in_tok = sum(i.input_tokens for i in iterations)
        out_tok = sum(i.output_tokens for i in iterations)
        cache_w = sum(i.cache_creation_input_tokens for i in iterations)
        cache_r = sum(i.cache_read_input_tokens for i in iterations)
        fallback = any(i.type == "fallback_message" for i in iterations)
    return ProviderResponse(
        text="".join(texts),
        model=str(_get(resp, "model", "")),
        input_tokens=in_tok,
        output_tokens=out_tok,
        stop_reason=_get(resp, "stop_reason"),
        cache_creation_input_tokens=cache_w,
        cache_read_input_tokens=cache_r,
        request_id=_get(resp, "_request_id") or _get(resp, "id"),
        served_by_fallback=fallback,
        iterations=iterations,
    )


def map_error(exc: BaseException) -> ProviderError:
    """Translate an ``anthropic`` SDK exception into the gateway's normalised error."""
    import anthropic

    if isinstance(exc, anthropic.APITimeoutError):
        return ProviderTimeout()
    if isinstance(exc, anthropic.APIConnectionError):
        return ProviderError("provider connection error", retryable=True, error_type="connection")
    if isinstance(exc, anthropic.APIStatusError):
        status = int(exc.status_code)
        retry_after = None
        try:
            ra = exc.response.headers.get("retry-after")
            retry_after = float(ra) if ra is not None else None
        except (TypeError, ValueError, AttributeError):
            retry_after = None
        # Message deliberately generic: provider bodies may echo request content.
        return ProviderError(f"provider returned HTTP {status}", retryable=status in RETRYABLE_STATUS,
                             status_code=status, retry_after=retry_after, error_type=type(exc).__name__)
    return ProviderError("unexpected provider error", retryable=False, error_type=type(exc).__name__)


class ClaudeMessagesProvider:
    """Base adapter; subclasses set ``name`` and implement ``model_id`` / ``_create``."""

    name = "claude"

    def __init__(self, client: Any):
        self.client = client

    def model_id(self, model: str) -> str:
        return model

    def _create(self, params: dict[str, Any], timeout_s: float) -> Any:
        return self.client.messages.create(**params, timeout=timeout_s)

    def complete(self, request: ProviderRequest, *, timeout_s: float) -> ProviderResponse:
        params = build_params(request, self.model_id(request.model))
        try:
            resp = self._create(params, timeout_s)
        except ProviderError:
            raise
        except Exception as exc:  # SDK errors -> normalised
            if type(exc).__module__.startswith("anthropic"):
                raise map_error(exc) from None
            raise
        return parse_response(resp)
