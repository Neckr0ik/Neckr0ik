import random

import pytest

from helpers import req
from llm_gateway_metering import ProviderError, ProviderTimeout
from llm_gateway_metering.providers import MockProvider
from llm_gateway_metering.retry import RetryPolicy, call_with_retries


def retryable(status=503, retry_after=None):
    return ProviderError(f"HTTP {status}", retryable=True, status_code=status, retry_after=retry_after)


def test_retries_then_succeeds_and_records_attempts(make_gateway, log_capture):
    provider = MockProvider(failures=[retryable(529), retryable(429)])
    gw = make_gateway(provider=provider, max_attempts=3)
    r = gw.complete(req())
    assert r.attempts == 3 and provider.call_count == 3
    rep = gw.usage_report("acme")
    assert rep["requests"] == 1 and rep["by_user"][0]["ok"] == 1
    assert log_capture.getvalue().count('"event":"provider_retry"') == 2


def test_non_retryable_is_not_retried(make_gateway):
    provider = MockProvider(failures=[ProviderError("HTTP 400", retryable=False, status_code=400)])
    gw = make_gateway(provider=provider, max_attempts=5)
    with pytest.raises(ProviderError):
        gw.complete(req())
    assert provider.call_count == 1


def test_gives_up_after_max_attempts(make_gateway):
    provider = MockProvider(failures=[retryable() for _ in range(5)])
    gw = make_gateway(provider=provider, max_attempts=3)
    with pytest.raises(ProviderError) as ei:
        gw.complete(req())
    assert provider.call_count == 3 and ei.value.attempts == 3
    assert gw.usage_report("acme")["by_user"][0]["ok"] == 0


def test_timeout_is_retried_and_reported(make_gateway):
    provider = MockProvider(failures=[ProviderTimeout(), ProviderTimeout()])
    gw = make_gateway(provider=provider, max_attempts=2)
    with pytest.raises(ProviderTimeout):
        gw.complete(req())
    rows = gw.store._conn.execute("SELECT status, attempts FROM requests").fetchall()
    assert [tuple(r) for r in rows] == [("timeout", 2)]


def test_mock_delay_beyond_timeout_raises_timeout(make_gateway):
    gw = make_gateway(provider=MockProvider(delay_s=0.5), timeout_s=0.05, max_attempts=1)
    with pytest.raises(ProviderTimeout):
        gw.complete(req())


def test_backoff_is_exponential_capped_and_honours_retry_after():
    sleeps = []
    calls = iter([retryable(), retryable(), retryable(retry_after=3.0), retryable(), "ok"])

    def fn():
        v = next(calls)
        if isinstance(v, Exception):
            raise v
        return v

    policy = RetryPolicy(max_attempts=5, base_s=0.5, max_s=2.0, jitter=False)
    result, attempts = call_with_retries(fn, policy, sleep=sleeps.append, rng=random.Random(0))
    assert result == "ok" and attempts == 5
    assert sleeps == [0.5, 1.0, 2.0, 2.0]  # retry_after=3 clamped to max_s=2


def test_jitter_stays_within_ceiling():
    policy = RetryPolicy(base_s=1.0, max_s=4.0, jitter=True)
    rng = random.Random(42)
    for attempt in range(1, 8):
        d = policy.delay(attempt, None, rng)
        assert 0 <= d <= min(4.0, 2 ** (attempt - 1))
