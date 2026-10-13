import pytest

from helpers import req
from llm_gateway_metering import RateLimited
from llm_gateway_metering.config import BucketConfig
from llm_gateway_metering.ratelimit import RateLimiter, TokenBucket
from conftest import FakeClock


def test_token_bucket_burst_and_refill():
    clk = FakeClock(0.0)
    b = TokenBucket(capacity=3, refill_per_s=1, clock=clk)
    assert [b.try_acquire()[0] for _ in range(4)] == [True, True, True, False]
    ok, wait = b.try_acquire()
    assert not ok and wait == pytest.approx(1.0)
    clk.advance(0.5)
    assert not b.try_acquire()[0]
    clk.advance(0.5)
    assert b.try_acquire()[0]
    clk.advance(100)
    assert [b.try_acquire()[0] for _ in range(4)] == [True, True, True, False]  # capped at capacity


def test_user_limit_is_per_user_and_refunds_org():
    clk = FakeClock(0.0)
    rl = RateLimiter(BucketConfig(capacity=3, refill_per_s=0.001), BucketConfig(capacity=1, refill_per_s=0.001),
                     clock=clk)
    rl.check("acme", "alice")
    with pytest.raises(RateLimited) as ei:
        rl.check("acme", "alice")
    assert ei.value.scope == "user"
    rl.check("acme", "bob")      # org bucket was refunded for alice's rejection
    rl.check("acme", "carol")
    with pytest.raises(RateLimited) as ei:
        rl.check("acme", "dave")
    assert ei.value.scope == "org"
    rl.check("globex", "alice")  # different org, different buckets


def test_gateway_rate_limit_rejects_without_metering(make_gateway, mono):
    gw = make_gateway(user_rate=BucketConfig(capacity=2, refill_per_s=1))
    gw.complete(req())
    gw.complete(req())
    with pytest.raises(RateLimited) as ei:
        gw.complete(req())
    assert ei.value.retry_after == pytest.approx(1.0)
    assert gw.usage_report("acme")["requests"] == 2
    mono.advance(1.0)
    gw.complete(req())
