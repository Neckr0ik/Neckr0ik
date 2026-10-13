import pytest

from helpers import req
from llm_gateway_metering import FeatureConfig, ModelRate, ProviderError, QuotaExceeded
from llm_gateway_metering.estimate import estimate_input_tokens
from llm_gateway_metering.providers import MockProvider
from conftest import ts


def test_hard_cap_rejects_before_calling_provider(make_gateway):
    provider = MockProvider(output_tokens=10)
    gw = make_gateway(limit=100, provider=provider, features={"chat": FeatureConfig(max_tokens=50)})
    # "hello there" -> estimate = input(7) + max_tokens(50) <= 100 -> passes; actual = 7 + 10 = 17
    first = gw.complete(req("hello there"))
    assert first.quota.used == first.input_tokens + 10
    gw.complete(req("hello there"))
    gw.complete(req("hello there"))  # used ~51
    calls_before = provider.call_count
    with pytest.raises(QuotaExceeded) as ei:
        gw.complete(req("hello there"))  # 51 + 57 > 100
    assert provider.call_count == calls_before  # provider never called
    assert ei.value.limit == 100 and ei.value.requested > 0
    # A smaller request still fits under the cap
    ok = gw.complete(req("hello there", max_tokens=5))
    assert ok.quota.used <= 100


def test_quota_shared_across_users_of_same_org(make_gateway):
    gw = make_gateway(limit=60, features={"chat": FeatureConfig(max_tokens=20)})
    gw.complete(req(user="alice"))
    gw.complete(req(user="bob"))
    with pytest.raises(QuotaExceeded):
        gw.complete(req(user="carol"))
    # Another org has its own pool
    gw.complete(req(org="globex", user="carol"))


def test_model_rates_weight_the_quota(make_gateway):
    gw = make_gateway(limit=100_000, model_rates={"default": ModelRate(input=1, output=5)},
                      provider=MockProvider(output_tokens=10))
    r = gw.complete(req("abcd" * 10))
    assert r.cost_units == r.input_tokens * 1 + 10 * 5
    assert r.quota.used == r.cost_units


def test_soft_warning_at_80_percent_fires_once(make_gateway, log_capture):
    warnings = []
    gw = make_gateway(limit=100, provider=MockProvider(output_tokens=20),
                      features={"chat": FeatureConfig(max_tokens=20)})
    gw.on_warning = lambda org, q: warnings.append((org, q.used))
    in_tok = estimate_input_tokens([{"role": "user", "content": "hello there"}])
    per = in_tok + 20
    responses = []
    while True:
        try:
            responses.append(gw.complete(req()))
        except QuotaExceeded:
            break
    flags = [r.quota.warning for r in responses]
    first_warn = flags.index(True)
    assert responses[first_warn].quota.used >= 80
    assert responses[first_warn - 1].quota.used < 80
    assert all(flags[first_warn:])
    assert len(warnings) == 1 and warnings[0][0] == "acme"
    assert log_capture.getvalue().count('"event":"quota_warning"') == 1
    assert per > 0


def test_warn_ratio_is_configurable(make_gateway):
    gw = make_gateway(limit=1000, warn_ratio=0.5, provider=MockProvider(output_tokens=300),
                      features={"chat": FeatureConfig(max_tokens=300)})
    r1 = gw.complete(req())
    assert not r1.quota.warning
    r2 = gw.complete(req())
    assert r2.quota.used >= 500 and r2.quota.warning


def test_month_rollover_resets_pool_and_keeps_history(make_gateway, clock):
    gw = make_gateway(limit=60, features={"chat": FeatureConfig(max_tokens=20)})
    gw.complete(req())
    gw.complete(req())
    with pytest.raises(QuotaExceeded):
        gw.complete(req())
    clock.t = ts(2026, 4, 1, 0)  # first second of April (UTC)
    r = gw.complete(req())
    assert r.quota.period == "2026-04"
    assert r.quota.used == r.cost_units  # fresh pool
    march = gw.usage_report("acme", "2026-03")
    april = gw.usage_report("acme")
    assert march["requests"] == 2 and april["requests"] == 1
    assert march["period"] == "2026-03" and april["period"] == "2026-04"


def test_december_to_january_rollover(make_gateway, clock):
    clock.t = ts(2026, 12, 31, 23)
    gw = make_gateway()
    assert gw.complete(req()).quota.period == "2026-12"
    clock.t = ts(2027, 1, 1, 0)
    assert gw.complete(req()).quota.period == "2027-01"


def test_reports_by_user_and_feature(make_gateway):
    gw = make_gateway(provider=MockProvider(output_tokens=10))
    gw.complete(req(user="alice", feature="chat"))
    gw.complete(req(user="alice", feature="summarize"))
    gw.complete(req(user="bob", feature="chat"))
    gw.complete(req(user="bob", feature="chat"))
    rep = gw.usage_report("acme")
    by_user = {r["user_id"]: r for r in rep["by_user"]}
    by_feature = {r["feature"]: r for r in rep["by_feature"]}
    assert by_user["alice"]["requests"] == 2 and by_user["bob"]["requests"] == 2
    assert by_feature["chat"]["requests"] == 3 and by_feature["summarize"]["requests"] == 1
    assert sum(r["cost_units"] for r in rep["by_user"]) == pytest.approx(rep["used"])
    assert sum(r["output_tokens"] for r in rep["by_feature"]) == 40
    assert rep["limit"] == 10_000 and rep["remaining"] == 10_000 - rep["used"]
    assert rep["by_model"][0]["model"] == "claude-sonnet-5-5"
    assert gw.usage_report("other-org")["requests"] == 0


def test_failed_request_releases_reservation_and_is_recorded(make_gateway):
    boom = ProviderError("bad request", retryable=False, status_code=400)
    gw = make_gateway(limit=60, provider=MockProvider(failures=[boom]),
                      features={"chat": FeatureConfig(max_tokens=20)})
    with pytest.raises(ProviderError):
        gw.complete(req())
    used, reserved = gw.store.totals("acme", "2026-03", now=gw.clock())
    assert used == 0 and reserved == 0
    rep = gw.usage_report("acme")
    assert rep["requests"] == 1 and rep["by_user"][0]["ok"] == 0
    # The pool is intact: two full requests still fit.
    gw.complete(req())
    gw.complete(req())


def test_expired_reservations_do_not_block(make_gateway, clock):
    gw = make_gateway(limit=100)
    gw.store.reserve("acme", "2026-03", 100, 100, now=clock(), ttl_s=60)  # simulate a crashed worker
    with pytest.raises(QuotaExceeded):
        gw.complete(req(max_tokens=5))
    clock.advance(61)
    gw.complete(req(max_tokens=5))


def test_feature_model_and_max_tokens(make_gateway):
    provider = MockProvider()
    gw = make_gateway(provider=provider, features={
        "summarize": FeatureConfig(model="claude-haiku-5-5", max_tokens=256, effort="low")})
    r = gw.complete(req(feature="summarize", max_tokens=10_000))
    assert r.model == "claude-haiku-5-5"
    call = provider.calls[-1]
    assert call.max_tokens == 256 and call.effort == "low"  # caller cannot exceed the feature cap
    assert gw.complete(req(feature="other")).model == "claude-sonnet-5-5"


def test_strict_features_rejects_unknown(make_gateway):
    from llm_gateway_metering import InvalidRequest

    gw = make_gateway(strict_features=True, features={"chat": FeatureConfig()})
    gw.complete(req(feature="chat"))
    with pytest.raises(InvalidRequest):
        gw.complete(req(feature="nope"))


@pytest.mark.parametrize("bad", [
    dict(messages=[]),
    dict(messages=[{"role": "system", "content": "x"}]),
    dict(messages=[{"role": "assistant", "content": "x"}]),
    dict(user_id="bad user!"),
    dict(max_tokens=0),
])
def test_validation(make_gateway, bad):
    from dataclasses import replace

    from llm_gateway_metering import InvalidRequest

    gw = make_gateway()
    with pytest.raises(InvalidRequest):
        gw.complete(replace(req(), **bad))
