import threading

import pytest

from helpers import req
from llm_gateway_metering import FeatureConfig, Gateway, GatewayConfig, OrgConfig, QuotaExceeded
from llm_gateway_metering.providers import MockProvider
from llm_gateway_metering.store import SQLiteStore


def _race(n, fn):
    barrier = threading.Barrier(n)
    results, errors = [], []

    def worker(i):
        barrier.wait()
        try:
            results.append(fn(i))
        except QuotaExceeded as e:
            errors.append(e)

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(n)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(10)
    return results, errors


def test_two_concurrent_requests_cannot_both_pass_cap(make_gateway):
    # Each request reserves ~7 + 50 units; the cap allows exactly one in flight.
    provider = MockProvider(output_tokens=50, delay_s=0.2)
    gw = make_gateway(limit=100, provider=provider, features={"chat": FeatureConfig(max_tokens=50)})
    results, errors = _race(2, lambda i: gw.complete(req(user=f"u{i}")))
    assert len(results) == 1 and len(errors) == 1
    assert provider.call_count == 1


def test_cap_holds_across_separate_store_connections(tmp_path, clock, mono):
    """Two gateway instances (like two worker processes) sharing one SQLite file."""
    db = str(tmp_path / "shared.db")
    cfg = GatewayConfig(provider="mock", db_path=db, org_rate=None, user_rate=None,
                        default_org=OrgConfig(monthly_limit=100), features={"chat": FeatureConfig(max_tokens=50)})
    providers = [MockProvider(output_tokens=50, delay_s=0.2) for _ in range(2)]
    gws = [Gateway(cfg, provider=p, store=SQLiteStore(db), clock=clock, monotonic=mono) for p in providers]
    try:
        results, errors = _race(2, lambda i: gws[i].complete(req(user=f"u{i}")))
        assert len(results) == 1 and len(errors) == 1
        assert sum(p.call_count for p in providers) == 1
    finally:
        for g in gws:
            g.close()


@pytest.mark.parametrize("n", [16])
def test_many_concurrent_requests_never_overspend(make_gateway, n):
    provider = MockProvider(output_tokens=20, delay_s=0.01)
    gw = make_gateway(limit=200, provider=provider, features={"chat": FeatureConfig(max_tokens=20)})
    results, errors = _race(n, lambda i: gw.complete(req(user=f"u{i % 4}")))
    used, reserved = gw.store.totals("acme", "2026-03", now=gw.clock())
    assert used <= 200 and reserved == 0
    assert len(results) + len(errors) == n
    assert len(results) == provider.call_count
    per = results[0].cost_units
    assert len(results) == int(200 // per)  # every request that could fit, did
