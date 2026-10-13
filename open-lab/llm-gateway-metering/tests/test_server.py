import json
import threading
import urllib.error
import urllib.request

import pytest

from llm_gateway_metering import FeatureConfig
from llm_gateway_metering.config import BucketConfig, hash_key
from llm_gateway_metering.server import serve

KEYS = {"acme": {hash_key("acme-key-123")}, "globex": {hash_key("globex-key-456")}}


@pytest.fixture
def server(make_gateway):
    gw = make_gateway(limit=100, features={"chat": FeatureConfig(max_tokens=20)}, api_key_hashes=KEYS,
                      user_rate=BucketConfig(capacity=3, refill_per_s=0.001))
    httpd = serve(gw, "127.0.0.1", 0)
    t = threading.Thread(target=httpd.serve_forever, daemon=True)
    t.start()
    yield f"http://127.0.0.1:{httpd.server_address[1]}", gw
    httpd.shutdown()
    httpd.server_close()


def call(base, method, path, body=None, key=None, raw=None):
    data = raw if raw is not None else (json.dumps(body).encode() if body is not None else None)
    r = urllib.request.Request(base + path, data=data, method=method)
    r.add_header("Content-Type", "application/json")
    if key:
        r.add_header("Authorization", f"Bearer {key}")
    try:
        with urllib.request.urlopen(r, timeout=5) as resp:
            return resp.status, json.loads(resp.read()), dict(resp.headers)
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read()), dict(e.headers)


def test_health(server):
    base, _ = server
    assert call(base, "GET", "/healthz")[0] == 200


def test_auth_required(server):
    base, _ = server
    st, body, hdr = call(base, "POST", "/v1/complete", {"user": "a", "prompt": "x"})
    assert st == 401 and body["error"]["type"] == "unauthorized" and hdr["WWW-Authenticate"] == "Bearer"
    assert call(base, "GET", "/v1/usage", key="wrong")[0] == 401


def test_complete_and_usage(server):
    base, gw = server
    st, body, _ = call(base, "POST", "/v1/complete",
                       {"user": "alice", "feature": "chat", "prompt": "hello there"}, key="acme-key-123")
    assert st == 200 and body["provider"] == "mock" and body["usage"]["output_tokens"] == 16
    assert body["quota"]["limit"] == 100 and body["quota"]["period"] == "2026-03"
    st, body, _ = call(base, "POST", "/v1/complete",
                       {"user": "bob", "feature": "chat",
                        "messages": [{"role": "user", "content": "hello there"}]}, key="acme-key-123")
    assert st == 200
    st, rep, _ = call(base, "GET", "/v1/usage", key="acme-key-123")
    assert st == 200 and rep["requests"] == 2 and {u["user_id"] for u in rep["by_user"]} == {"alice", "bob"}
    st, rep, _ = call(base, "GET", "/v1/usage?period=2026-03", key="globex-key-456")
    assert rep["requests"] == 0  # org comes from the key


def test_body_cannot_choose_org(server):
    base, gw = server
    call(base, "POST", "/v1/complete", {"user": "eve", "org_id": "acme", "feature": "chat", "prompt": "hi"}, key="globex-key-456")
    assert gw.usage_report("acme")["requests"] == 0
    assert gw.usage_report("globex")["requests"] == 1


def test_quota_and_rate_limit_statuses(server):
    base, _ = server
    k = "acme-key-123"
    ok = [call(base, "POST", "/v1/complete", {"user": f"u{i}", "feature": "chat", "prompt": "hello there"}, key=k)
          for i in range(5)]
    statuses = [s for s, _, _ in ok]
    assert statuses[:3] == [200, 200, 200] and 402 in statuses
    assert ok[-1][1]["error"]["type"] == "quota_exceeded"
    # per-user rate limit: capacity 3
    st = [call(base, "POST", "/v1/complete", {"user": "zed", "feature": "chat", "prompt": "x", "max_tokens": 1},
               key="globex-key-456") for _ in range(4)]
    assert [s for s, _, _ in st] == [200, 200, 200, 429]
    assert st[-1][2]["Retry-After"].isdigit()


def test_bad_requests(server):
    base, _ = server
    k = "acme-key-123"
    assert call(base, "POST", "/v1/complete", raw=b"{not json", key=k)[0] == 400
    assert call(base, "POST", "/v1/complete", {"user": "a"}, key=k)[0] == 400
    assert call(base, "GET", "/v1/usage?period=March", key=k)[0] == 400
    assert call(base, "GET", "/nope", key=k)[0] == 404
