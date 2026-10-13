"""Regression tests from the adversarial audit: cache tokens, fallback hops, the input
estimator, metering-write failures, the HTTP server's limits, and config validation."""

import socket
import threading
import time
import urllib.error
import urllib.request
from types import SimpleNamespace as NS

import pytest
from helpers import req

from llm_gateway_metering import GatewayConfig, ModelRate, QuotaExceeded
from llm_gateway_metering.cli import main as cli_main
from llm_gateway_metering.config import hash_key
from llm_gateway_metering.estimate import IMAGE_TOKENS, estimate_input_tokens
from llm_gateway_metering.logging_utils import pseudonymize
from llm_gateway_metering.providers.anthropic_api import AnthropicProvider
from llm_gateway_metering.server import serve


class FakeMessages:
    def __init__(self, response):
        self.response, self.calls = response, []

    def create(self, **kw):
        self.calls.append(kw)
        return self.response


def fake_client(response):
    return NS(messages=FakeMessages(response), beta=NS(messages=FakeMessages(response)))


def usage(in_tok=10, out_tok=5, cache_w=0, cache_r=0, iterations=None):
    return NS(input_tokens=in_tok, output_tokens=out_tok, cache_creation_input_tokens=cache_w,
              cache_read_input_tokens=cache_r, iterations=iterations)


def sdk_response(model="claude-sonnet-5-5", **kw):
    return NS(id="msg_1", model=model, stop_reason="end_turn", content=[NS(type="text", text="ok")],
              usage=usage(**kw))


# -- cost: cache tokens and per-iteration rates ----------------------------------------------------

def test_cache_tokens_are_charged_with_their_own_weights(make_gateway):
    client = fake_client(sdk_response(in_tok=10, out_tok=5, cache_w=2000, cache_r=4000))
    gw = make_gateway(limit=100_000, provider=AnthropicProvider(client, server_fallbacks=False),
                      model_rates={"default": ModelRate(input=1, output=5, cache_write=1.25, cache_read=0.1)})
    r = gw.complete(req())
    assert r.cost_units == pytest.approx(10 + 5 * 5 + 2000 * 1.25 + 4000 * 0.1)
    assert r.quota.used == pytest.approx(r.cost_units)
    assert (r.cache_creation_input_tokens, r.cache_read_input_tokens) == (2000, 4000)
    assert r.to_dict()["usage"]["cache_read_input_tokens"] == 4000


def test_cache_tokens_default_to_full_input_weight():
    assert ModelRate().cost(10, 5, 200_000, 0) == 200_015


def test_each_fallback_iteration_is_charged_at_its_own_model_rate(make_gateway):
    its = [NS(type="message", model=None, input_tokens=10, output_tokens=100,
              cache_creation_input_tokens=0, cache_read_input_tokens=0),
           NS(type="fallback_message", model="claude-opus-4-8", input_tokens=10, output_tokens=100,
              cache_creation_input_tokens=0, cache_read_input_tokens=0)]
    client = fake_client(sdk_response(model="claude-opus-4-8", in_tok=10, out_tok=100, iterations=its))
    gw = make_gateway(limit=100_000, provider=AnthropicProvider(client),
                      model_rates={"claude-sonnet-5-5": ModelRate(1, 1), "claude-opus-4-8": ModelRate(3, 3)})
    r = gw.complete(req("hi", max_tokens=100))
    assert r.cost_units == 110 * 1 + 110 * 3
    assert r.model == "claude-opus-4-8"


def test_reservation_covers_fallback_hops_at_the_highest_rate(make_gateway):
    client = fake_client(sdk_response())
    gw = make_gateway(limit=150, provider=AnthropicProvider(client),
                      model_rates={"claude-sonnet-5-5": ModelRate(1, 1), "claude-opus-4-8": ModelRate(3, 3)})
    with pytest.raises(QuotaExceeded) as ei:
        gw.complete(req("hi", max_tokens=100))
    est = estimate_input_tokens([{"role": "user", "content": "hi"}])
    assert ei.value.requested == (est + 100) * 1 + (est + 100) * 3  # own attempt + one hop at max rate
    assert client.beta.messages.calls == []  # provider never called


def test_fallbacks_only_requested_for_supported_models(make_gateway):
    client = fake_client(sdk_response(model="claude-haiku-5-5"))
    provider = AnthropicProvider(client)
    gw = make_gateway(limit=1000, provider=provider, default_model="claude-haiku-5-5")
    r = gw.complete(req("hi", max_tokens=100))
    assert client.beta.messages.calls == [] and "fallbacks" not in client.messages.calls[0]
    assert provider.fallback_hops("claude-haiku-5-5") == 0 and provider.fallback_hops("claude-sonnet-5-5") == 1
    assert r.quota.used == r.cost_units
    custom = AnthropicProvider(client, fallback_models=["claude-haiku-5-5"])
    assert custom.uses_fallback("claude-haiku-5-5") and not custom.uses_fallback("claude-sonnet-5-5")


def test_fallback_models_from_env():
    cfg = GatewayConfig.from_env({"LLMGW_ANTHROPIC_FALLBACK_MODELS": "a, b"})
    assert cfg.anthropic_fallback_models == ("a", "b")
    assert GatewayConfig().anthropic_fallback_models == ("claude-sonnet-5-5", "claude-opus-5-5")


# -- estimator -------------------------------------------------------------------------------------

def test_estimator_counts_utf8_bytes_for_dense_scripts():
    cjk = estimate_input_tokens([{"role": "user", "content": "漢" * 3000}])
    assert cjk >= 3000  # one token per CJK character or more, not 750


def test_estimator_counts_nested_document_and_tool_content():
    doc = [{"role": "user", "content": [{"type": "document", "source": {
        "type": "text", "media_type": "text/plain", "data": "x" * 400_000}}]}]
    assert estimate_input_tokens(doc) >= 100_000
    tool = [{"role": "user", "content": [{"type": "tool_result", "tool_use_id": "t1",
                                          "content": [{"type": "text", "text": "y" * 3000}]}]}]
    assert estimate_input_tokens(tool) >= 1000
    use = [{"role": "user", "content": "q"}, {"role": "assistant", "content": [
        {"type": "tool_use", "id": "t1", "name": "f", "input": {"q": "z" * 3000}}]}]
    assert estimate_input_tokens(use) >= 1000


def test_estimator_flat_guess_for_images():
    img = [{"role": "user", "content": [{"type": "image", "source": {
        "type": "base64", "media_type": "image/png", "data": "A" * 2_000_000}}]}]
    assert estimate_input_tokens(img) == IMAGE_TOKENS + 4


def test_no_new_request_once_usage_overshoots_the_cap(make_gateway):
    client = fake_client(sdk_response(in_tok=10, out_tok=5, cache_w=5000))
    gw = make_gateway(limit=1000, provider=AnthropicProvider(client, server_fallbacks=False))
    r = gw.complete(req("hi", max_tokens=10))
    assert r.quota.used > 1000  # actual usage can exceed the estimate
    with pytest.raises(QuotaExceeded):
        gw.complete(req("hi", max_tokens=10))
    assert len(client.messages.calls) == 1


# -- metering write failures -----------------------------------------------------------------------

def test_settle_is_retried_once(make_gateway):
    gw = make_gateway()
    real, fails = gw.store.settle, []

    def flaky(*a, **k):
        if not fails:
            fails.append(1)
            raise RuntimeError("database is locked")
        return real(*a, **k)

    gw.store.settle = flaky
    r = gw.complete(req())
    assert gw.usage_report("acme")["requests"] == 1 and r.quota.used == r.cost_units


def test_settle_failure_releases_reservation_and_logs(make_gateway, log_capture):
    gw = make_gateway()

    def boom(*a, **k):
        raise RuntimeError("database is locked")

    gw.store.settle = boom
    r = gw.complete(req())  # the provider already answered: the caller still gets the reply
    used, reserved = gw.store.totals("acme", "2026-03", now=gw.clock())
    assert reserved == 0 and used == r.cost_units  # release() wrote the record instead
    assert '"event":"metering_write_failed"' in log_capture.getvalue()
    assert '"recorded_on_release":true' in log_capture.getvalue()


# -- HTTP server limits ----------------------------------------------------------------------------

KEYS = {"acme": {hash_key("acme-key-123")}}


def _start(gw, **kw):
    httpd = serve(gw, "127.0.0.1", 0, **kw)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    return httpd


def test_stalled_client_is_dropped_after_request_timeout(make_gateway):
    httpd = _start(make_gateway(api_key_hashes=KEYS), request_timeout_s=0.5)
    try:
        s = socket.create_connection(httpd.server_address)
        s.sendall(b"POST /v1/complete HTTP/1.1\r\nHost: x\r\nContent-Length: 1000\r\n\r\n")
        s.settimeout(5)
        t0 = time.monotonic()
        while s.recv(4096):
            pass  # server closes the connection once its read times out
        assert time.monotonic() - t0 < 4
        s.close()
    finally:
        httpd.shutdown()
        httpd.server_close()


def test_concurrency_cap_returns_503(make_gateway):
    httpd = _start(make_gateway(api_key_hashes=KEYS), max_concurrency=1, request_timeout_s=3)
    base = f"http://127.0.0.1:{httpd.server_address[1]}"
    try:
        hog = socket.create_connection(httpd.server_address)
        hog.sendall(b"GET /healthz HTTP/1.1\r\n")  # incomplete request holds the only slot
        time.sleep(0.2)
        with pytest.raises(urllib.error.HTTPError) as ei:
            urllib.request.urlopen(base + "/healthz", timeout=5)
        assert ei.value.code == 503 and ei.value.headers["Retry-After"] == "1"
        hog.close()
        deadline = time.monotonic() + 5
        while True:  # slot frees once the hog's handler finishes
            try:
                with urllib.request.urlopen(base + "/healthz", timeout=5) as resp:
                    assert resp.status == 200
                break
            except urllib.error.HTTPError:
                assert time.monotonic() < deadline
                time.sleep(0.1)
    finally:
        httpd.shutdown()
        httpd.server_close()


# -- CLI and config --------------------------------------------------------------------------------

def test_cli_rejects_bad_period_cleanly(capsys):
    with pytest.raises(SystemExit) as ei:
        cli_main(["usage", "--org", "acme", "--period", "2026-13"])
    assert ei.value.code == 2
    err = capsys.readouterr().err
    assert "period must look like YYYY-MM" in err and "Traceback" not in err


def test_log_salt_changes_pseudonyms(make_gateway):
    assert pseudonymize("alice", "s1") != pseudonymize("alice")
    gw = make_gateway(log_salt="pepper")
    assert gw._uid("alice") == pseudonymize("alice", "pepper")
    assert GatewayConfig.from_env({"LLMGW_LOG_SALT": "pepper"}).log_salt == "pepper"
    assert "pepper" not in repr(GatewayConfig(log_salt="pepper"))
    with pytest.raises(ValueError):
        GatewayConfig.from_mapping({"log_salt": "x"})


def test_reservation_ttl_must_outlive_the_slowest_call():
    with pytest.raises(ValueError, match="reservation_ttl_s"):
        GatewayConfig(timeout_s=60, max_attempts=3, backoff_max_s=8, reservation_ttl_s=195)
    GatewayConfig(timeout_s=60, max_attempts=3, backoff_max_s=8, reservation_ttl_s=196)
    with pytest.raises(ValueError):
        GatewayConfig.from_env({"LLMGW_TIMEOUT_S": "400"})  # 3 * 400 + 16 > 900 default TTL
    assert GatewayConfig.from_env({"LLMGW_TIMEOUT_S": "400", "LLMGW_RESERVATION_TTL_S": "1300"}).timeout_s == 400
