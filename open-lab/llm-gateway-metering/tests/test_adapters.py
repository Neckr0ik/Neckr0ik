"""Request shaping and response parsing for the Claude adapters, using fake SDK clients.
No network: clients are stand-ins that record the kwargs they receive."""

from types import SimpleNamespace

import pytest

from llm_gateway_metering import GatewayConfig, ProviderError, ProviderTimeout
from llm_gateway_metering.providers import build_provider
from llm_gateway_metering.providers._claude_messages import build_params, parse_response
from llm_gateway_metering.providers.anthropic_api import FALLBACK_BETA, AnthropicProvider
from llm_gateway_metering.providers.bedrock import BedrockProvider
from llm_gateway_metering.providers.vertex import VertexProvider
from llm_gateway_metering.types import ProviderRequest


def sdk_response(model="claude-sonnet-5-5", text="hi", in_tok=12, out_tok=3, stop="end_turn", iterations=None):
    usage = SimpleNamespace(input_tokens=in_tok, output_tokens=out_tok, cache_creation_input_tokens=2,
                            cache_read_input_tokens=5, iterations=iterations)
    return SimpleNamespace(id="msg_1", _request_id="req_1", model=model, stop_reason=stop,
                           content=[SimpleNamespace(type="thinking", thinking=""),
                                    SimpleNamespace(type="text", text=text)], usage=usage)


class FakeMessages:
    def __init__(self, response=None, exc=None):
        self.calls, self.response, self.exc = [], response or sdk_response(), exc

    def create(self, **kwargs):
        self.calls.append(kwargs)
        if self.exc:
            raise self.exc
        return self.response


class FakeClient:
    def __init__(self, **kw):
        self.messages = FakeMessages(**kw)
        self.beta = SimpleNamespace(messages=FakeMessages(**kw))


PREQ = ProviderRequest(model="claude-sonnet-5-5", messages=[{"role": "user", "content": "hello"}],
                       max_tokens=512, system="be brief", effort="low")


def test_build_params_shape():
    p = build_params(PREQ, "claude-sonnet-5-5")
    assert p == {"model": "claude-sonnet-5-5", "max_tokens": 512, "messages": PREQ.messages,
                 "system": "be brief", "output_config": {"effort": "low"}}
    bare = build_params(ProviderRequest(model="m", messages=PREQ.messages, max_tokens=1), "m")
    assert set(bare) == {"model", "max_tokens", "messages"}  # no sampling params, no thinking config


def test_anthropic_uses_server_side_fallback_by_default():
    client = FakeClient()
    resp = AnthropicProvider(client).complete(PREQ, timeout_s=7)
    call = client.beta.messages.calls[0]
    assert call["betas"] == [FALLBACK_BETA] and call["fallbacks"] == "default"
    assert call["model"] == "claude-sonnet-5-5" and call["timeout"] == 7
    assert client.messages.calls == []
    assert (resp.text, resp.input_tokens, resp.output_tokens) == ("hi", 12, 3)
    assert resp.cache_creation_input_tokens == 2 and resp.cache_read_input_tokens == 5
    assert resp.request_id == "req_1"


def test_anthropic_without_fallbacks_uses_plain_messages():
    client = FakeClient()
    AnthropicProvider(client, server_fallbacks=False).complete(PREQ, timeout_s=7)
    assert client.beta.messages.calls == [] and "betas" not in client.messages.calls[0]


def test_bedrock_prefixes_model_id():
    client = FakeClient()
    p = BedrockProvider(client)
    p.complete(PREQ, timeout_s=5)
    assert client.messages.calls[0]["model"] == "anthropic.claude-sonnet-5-5"
    assert "fallbacks" not in client.messages.calls[0]
    assert p.model_id("anthropic.claude-haiku-5-5") == "anthropic.claude-haiku-5-5"
    assert p.model_id("us.anthropic.claude-sonnet-5-5") == "us.anthropic.claude-sonnet-5-5"
    assert p.model_id("arn:aws:bedrock:us-east-1:1:inference-profile/x").startswith("arn:")


def test_vertex_uses_bare_model_id():
    client = FakeClient()
    VertexProvider(client).complete(PREQ, timeout_s=5)
    assert client.messages.calls[0]["model"] == "claude-sonnet-5-5"


def test_usage_sums_fallback_iterations():
    its = [SimpleNamespace(type="message", input_tokens=10, output_tokens=0),
           SimpleNamespace(type="fallback_message", input_tokens=10, output_tokens=7)]
    r = parse_response(sdk_response(model="claude-sonnet-5", in_tok=10, out_tok=7, iterations=its))
    assert (r.input_tokens, r.output_tokens, r.served_by_fallback, r.model) == (20, 7, True, "claude-sonnet-5")


def test_refusal_is_metered_as_refused(make_gateway):
    client = FakeClient(response=sdk_response(text="", stop="refusal", out_tok=0))
    gw = make_gateway(provider=AnthropicProvider(client))
    from helpers import req

    r = gw.complete(req())
    assert r.stop_reason == "refusal" and r.text == ""
    assert gw.store._conn.execute("SELECT status FROM requests").fetchone()[0] == "refused"


def test_build_provider_from_config(monkeypatch):
    anthropic = pytest.importorskip("anthropic")
    seen = {}

    def fake(name):
        def ctor(**kw):
            seen[name] = kw
            return FakeClient()
        return ctor

    monkeypatch.setattr(anthropic, "Anthropic", fake("anthropic"))
    monkeypatch.setattr(anthropic, "AnthropicBedrockMantle", fake("bedrock"))
    monkeypatch.setattr(anthropic, "AnthropicVertex", fake("vertex"))
    assert build_provider(GatewayConfig(provider="anthropic", timeout_s=9)).name == "anthropic"
    assert seen["anthropic"] == {"max_retries": 0, "timeout": 9}
    assert build_provider(GatewayConfig(provider="bedrock", aws_region="us-east-1")).name == "bedrock"
    assert seen["bedrock"]["aws_region"] == "us-east-1" and seen["bedrock"]["max_retries"] == 0
    assert build_provider(GatewayConfig(provider="vertex", vertex_project_id="p1")).name == "vertex"
    assert seen["vertex"] == {"project_id": "p1", "region": "global", "max_retries": 0, "timeout": 60.0}
    with pytest.raises(ValueError):
        build_provider(GatewayConfig(provider="bedrock"))
    with pytest.raises(ValueError):
        build_provider(GatewayConfig(provider="vertex"))


def _status_error(cls, status, headers=None):
    import httpx2

    request = httpx2.Request("POST", "https://api.example.invalid/v1/messages")
    response = httpx2.Response(status, request=request, headers=headers or {})
    return cls("secret prompt echoed back", response=response, body=None)


def test_sdk_error_mapping():
    anthropic = pytest.importorskip("anthropic")
    pytest.importorskip("httpx2")
    cases = [
        (_status_error(anthropic.RateLimitError, 429, {"retry-after": "2"}), True, 429),
        (_status_error(anthropic.InternalServerError, 503), True, 503),
        (_status_error(anthropic.BadRequestError, 400), False, 400),
        (_status_error(anthropic.AuthenticationError, 401), False, 401),
    ]
    for exc, retryable, status in cases:
        client = FakeClient(exc=exc)
        with pytest.raises(ProviderError) as ei:
            AnthropicProvider(client, server_fallbacks=False).complete(PREQ, timeout_s=1)
        assert ei.value.retryable is retryable and ei.value.status_code == status
        assert "secret" not in str(ei.value)  # provider body text is not propagated
    assert ei.value.retry_after is None
    client = FakeClient(exc=_status_error(anthropic.RateLimitError, 429, {"retry-after": "2"}))
    with pytest.raises(ProviderError) as ei:
        VertexProvider(client).complete(PREQ, timeout_s=1)
    assert ei.value.retry_after == 2.0

    import httpx2

    t = anthropic.APITimeoutError(request=httpx2.Request("POST", "https://x.invalid"))
    with pytest.raises(ProviderTimeout):
        BedrockProvider(FakeClient(exc=t)).complete(PREQ, timeout_s=1)
    c = anthropic.APIConnectionError(request=httpx2.Request("POST", "https://x.invalid"))
    with pytest.raises(ProviderError) as ei:
        BedrockProvider(FakeClient(exc=c)).complete(PREQ, timeout_s=1)
    assert ei.value.retryable and not isinstance(ei.value, ProviderTimeout)
