"""Offline tests of the Anthropic adapter using a fake client (no network)."""

import os
from types import SimpleNamespace

import pytest

from silicon_sample_validation.adapters.anthropic_adapter import (
    DEFAULT_MODEL,
    AnthropicLLM,
    anthropic_available,
)


class FakeMessages:
    def __init__(self, response):
        self.response = response
        self.kwargs = None

    def create(self, **kwargs):
        self.kwargs = kwargs
        return self.response


def fake_client(blocks, stop_reason="end_turn"):
    return SimpleNamespace(messages=FakeMessages(SimpleNamespace(content=blocks, stop_reason=stop_reason)))


def test_default_model_and_request_shape():
    client = fake_client([SimpleNamespace(type="thinking", thinking=""), SimpleNamespace(type="text", text=" 31.4 ")])
    llm = AnthropicLLM(client=client, system="sys")
    assert DEFAULT_MODEL == "claude-haiku-5-5"
    assert llm("What is X?") == "31.4"
    kw = client.messages.kwargs
    assert kw["model"] == "claude-haiku-5-5"
    assert kw["messages"] == [{"role": "user", "content": "What is X?"}]
    assert kw["output_config"] == {"effort": "low"}
    assert kw["system"] == "sys"
    assert "temperature" not in kw  # non-default sampling is rejected on this model


def test_refusal_returns_empty_text():
    client = fake_client([SimpleNamespace(type="text", text="ignored")], stop_reason="refusal")
    assert AnthropicLLM(client=client)("q") == ""


def test_effort_can_be_omitted():
    client = fake_client([SimpleNamespace(type="text", text="1")])
    AnthropicLLM(client=client, effort=None)("q")
    assert "output_config" not in client.messages.kwargs


def test_requires_sdk_and_key_without_client(monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    assert anthropic_available() is False
    with pytest.raises(RuntimeError):
        AnthropicLLM()


@pytest.mark.skipif(
    not (anthropic_available() and os.environ.get("SSV_LIVE_TESTS") == "1"),
    reason="live API test: needs anthropic, ANTHROPIC_API_KEY and SSV_LIVE_TESTS=1",
)
def test_live_call():  # pragma: no cover
    assert isinstance(AnthropicLLM()("Reply with the number 7 only."), str)
