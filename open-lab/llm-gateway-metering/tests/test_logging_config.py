import json

import pytest

from helpers import req
from llm_gateway_metering import GatewayConfig
from llm_gateway_metering.config import hash_key, parse_api_keys
from llm_gateway_metering.logging_utils import redact


def test_logs_are_json_and_exclude_prompts_and_raw_user_ids(make_gateway, log_capture):
    gw = make_gateway()
    gw.complete(req("TOP-SECRET-PROMPT about alice@example.com", user="alice@example.com",
                    system="SYSTEM-SECRET"))
    out = log_capture.getvalue()
    assert "TOP-SECRET-PROMPT" not in out and "SYSTEM-SECRET" not in out and "deterministic reply" not in out
    assert "alice@example.com" not in out
    events = [json.loads(line) for line in out.splitlines()]
    done = [e for e in events if e["event"] == "request_completed"][0]
    assert done["user"].startswith("u_") and done["org_id"] == "acme" and done["feature"] == "chat"
    for field in ("provider", "model", "input_tokens", "output_tokens", "latency_ms", "status", "attempts"):
        assert field in done


def test_redaction_scrubs_credentials():
    s = redact("key sk-ant-api03-abcdefghijkl and Bearer abcdefghijklmnop and AKIAABCDEFGHIJKLMNOP")
    assert "sk-ant" not in s and "abcdefghijklmnop" not in s and "AKIA" not in s


def test_from_env_and_api_keys(tmp_path):
    cfg_file = tmp_path / "gw.json"
    cfg_file.write_text(json.dumps({
        "orgs": {"acme": {"monthly_limit": 5000, "warn_ratio": 0.9}},
        "features": {"summarize": {"model": "claude-haiku-5-5", "max_tokens": 256}},
        "model_rates": {"default": {"input": 1, "output": 4}},
        "rate_limits": {"org": {"capacity": 5, "refill_per_s": 1}, "user": None},
    }))
    env = {"LLMGW_CONFIG_FILE": str(cfg_file), "LLMGW_PROVIDER": "bedrock", "AWS_REGION": "us-west-2",
           "LLMGW_API_KEYS": "acme:k1,acme:k2", "LLMGW_API_KEY_SHA256": f"globex:{hash_key('k3')}",
           "LLMGW_DEFAULT_MONTHLY_LIMIT": "777"}
    cfg = GatewayConfig.from_env(env)
    assert cfg.provider == "bedrock" and cfg.aws_region == "us-west-2"
    assert cfg.default_model == "claude-sonnet-5-5"
    assert cfg.org("acme").monthly_limit == 5000 and cfg.org("acme").warn_ratio == 0.9
    assert cfg.org("unknown").monthly_limit == 777
    assert cfg.feature("summarize").model == "claude-haiku-5-5"
    assert cfg.rate_for("anything").output == 4
    assert cfg.user_rate is None and cfg.org_rate.capacity == 5
    assert cfg.api_key_hashes == {"acme": {hash_key("k1"), hash_key("k2")}, "globex": {hash_key("k3")}}
    assert "k1" not in repr(cfg)


def test_config_file_rejects_keys(tmp_path):
    f = tmp_path / "bad.json"
    f.write_text(json.dumps({"api_keys": {"acme": "plaintext"}}))
    with pytest.raises(ValueError):
        GatewayConfig.from_env({"LLMGW_CONFIG_FILE": str(f)})


def test_bad_key_specs():
    with pytest.raises(ValueError):
        parse_api_keys("no-colon", "")
    with pytest.raises(ValueError):
        parse_api_keys("", "acme:short")
    with pytest.raises(ValueError):
        GatewayConfig(provider="openai")
