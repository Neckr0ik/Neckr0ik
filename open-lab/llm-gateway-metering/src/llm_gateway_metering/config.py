"""Configuration: dataclasses plus loaders for environment variables and a JSON file.

Secrets (provider credentials, gateway API keys) are read from the environment only.
The JSON file holds non-secret policy: orgs, quotas, features, model rates, rate limits.
"""

from __future__ import annotations

import hashlib
import json
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Mapping

from .errors import InvalidRequest

DEFAULT_MODEL = "claude-sonnet-5-5"
PROVIDERS = ("mock", "anthropic", "bedrock", "vertex")
# Models for which the Anthropic API's server-side refusal fallback is requested. Other
# models are sent without it, so a model that doesn't support it never gets a 400.
DEFAULT_FALLBACK_MODELS = ("claude-sonnet-5-5", "claude-opus-5-5")


@dataclass(frozen=True)
class ModelRate:
    """Cost units charged per token. Defaults to 1:1, i.e. quotas are plain token counts.

    Set your own weights (e.g. output tokens count 5x) to approximate relative cost;
    the package ships no price list on purpose.
    """

    input: float = 1.0
    output: float = 1.0
    cache_write: float = 1.0  # per cache_creation_input_token
    cache_read: float = 1.0  # per cache_read_input_token

    def cost(self, input_tokens: int, output_tokens: int, cache_write_tokens: int = 0,
             cache_read_tokens: int = 0) -> float:
        return (input_tokens * self.input + output_tokens * self.output
                + cache_write_tokens * self.cache_write + cache_read_tokens * self.cache_read)


@dataclass(frozen=True)
class FeatureConfig:
    model: str | None = None  # None -> GatewayConfig.default_model
    max_tokens: int = 4096
    effort: str | None = None  # forwarded as output_config.effort when set


@dataclass(frozen=True)
class OrgConfig:
    monthly_limit: float  # cost units per calendar month (UTC), shared by all users of the org
    warn_ratio: float = 0.8

    def __post_init__(self) -> None:
        if self.monthly_limit < 0:
            raise ValueError("monthly_limit must be >= 0")
        if not 0 < self.warn_ratio <= 1:
            raise ValueError("warn_ratio must be in (0, 1]")


@dataclass(frozen=True)
class BucketConfig:
    capacity: float
    refill_per_s: float


@dataclass
class GatewayConfig:
    provider: str = "mock"
    default_model: str = DEFAULT_MODEL
    db_path: str = "llm_gateway.db"
    timeout_s: float = 60.0
    max_attempts: int = 3
    backoff_base_s: float = 0.5
    backoff_max_s: float = 8.0
    reservation_ttl_s: float = 900.0
    default_org: OrgConfig = field(default_factory=lambda: OrgConfig(monthly_limit=1_000_000))
    orgs: dict[str, OrgConfig] = field(default_factory=dict)
    features: dict[str, FeatureConfig] = field(default_factory=dict)
    strict_features: bool = False
    model_rates: dict[str, ModelRate] = field(default_factory=dict)
    org_rate: BucketConfig | None = field(default_factory=lambda: BucketConfig(capacity=60, refill_per_s=10))
    user_rate: BucketConfig | None = field(default_factory=lambda: BucketConfig(capacity=20, refill_per_s=2))
    # Provider-specific, non-secret settings
    aws_region: str | None = None
    vertex_project_id: str | None = None
    vertex_region: str = "global"
    anthropic_server_fallbacks: bool = True
    anthropic_fallback_models: tuple[str, ...] = DEFAULT_FALLBACK_MODELS
    anthropic_fallback_hops: int = 1  # extra attempts reserved for when a fallback is requested
    # Logging / privacy
    log_level: str = "INFO"
    log_hash_user_ids: bool = True
    log_salt: str = field(default="", repr=False)  # LLMGW_LOG_SALT; environment only
    # API keys: org_id -> set of sha256 hex digests. Populated from env only.
    api_key_hashes: dict[str, set[str]] = field(default_factory=dict, repr=False)

    def __post_init__(self) -> None:
        if self.provider not in PROVIDERS:
            raise ValueError(f"provider must be one of {PROVIDERS}, got {self.provider!r}")
        if self.max_attempts < 1:
            raise ValueError("max_attempts must be >= 1")
        if self.anthropic_fallback_hops < 0:
            raise ValueError("anthropic_fallback_hops must be >= 0")
        self.anthropic_fallback_models = tuple(self.anthropic_fallback_models)
        # A reservation must outlive the slowest possible call, or it could expire while the
        # provider is still working and let other requests spend the same budget.
        worst = self.max_attempts * self.timeout_s + (self.max_attempts - 1) * self.backoff_max_s
        if self.reservation_ttl_s < worst:
            raise ValueError(f"reservation_ttl_s ({self.reservation_ttl_s:g}) must be >= max_attempts * timeout_s"
                             f" + (max_attempts - 1) * backoff_max_s = {worst:g}")

    # -- lookups -----------------------------------------------------------
    def org(self, org_id: str) -> OrgConfig:
        return self.orgs.get(org_id, self.default_org)

    def feature(self, name: str) -> FeatureConfig:
        if name in self.features:
            return self.features[name]
        if self.strict_features:
            raise InvalidRequest(f"unknown feature {name!r}")
        return self.features.get("default", FeatureConfig())

    def model_for(self, feature: FeatureConfig) -> str:
        return feature.model or self.default_model

    def rate_for(self, model: str) -> ModelRate:
        return self.model_rates.get(model, self.model_rates.get("default", ModelRate()))

    def max_rate(self) -> ModelRate:
        """Component-wise maximum over every configured rate (and the default).

        Used to reserve for server-side fallback hops, whose model the API chooses.
        """
        rates = [*self.model_rates.values(), self.rate_for("default")]
        return ModelRate(*(max(getattr(r, f) for r in rates) for f in ("input", "output", "cache_write", "cache_read")))

    # -- loaders -----------------------------------------------------------
    @classmethod
    def from_mapping(cls, data: Mapping[str, Any], **overrides: Any) -> "GatewayConfig":
        kw: dict[str, Any] = {}
        simple = ("provider", "default_model", "db_path", "timeout_s", "max_attempts", "backoff_base_s",
                  "backoff_max_s", "reservation_ttl_s", "strict_features", "aws_region", "vertex_project_id",
                  "vertex_region", "anthropic_server_fallbacks", "anthropic_fallback_models",
                  "anthropic_fallback_hops", "log_level", "log_hash_user_ids")
        for key in simple:
            if key in data:
                kw[key] = data[key]
        if "default_org" in data:
            kw["default_org"] = OrgConfig(**data["default_org"])
        if "orgs" in data:
            kw["orgs"] = {k: OrgConfig(**v) for k, v in data["orgs"].items()}
        if "features" in data:
            kw["features"] = {k: FeatureConfig(**v) for k, v in data["features"].items()}
        if "model_rates" in data:
            kw["model_rates"] = {k: ModelRate(**v) for k, v in data["model_rates"].items()}
        rl = data.get("rate_limits", {})
        for scope in ("org", "user"):
            if scope in rl:
                kw[f"{scope}_rate"] = BucketConfig(**rl[scope]) if rl[scope] else None
        if "api_keys" in data or "api_key_sha256" in data:
            raise ValueError("API keys are not accepted in the config file; use LLMGW_API_KEYS / LLMGW_API_KEY_SHA256")
        if "log_salt" in data:
            raise ValueError("log_salt is not accepted in the config file; use LLMGW_LOG_SALT")
        kw.update(overrides)
        return cls(**kw)

    @classmethod
    def from_env(cls, env: Mapping[str, str] | None = None) -> "GatewayConfig":
        env = os.environ if env is None else env
        data: dict[str, Any] = {}
        path = env.get("LLMGW_CONFIG_FILE")
        if path:
            data = json.loads(Path(path).read_text(encoding="utf-8"))
        ov: dict[str, Any] = {}
        mapping = {
            "LLMGW_PROVIDER": ("provider", str),
            "LLMGW_DEFAULT_MODEL": ("default_model", str),
            "LLMGW_DB_PATH": ("db_path", str),
            "LLMGW_TIMEOUT_S": ("timeout_s", float),
            "LLMGW_MAX_ATTEMPTS": ("max_attempts", int),
            "LLMGW_RESERVATION_TTL_S": ("reservation_ttl_s", float),
            "LLMGW_LOG_LEVEL": ("log_level", str),
            "LLMGW_VERTEX_REGION": ("vertex_region", str),
        }
        for var, (key, conv) in mapping.items():
            if env.get(var):
                ov[key] = conv(env[var])
        if env.get("LLMGW_ANTHROPIC_FALLBACKS"):
            ov["anthropic_server_fallbacks"] = env["LLMGW_ANTHROPIC_FALLBACKS"].lower() not in ("0", "false", "no", "off")
        if env.get("LLMGW_ANTHROPIC_FALLBACK_MODELS") is not None:
            ov["anthropic_fallback_models"] = tuple(
                m.strip() for m in env["LLMGW_ANTHROPIC_FALLBACK_MODELS"].split(",") if m.strip())
        if env.get("LLMGW_LOG_SALT"):
            ov["log_salt"] = env["LLMGW_LOG_SALT"]
        region = env.get("LLMGW_AWS_REGION") or env.get("AWS_REGION") or env.get("AWS_DEFAULT_REGION")
        if region:
            ov["aws_region"] = region
        project = env.get("LLMGW_VERTEX_PROJECT") or env.get("ANTHROPIC_VERTEX_PROJECT_ID")
        if project:
            ov["vertex_project_id"] = project
        if "vertex_region" not in ov and env.get("CLOUD_ML_REGION"):
            ov["vertex_region"] = env["CLOUD_ML_REGION"]
        if env.get("LLMGW_DEFAULT_MONTHLY_LIMIT"):
            base = data.get("default_org", {})
            ov["default_org"] = OrgConfig(monthly_limit=float(env["LLMGW_DEFAULT_MONTHLY_LIMIT"]),
                                          warn_ratio=float(env.get("LLMGW_WARN_RATIO", base.get("warn_ratio", 0.8))))
        ov["api_key_hashes"] = parse_api_keys(env.get("LLMGW_API_KEYS", ""), env.get("LLMGW_API_KEY_SHA256", ""))
        return cls.from_mapping(data, **ov)


def hash_key(key: str) -> str:
    return hashlib.sha256(key.encode("utf-8")).hexdigest()


def parse_api_keys(raw: str, hashed: str) -> dict[str, set[str]]:
    """Parse ``org:key,org:key`` (raw, hashed immediately) and ``org:sha256hex,...`` (pre-hashed)."""
    out: dict[str, set[str]] = {}
    for blob, is_hashed in ((raw, False), (hashed, True)):
        for item in filter(None, (p.strip() for p in blob.split(","))):
            org, sep, secret = item.partition(":")
            if not sep or not org or not secret:
                raise ValueError("API key entries must look like org_id:value")
            digest = secret.lower() if is_hashed else hash_key(secret)
            if is_hashed and len(digest) != 64:
                raise ValueError("LLMGW_API_KEY_SHA256 values must be 64-char sha256 hex digests")
            out.setdefault(org, set()).add(digest)
    return out
