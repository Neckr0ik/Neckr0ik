"""llm-gateway-metering: a small multi-provider LLM gateway with per-org metering."""

from .config import FeatureConfig, GatewayConfig, ModelRate, OrgConfig
from .errors import (
    AuthError,
    GatewayError,
    InvalidRequest,
    ProviderError,
    ProviderTimeout,
    QuotaExceeded,
    RateLimited,
)
from .gateway import Gateway, GatewayResponse
from .types import CompletionRequest, ProviderResponse

__all__ = [
    "AuthError",
    "CompletionRequest",
    "FeatureConfig",
    "Gateway",
    "GatewayConfig",
    "GatewayError",
    "GatewayResponse",
    "InvalidRequest",
    "ModelRate",
    "OrgConfig",
    "ProviderError",
    "ProviderResponse",
    "ProviderTimeout",
    "QuotaExceeded",
    "RateLimited",
]

__version__ = "0.1.0"
