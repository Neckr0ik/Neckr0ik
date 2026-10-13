"""Run offline with the Mock provider:  python examples/library_usage.py"""

from llm_gateway_metering import CompletionRequest, FeatureConfig, Gateway, GatewayConfig, OrgConfig, QuotaExceeded
from llm_gateway_metering.logging_utils import configure_logging

configure_logging("INFO")
cfg = GatewayConfig(
    provider="mock",
    db_path=":memory:",
    default_org=OrgConfig(monthly_limit=200, warn_ratio=0.8),
    features={"chat": FeatureConfig(max_tokens=32)},
)
gw = Gateway(cfg)
for user in ["alice", "bob", "alice", "carol", "bob", "alice", "dave"]:
    try:
        r = gw.complete(CompletionRequest(org_id="acme", user_id=user, feature="chat",
                                          messages=[{"role": "user", "content": "Write a haiku about quotas"}]))
        print(f"{user}: used={r.quota.used:g}/{r.quota.limit:g} warning={r.quota.warning}")
    except QuotaExceeded as e:
        print(f"{user}: rejected before calling the provider ({e.code})")
print(gw.usage_report("acme")["by_user"])
