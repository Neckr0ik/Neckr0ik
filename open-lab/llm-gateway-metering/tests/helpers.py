from llm_gateway_metering import CompletionRequest


def req(prompt: str = "hello there", *, org: str = "acme", user: str = "alice", feature: str = "chat",
        max_tokens: int | None = None, system: str | None = None) -> CompletionRequest:
    return CompletionRequest(org_id=org, user_id=user, feature=feature,
                             messages=[{"role": "user", "content": prompt}], max_tokens=max_tokens, system=system)
