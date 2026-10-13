"""Claude on Google Cloud Vertex AI (``pip install .[vertex]``).

Auth is Google Application Default Credentials. Current models use the bare
first-party id (``claude-sonnet-5-5``); dated snapshots use ``name@YYYYMMDD``.
"""

from __future__ import annotations

from ._claude_messages import ClaudeMessagesProvider


class VertexProvider(ClaudeMessagesProvider):
    name = "vertex"

    @classmethod
    def from_config(cls, config) -> "VertexProvider":
        if not config.vertex_project_id:
            raise ValueError("Vertex needs a project: set LLMGW_VERTEX_PROJECT or ANTHROPIC_VERTEX_PROJECT_ID")
        from anthropic import AnthropicVertex

        return cls(AnthropicVertex(project_id=config.vertex_project_id, region=config.vertex_region,
                                   max_retries=0, timeout=config.timeout_s))
