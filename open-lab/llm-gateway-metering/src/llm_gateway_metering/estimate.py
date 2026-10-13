"""Pre-flight token estimation used for the hard-cap check.

The reservation is deliberately pessimistic: estimated input + the full ``max_tokens``.
After the call the reservation is replaced by the provider-reported usage.
"""

from __future__ import annotations

import math
from typing import Any, Iterable

CHARS_PER_TOKEN = 4
PER_MESSAGE_OVERHEAD = 4


def _content_chars(content: Any) -> int:
    if isinstance(content, str):
        return len(content)
    if isinstance(content, list):
        total = 0
        for block in content:
            if isinstance(block, dict):
                if isinstance(block.get("text"), str):
                    total += len(block["text"])
                else:
                    total += 1000  # non-text block (image, document): flat conservative guess
            elif isinstance(block, str):
                total += len(block)
        return total
    return len(str(content))


def estimate_input_tokens(messages: Iterable[dict[str, Any]], system: str | None = None) -> int:
    chars = len(system or "")
    n = 0
    for m in messages:
        chars += _content_chars(m.get("content", ""))
        n += 1
    return math.ceil(chars / CHARS_PER_TOKEN) + PER_MESSAGE_OVERHEAD * n
