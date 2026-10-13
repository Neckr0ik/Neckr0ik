"""Pre-flight token estimation used for the hard-cap check.

The reservation is deliberately pessimistic: estimated input + the full ``max_tokens``.
After the call the reservation is replaced by the provider-reported usage.

Text is estimated as ``max(characters / 4, UTF-8 bytes / 3)`` tokens, so scripts that
tokenize densely (CJK, emoji, many accented letters) are not undercounted the way a flat
4-characters-per-token rule undercounts them. Every string inside a content block is
counted (``text``, ``source.data`` of text and base64 documents, nested ``content`` of
tool results, tool-use ``input``), not only top-level ``text``. Images are a flat guess
because their token cost depends on pixel size, not on payload length.
"""

from __future__ import annotations

import json
import math
from typing import Any, Iterable

CHARS_PER_TOKEN = 4
BYTES_PER_TOKEN = 3
PER_MESSAGE_OVERHEAD = 4
IMAGE_TOKENS = 1600  # flat guess per image block (cost depends on pixel size, not bytes)
UNSIZED_SOURCE_TOKENS = 1600  # flat guess for URL / file-id sources whose size is unknown

# Keys whose values are protocol metadata rather than text the model reads.
_SKIP_KEYS = frozenset({"type", "media_type", "cache_control", "id", "tool_use_id", "signature"})


class _Counter:
    __slots__ = ("chars", "bytes", "flat")

    def __init__(self) -> None:
        self.chars = 0
        self.bytes = 0
        self.flat = 0  # tokens added directly (images, unsized sources)

    def text(self, s: str) -> None:
        self.chars += len(s)
        self.bytes += len(s.encode("utf-8", "surrogatepass"))

    def tokens(self) -> int:
        return math.ceil(max(self.chars / CHARS_PER_TOKEN, self.bytes / BYTES_PER_TOKEN)) + self.flat


def _walk(value: Any, c: _Counter) -> None:
    if isinstance(value, str):
        c.text(value)
    elif isinstance(value, dict):
        btype = value.get("type")
        if btype == "image":
            c.flat += IMAGE_TOKENS
            return
        source = value.get("source")
        if isinstance(source, dict) and source.get("type") in ("url", "file") and not isinstance(
                source.get("data"), (str, list)):
            c.flat += UNSIZED_SOURCE_TOKENS
        for key, v in value.items():
            if key in _SKIP_KEYS:
                continue
            if key == "input" and btype == "tool_use" and not isinstance(v, str):
                c.text(json.dumps(v, ensure_ascii=False, default=str))
                continue
            _walk(v, c)
    elif isinstance(value, (list, tuple)):
        for item in value:
            _walk(item, c)
    elif value is not None and not isinstance(value, bool):
        c.text(str(value))


def estimate_input_tokens(messages: Iterable[dict[str, Any]], system: str | None = None) -> int:
    c = _Counter()
    c.text(system or "")
    n = 0
    for m in messages:
        _walk(m.get("content", ""), c)
        n += 1
    return c.tokens() + PER_MESSAGE_OVERHEAD * n
