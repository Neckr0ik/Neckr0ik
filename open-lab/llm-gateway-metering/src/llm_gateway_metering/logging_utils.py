"""Structured JSON logs. Prompts and completions are never passed to the logger.

User ids are hashed by default (they are often e-mails). A redaction filter also
scrubs anything that looks like a credential, as a second line of defence.
"""

from __future__ import annotations

import hashlib
import json
import logging
import re
import sys
import time

LOGGER_NAME = "llm_gateway"
_SECRET_RE = re.compile(r"(sk-ant-[A-Za-z0-9_\-]{6,}|AKIA[0-9A-Z]{12,}|Bearer\s+[A-Za-z0-9._\-]{8,}|ya29\.[A-Za-z0-9._\-]+)")


def redact(text: str) -> str:
    return _SECRET_RE.sub("[REDACTED]", text)


def pseudonymize(value: str, salt: str = "") -> str:
    return "u_" + hashlib.sha256((salt + value).encode("utf-8")).hexdigest()[:16]


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload = {
            "ts": time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(record.created)) + f".{int(record.msecs):03d}Z",
            "level": record.levelname.lower(),
            "event": getattr(record, "event", record.getMessage()),
        }
        fields = getattr(record, "fields", None)
        if isinstance(fields, dict):
            payload.update(fields)
        if record.exc_info and record.exc_info[0] is not None:
            payload["exc_type"] = record.exc_info[0].__name__  # type only: no message, no traceback text
        return redact(json.dumps(payload, default=str, separators=(",", ":")))


def get_logger() -> logging.Logger:
    return logging.getLogger(LOGGER_NAME)


def configure_logging(level: str = "INFO", stream=None) -> logging.Logger:
    logger = get_logger()
    logger.setLevel(level.upper())
    if not any(getattr(h, "_llmgw", False) for h in logger.handlers):
        h = logging.StreamHandler(stream or sys.stderr)
        h.setFormatter(JsonFormatter())
        h._llmgw = True  # type: ignore[attr-defined]
        logger.addHandler(h)
    logger.propagate = False
    return logger


def log_event(event: str, level: int = logging.INFO, **fields) -> None:
    get_logger().log(level, event, extra={"event": event, "fields": fields})
