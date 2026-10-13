"""Billing periods are calendar months in UTC, keyed ``YYYY-MM``. Rollover is implicit."""

from __future__ import annotations

import re
from datetime import datetime, timezone

_PERIOD_RE = re.compile(r"^\d{4}-(0[1-9]|1[0-2])$")


def period_for(ts: float) -> str:
    return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m")


def validate_period(period: str) -> str:
    if not _PERIOD_RE.match(period):
        raise ValueError("period must look like YYYY-MM")
    return period
