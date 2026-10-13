from __future__ import annotations

import calendar
import io
import logging

import pytest

from llm_gateway_metering import Gateway, GatewayConfig, OrgConfig
from llm_gateway_metering.logging_utils import JsonFormatter, get_logger
from llm_gateway_metering.providers import MockProvider
from llm_gateway_metering.store import SQLiteStore


class FakeClock:
    def __init__(self, t: float):
        self.t = t

    def __call__(self) -> float:
        return self.t

    def advance(self, s: float) -> None:
        self.t += s


def ts(year: int, month: int, day: int = 15, hour: int = 12) -> float:
    return float(calendar.timegm((year, month, day, hour, 0, 0)))


@pytest.fixture
def clock():
    return FakeClock(ts(2026, 3, 15))


@pytest.fixture
def mono():
    return FakeClock(1000.0)


@pytest.fixture
def make_gateway(tmp_path, clock, mono):
    made = []

    def _make(*, limit: float = 10_000, warn_ratio: float = 0.8, provider=None, store=None, **cfg_kw):
        cfg_kw.setdefault("org_rate", None)
        cfg_kw.setdefault("user_rate", None)
        cfg = GatewayConfig(provider="mock", db_path=str(tmp_path / "meter.db"),
                            default_org=OrgConfig(monthly_limit=limit, warn_ratio=warn_ratio), **cfg_kw)
        gw = Gateway(cfg, provider=provider or MockProvider(), store=store or SQLiteStore(cfg.db_path),
                     clock=clock, monotonic=mono, sleep=lambda s: None)
        made.append(gw)
        return gw

    yield _make
    for gw in made:
        gw.close()


@pytest.fixture
def log_capture():
    buf = io.StringIO()
    handler = logging.StreamHandler(buf)
    handler.setFormatter(JsonFormatter())
    logger = get_logger()
    logger.addHandler(handler)
    old = logger.level
    logger.setLevel(logging.DEBUG)
    yield buf
    logger.removeHandler(handler)
    logger.setLevel(old)
