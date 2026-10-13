"""SQLite metering store (stdlib ``sqlite3``).

Atomicity: every quota decision runs inside ``BEGIN IMMEDIATE``, which takes SQLite's
write lock before reading. Two concurrent reservations (threads in one process, or
separate processes sharing the file) are therefore serialized and cannot both pass a cap.
"""

from __future__ import annotations

import sqlite3
import threading
import uuid
from contextlib import contextmanager

from ..errors import QuotaExceeded
from .base import COLUMNS, Reservation, UsageRecord

SCHEMA = """
CREATE TABLE IF NOT EXISTS requests (
    id TEXT PRIMARY KEY,
    org_id TEXT NOT NULL,
    user_id TEXT NOT NULL,
    feature TEXT NOT NULL,
    provider TEXT NOT NULL,
    model TEXT NOT NULL,
    period TEXT NOT NULL,
    input_tokens INTEGER NOT NULL,
    output_tokens INTEGER NOT NULL,
    cost_units REAL NOT NULL,
    latency_ms INTEGER NOT NULL,
    status TEXT NOT NULL,
    created_at REAL NOT NULL,
    cache_creation_input_tokens INTEGER NOT NULL DEFAULT 0,
    cache_read_input_tokens INTEGER NOT NULL DEFAULT 0,
    stop_reason TEXT,
    error_type TEXT,
    attempts INTEGER NOT NULL DEFAULT 1
);
CREATE INDEX IF NOT EXISTS ix_requests_org_period ON requests(org_id, period);
CREATE TABLE IF NOT EXISTS reservations (
    id TEXT PRIMARY KEY,
    org_id TEXT NOT NULL,
    period TEXT NOT NULL,
    units REAL NOT NULL,
    created_at REAL NOT NULL,
    expires_at REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS ix_reservations_org_period ON reservations(org_id, period);
CREATE TABLE IF NOT EXISTS warnings (
    org_id TEXT NOT NULL,
    period TEXT NOT NULL,
    fired_at REAL NOT NULL,
    PRIMARY KEY (org_id, period)
);
"""


class SQLiteStore:
    def __init__(self, path: str = "llm_gateway.db", *, busy_timeout_ms: int = 10_000):
        self.path = path
        self._lock = threading.RLock()
        self._conn = sqlite3.connect(path, isolation_level=None, check_same_thread=False,
                                     timeout=busy_timeout_ms / 1000)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute(f"PRAGMA busy_timeout={int(busy_timeout_ms)}")
        if path != ":memory:":
            self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.executescript(SCHEMA)

    @contextmanager
    def _tx(self):
        with self._lock:
            self._conn.execute("BEGIN IMMEDIATE")
            try:
                yield self._conn
            except BaseException:
                self._conn.execute("ROLLBACK")
                raise
            else:
                self._conn.execute("COMMIT")

    @staticmethod
    def _totals(c: sqlite3.Connection, org_id: str, period: str, now: float) -> tuple[float, float]:
        used = c.execute("SELECT COALESCE(SUM(cost_units),0) FROM requests WHERE org_id=? AND period=?",
                         (org_id, period)).fetchone()[0]
        reserved = c.execute("SELECT COALESCE(SUM(units),0) FROM reservations "
                             "WHERE org_id=? AND period=? AND expires_at>?", (org_id, period, now)).fetchone()[0]
        return float(used), float(reserved)

    def reserve(self, org_id: str, period: str, units: float, limit: float, *, now: float, ttl_s: float) -> Reservation:
        with self._tx() as c:
            c.execute("DELETE FROM reservations WHERE expires_at<=?", (now,))
            used, reserved = self._totals(c, org_id, period, now)
            if used + reserved + units > limit:
                raise QuotaExceeded(org_id, period, used, reserved, units, limit)
            rid = uuid.uuid4().hex
            c.execute("INSERT INTO reservations(id,org_id,period,units,created_at,expires_at) VALUES (?,?,?,?,?,?)",
                      (rid, org_id, period, units, now, now + ttl_s))
        return Reservation(rid, org_id, period, units, used, reserved)

    def _insert(self, c: sqlite3.Connection, record: UsageRecord) -> None:
        cols = ",".join(COLUMNS)
        marks = ",".join("?" for _ in COLUMNS)
        row = record.as_row()
        c.execute(f"INSERT INTO requests({cols}) VALUES ({marks})", tuple(row[k] for k in COLUMNS))

    def settle(self, reservation_id: str, record: UsageRecord) -> float:
        with self._tx() as c:
            c.execute("DELETE FROM reservations WHERE id=?", (reservation_id,))
            self._insert(c, record)
            used = c.execute("SELECT COALESCE(SUM(cost_units),0) FROM requests WHERE org_id=? AND period=?",
                             (record.org_id, record.period)).fetchone()[0]
        return float(used)

    def release(self, reservation_id: str, record: UsageRecord | None = None) -> None:
        with self._tx() as c:
            c.execute("DELETE FROM reservations WHERE id=?", (reservation_id,))
            if record is not None:
                self._insert(c, record)

    def totals(self, org_id: str, period: str, *, now: float) -> tuple[float, float]:
        with self._lock:
            return self._totals(self._conn, org_id, period, now)

    def report(self, org_id: str, period: str) -> dict:
        def group(col: str) -> list[dict]:
            rows = self._conn.execute(
                f"SELECT {col} AS key, COUNT(*) AS requests, SUM(status='ok') AS ok, "
                "SUM(input_tokens) AS input_tokens, SUM(output_tokens) AS output_tokens, "
                "SUM(cost_units) AS cost_units FROM requests WHERE org_id=? AND period=? "
                f"GROUP BY {col} ORDER BY cost_units DESC, key", (org_id, period)).fetchall()
            return [{col: r["key"], "requests": r["requests"], "ok": r["ok"] or 0,
                     "input_tokens": r["input_tokens"] or 0, "output_tokens": r["output_tokens"] or 0,
                     "cost_units": float(r["cost_units"] or 0)} for r in rows]

        with self._lock:
            t = self._conn.execute(
                "SELECT COUNT(*) n, COALESCE(SUM(input_tokens),0) i, COALESCE(SUM(output_tokens),0) o, "
                "COALESCE(SUM(cost_units),0) u FROM requests WHERE org_id=? AND period=?",
                (org_id, period)).fetchone()
            return {
                "org_id": org_id,
                "period": period,
                "requests": t["n"],
                "input_tokens": t["i"],
                "output_tokens": t["o"],
                "used": float(t["u"]),
                "by_user": group("user_id"),
                "by_feature": group("feature"),
                "by_model": group("model"),
            }

    def mark_warning(self, org_id: str, period: str, *, now: float) -> bool:
        with self._tx() as c:
            cur = c.execute("INSERT OR IGNORE INTO warnings(org_id,period,fired_at) VALUES (?,?,?)",
                            (org_id, period, now))
            return cur.rowcount == 1

    def close(self) -> None:
        with self._lock:
            self._conn.close()
