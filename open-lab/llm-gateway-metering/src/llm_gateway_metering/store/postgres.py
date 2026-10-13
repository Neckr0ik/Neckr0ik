"""Optional PostgreSQL store (``pip install .[postgres]``). Not exercised by the offline tests.

Atomicity: ``pg_advisory_xact_lock`` on a hash of (org, period) serializes reservations
for the same org-month across all gateway processes; other orgs are not blocked.
"""

from __future__ import annotations

import uuid

from ..errors import QuotaExceeded
from .base import COLUMNS, Reservation, UsageRecord

SCHEMA = """
CREATE TABLE IF NOT EXISTS llmgw_requests (
    id TEXT PRIMARY KEY, org_id TEXT NOT NULL, user_id TEXT NOT NULL, feature TEXT NOT NULL,
    provider TEXT NOT NULL, model TEXT NOT NULL, period TEXT NOT NULL,
    input_tokens BIGINT NOT NULL, output_tokens BIGINT NOT NULL, cost_units DOUBLE PRECISION NOT NULL,
    latency_ms BIGINT NOT NULL, status TEXT NOT NULL, created_at DOUBLE PRECISION NOT NULL,
    cache_creation_input_tokens BIGINT NOT NULL DEFAULT 0, cache_read_input_tokens BIGINT NOT NULL DEFAULT 0,
    stop_reason TEXT, error_type TEXT, attempts INT NOT NULL DEFAULT 1
);
CREATE INDEX IF NOT EXISTS llmgw_requests_org_period ON llmgw_requests(org_id, period);
CREATE TABLE IF NOT EXISTS llmgw_reservations (
    id TEXT PRIMARY KEY, org_id TEXT NOT NULL, period TEXT NOT NULL, units DOUBLE PRECISION NOT NULL,
    created_at DOUBLE PRECISION NOT NULL, expires_at DOUBLE PRECISION NOT NULL
);
CREATE INDEX IF NOT EXISTS llmgw_reservations_org_period ON llmgw_reservations(org_id, period);
CREATE TABLE IF NOT EXISTS llmgw_warnings (
    org_id TEXT NOT NULL, period TEXT NOT NULL, fired_at DOUBLE PRECISION NOT NULL, PRIMARY KEY (org_id, period)
);
"""


class PostgresStore:
    def __init__(self, dsn: str):
        try:
            import psycopg
            from psycopg_pool import ConnectionPool  # type: ignore
        except ImportError:  # pool is optional
            import psycopg  # noqa: F811

            ConnectionPool = None  # type: ignore
        self._psycopg = psycopg
        self._dsn = dsn
        self._pool = ConnectionPool(dsn, open=True) if ConnectionPool else None
        with self._connect() as conn:
            conn.execute(SCHEMA)

    def _connect(self):
        if self._pool is not None:
            return self._pool.connection()
        return self._psycopg.connect(self._dsn)

    @staticmethod
    def _lock(cur, org_id: str, period: str) -> None:
        cur.execute("SELECT pg_advisory_xact_lock(hashtextextended(%s, 0))", (f"{org_id}\x1f{period}",))

    @staticmethod
    def _totals(cur, org_id, period, now):
        cur.execute("SELECT COALESCE(SUM(cost_units),0) FROM llmgw_requests WHERE org_id=%s AND period=%s",
                    (org_id, period))
        used = float(cur.fetchone()[0])
        cur.execute("SELECT COALESCE(SUM(units),0) FROM llmgw_reservations "
                    "WHERE org_id=%s AND period=%s AND expires_at>%s", (org_id, period, now))
        return used, float(cur.fetchone()[0])

    def reserve(self, org_id, period, units, limit, *, now, ttl_s):
        with self._connect() as conn, conn.transaction(), conn.cursor() as cur:
            self._lock(cur, org_id, period)
            cur.execute("DELETE FROM llmgw_reservations WHERE org_id=%s AND expires_at<=%s", (org_id, now))
            used, reserved = self._totals(cur, org_id, period, now)
            # Once a pool is used up (usage can overshoot an estimate), nothing new starts.
            if used >= limit or used + reserved + units > limit:
                raise QuotaExceeded(org_id, period, used, reserved, units, limit)
            rid = uuid.uuid4().hex
            cur.execute("INSERT INTO llmgw_reservations VALUES (%s,%s,%s,%s,%s,%s)",
                        (rid, org_id, period, units, now, now + ttl_s))
        return Reservation(rid, org_id, period, units, used, reserved)

    def _insert(self, cur, record: UsageRecord):
        row = record.as_row()
        cur.execute(f"INSERT INTO llmgw_requests({','.join(COLUMNS)}) VALUES ({','.join(['%s'] * len(COLUMNS))})",
                    tuple(row[k] for k in COLUMNS))

    def settle(self, reservation_id, record):
        with self._connect() as conn, conn.transaction(), conn.cursor() as cur:
            self._lock(cur, record.org_id, record.period)
            cur.execute("DELETE FROM llmgw_reservations WHERE id=%s", (reservation_id,))
            self._insert(cur, record)
            cur.execute("SELECT COALESCE(SUM(cost_units),0) FROM llmgw_requests WHERE org_id=%s AND period=%s",
                        (record.org_id, record.period))
            return float(cur.fetchone()[0])

    def release(self, reservation_id, record=None):
        with self._connect() as conn, conn.transaction(), conn.cursor() as cur:
            cur.execute("DELETE FROM llmgw_reservations WHERE id=%s", (reservation_id,))
            if record is not None:
                self._insert(cur, record)

    def totals(self, org_id, period, *, now):
        with self._connect() as conn, conn.cursor() as cur:
            return self._totals(cur, org_id, period, now)

    def report(self, org_id, period):
        with self._connect() as conn, conn.cursor() as cur:
            def group(col):
                cur.execute(
                    f"SELECT {col}, COUNT(*), COUNT(*) FILTER (WHERE status='ok'), SUM(input_tokens), "
                    "SUM(output_tokens), SUM(cost_units) FROM llmgw_requests WHERE org_id=%s AND period=%s "
                    f"GROUP BY {col} ORDER BY 6 DESC, 1", (org_id, period))
                return [{col: r[0], "requests": r[1], "ok": r[2], "input_tokens": int(r[3] or 0),
                         "output_tokens": int(r[4] or 0), "cost_units": float(r[5] or 0)} for r in cur.fetchall()]

            cur.execute("SELECT COUNT(*), COALESCE(SUM(input_tokens),0), COALESCE(SUM(output_tokens),0), "
                        "COALESCE(SUM(cost_units),0) FROM llmgw_requests WHERE org_id=%s AND period=%s",
                        (org_id, period))
            n, i, o, u = cur.fetchone()
            return {"org_id": org_id, "period": period, "requests": n, "input_tokens": int(i),
                    "output_tokens": int(o), "used": float(u), "by_user": group("user_id"),
                    "by_feature": group("feature"), "by_model": group("model")}

    def mark_warning(self, org_id, period, *, now):
        with self._connect() as conn, conn.transaction(), conn.cursor() as cur:
            cur.execute("INSERT INTO llmgw_warnings VALUES (%s,%s,%s) ON CONFLICT DO NOTHING", (org_id, period, now))
            return cur.rowcount == 1

    def close(self):
        if self._pool is not None:
            self._pool.close()
