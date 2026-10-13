"""Metering stores. SQLite is the default; PostgreSQL is an optional adapter."""

from .base import MeteringStore, Reservation, UsageRecord
from .sqlite import SQLiteStore

__all__ = ["MeteringStore", "Reservation", "SQLiteStore", "UsageRecord", "open_store"]


def open_store(url_or_path: str) -> MeteringStore:
    """``postgresql://...`` -> PostgresStore (needs the ``postgres`` extra); anything else -> SQLite path."""
    if url_or_path.startswith(("postgres://", "postgresql://")):
        from .postgres import PostgresStore

        return PostgresStore(url_or_path)
    return SQLiteStore(url_or_path)
