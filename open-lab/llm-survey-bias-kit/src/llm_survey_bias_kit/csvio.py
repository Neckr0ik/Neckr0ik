"""CSV loading (stdlib only)."""

from __future__ import annotations

import csv
from pathlib import Path


def read_csv(path: str | Path, delimiter: str | None = None) -> list[dict]:
    """Read a CSV into a list of dicts (values stay strings).

    The delimiter is sniffed among ``,;\\t|`` unless given. A UTF-8 BOM is
    accepted.
    """
    text = Path(path).read_text(encoding="utf-8-sig")
    if delimiter is None:
        try:
            delimiter = csv.Sniffer().sniff(text[:4096], delimiters=",;\t|").delimiter
        except csv.Error:
            delimiter = ","
    reader = csv.DictReader(text.splitlines(), delimiter=delimiter)
    rows = [dict(r) for r in reader]
    if reader.fieldnames is None:
        raise ValueError(f"{path}: empty CSV")
    return rows


def require_columns(rows: list[dict], columns: list[str], path: str = "CSV") -> None:
    if not rows:
        raise ValueError(f"{path}: no data rows")
    missing = [c for c in columns if c not in rows[0]]
    if missing:
        raise ValueError(f"{path}: missing column(s) {missing}; found {list(rows[0])}")
