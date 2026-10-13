"""CSV loading (stdlib only)."""

from __future__ import annotations

import csv
from pathlib import Path


def read_csv(path: str | Path, delimiter: str | None = None) -> list[dict]:
    """Read a CSV into a list of dicts (values stay strings).

    The delimiter is sniffed among ``,;\\t|`` unless given. A UTF-8 BOM is
    accepted. The file is opened with ``newline=""`` as the ``csv`` module
    requires, so quoted fields may contain line breaks.
    """
    with open(path, newline="", encoding="utf-8-sig") as fh:
        if delimiter is None:
            sample = fh.read(4096)
            fh.seek(0)
            try:
                delimiter = csv.Sniffer().sniff(sample, delimiters=",;\t|").delimiter
            except csv.Error:
                delimiter = ","
        reader = csv.DictReader(fh, delimiter=delimiter)
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
