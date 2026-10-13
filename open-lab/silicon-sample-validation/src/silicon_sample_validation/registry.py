"""Append-only, hash-chained forecast registry (JSONL).

Every forecast is written *before* the official figure is released. Each line
holds a sequence number, a UTC timestamp, the hash of the previous line and the
forecast record; its own SHA-256 hash covers all of those fields. Editing,
deleting or reordering any earlier line breaks every later hash.

What this does and does not prove: the chain shows the file is internally
consistent and has not been edited after the fact *relative to a published
head hash*. It cannot by itself prove wall-clock time - the machine's clock is
trusted. To make the timing auditable, publish the head hash somewhere you do
not control (a pre-registration on OSF, a public git commit, an e-mail to the
journal editor, or an RFC 3161 timestamp) before the release date.
"""

from __future__ import annotations

import hashlib
import json
import math
import os
from dataclasses import dataclass, field
from datetime import date, datetime, timezone
from pathlib import Path
from typing import Any, Callable, Mapping

GENESIS_HASH = "0" * 64
SCHEMA = "ssv-forecast/1"


def canonical_json(obj: Any) -> str:
    """Deterministic JSON used for hashing (sorted keys, no spaces, no NaN)."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)


def entry_hash(entry: Mapping) -> str:
    body = {k: entry[k] for k in ("schema", "seq", "timestamp", "prev_hash", "record")}
    return hashlib.sha256(canonical_json(body).encode("utf-8")).hexdigest()


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _iso(dt: datetime) -> str:
    if dt.tzinfo is None:
        raise ValueError("timestamps must be timezone-aware")
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def parse_time(value: str | date | datetime) -> datetime:
    """Parse an ISO date/datetime. A bare date means 00:00 UTC of that day."""
    if isinstance(value, datetime):
        if value.tzinfo is None:
            raise ValueError("datetime must be timezone-aware")
        return value.astimezone(timezone.utc)
    if isinstance(value, date):
        return datetime(value.year, value.month, value.day, tzinfo=timezone.utc)
    s = str(value).strip()
    if len(s) == 10:
        d = date.fromisoformat(s)
        return datetime(d.year, d.month, d.day, tzinfo=timezone.utc)
    dt = datetime.fromisoformat(s.replace("Z", "+00:00"))
    if dt.tzinfo is None:
        raise ValueError(f"timestamp without timezone: {s!r}")
    return dt.astimezone(timezone.utc)


@dataclass
class VerificationReport:
    ok: bool
    n_entries: int
    head_hash: str
    errors: list[str] = field(default_factory=list)


class RegistryError(RuntimeError):
    pass


class ForecastRegistry:
    """Append-only JSONL forecast registry with SHA-256 hash chaining.

    >>> reg = ForecastRegistry("forecasts.jsonl")          # doctest: +SKIP
    >>> reg.append("ENIGH-2026:state-09:poverty", 31.4,
    ...            lower=27.0, upper=35.8, model="claude-haiku-5-5")  # doctest: +SKIP
    >>> reg.verify().ok                                     # doctest: +SKIP
    True
    """

    def __init__(self, path: str | Path, clock: Callable[[], datetime] | None = None):
        self.path = Path(path)
        self._clock = clock or _utc_now

    # -- reading ---------------------------------------------------------
    def _raw_lines(self) -> list[str]:
        if not self.path.exists():
            return []
        return [ln for ln in self.path.read_text(encoding="utf-8").splitlines() if ln.strip()]

    def entries(self) -> list[dict]:
        return [json.loads(ln) for ln in self._raw_lines()]

    def verify(self) -> VerificationReport:
        """Re-compute every hash and check the chain, sequence and clock order."""
        errors: list[str] = []
        prev = GENESIS_HASH
        last_ts: datetime | None = None
        lines = self._raw_lines()
        for i, ln in enumerate(lines):
            try:
                e = json.loads(ln)
            except json.JSONDecodeError as exc:
                errors.append(f"line {i + 1}: invalid JSON ({exc.msg})")
                prev = "invalid"
                continue
            missing = {"schema", "seq", "timestamp", "prev_hash", "record", "hash"} - set(e)
            if missing:
                errors.append(f"line {i + 1}: missing field(s) {sorted(missing)}")
                prev = "invalid"
                continue
            if e["seq"] != i:
                errors.append(f"line {i + 1}: seq {e['seq']} != expected {i}")
            if e["prev_hash"] != prev:
                errors.append(f"line {i + 1}: prev_hash does not match previous entry")
            try:
                h = entry_hash(e)
            except (TypeError, ValueError) as exc:
                errors.append(f"line {i + 1}: cannot hash ({exc})")
                h = "invalid"
            if h != e["hash"]:
                errors.append(f"line {i + 1}: hash mismatch (entry was modified)")
            try:
                ts = parse_time(e["timestamp"])
                if last_ts is not None and ts < last_ts:
                    errors.append(f"line {i + 1}: timestamp earlier than previous entry")
                last_ts = ts
            except ValueError:
                errors.append(f"line {i + 1}: bad timestamp")
            prev = e["hash"]
        head = prev if lines else GENESIS_HASH
        return VerificationReport(ok=not errors, n_entries=len(lines), head_hash=head, errors=errors)

    def head(self) -> str:
        lines = self._raw_lines()
        return json.loads(lines[-1])["hash"] if lines else GENESIS_HASH

    # -- writing ---------------------------------------------------------
    def append(
        self,
        target_id: str,
        estimate: float,
        lower: float | None = None,
        upper: float | None = None,
        *,
        model: str | None = None,
        method: str | None = None,
        seed: int | None = None,
        metadata: Mapping[str, Any] | None = None,
    ) -> dict:
        """Register a forecast. Refuses to write onto a broken chain."""
        if not target_id:
            raise ValueError("target_id is required")
        for name, v in (("estimate", estimate), ("lower", lower), ("upper", upper)):
            if v is not None and not math.isfinite(float(v)):
                raise ValueError(f"{name} must be finite")
        if lower is not None and upper is not None and float(lower) > float(upper):
            raise ValueError("lower > upper")
        if (lower is not None and float(estimate) < float(lower)) or (
            upper is not None and float(estimate) > float(upper)
        ):
            raise ValueError("estimate outside its interval")
        rep = self.verify()
        if not rep.ok:
            raise RegistryError("registry failed verification; refusing to append: " + "; ".join(rep.errors))
        now = self._clock()
        if rep.n_entries:
            last = parse_time(self.entries()[-1]["timestamp"])
            if now < last:
                raise RegistryError("clock is earlier than the last entry")
        record: dict[str, Any] = {"target_id": str(target_id), "estimate": float(estimate)}
        if lower is not None:
            record["lower"] = float(lower)
        if upper is not None:
            record["upper"] = float(upper)
        if model is not None:
            record["model"] = model
        if method is not None:
            record["method"] = method
        if seed is not None:
            record["seed"] = int(seed)
        if metadata:
            record["metadata"] = dict(metadata)
        entry = {
            "schema": SCHEMA,
            "seq": rep.n_entries,
            "timestamp": _iso(now),
            "prev_hash": rep.head_hash,
            "record": record,
        }
        entry["hash"] = entry_hash(entry)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with open(self.path, "a", encoding="utf-8") as fh:
            fh.write(canonical_json(entry) + "\n")
            fh.flush()
            os.fsync(fh.fileno())
        return entry

    # -- querying --------------------------------------------------------
    def latest_before(self, target_id: str, release: str | date | datetime) -> dict | None:
        """Last forecast for ``target_id`` registered strictly before ``release``."""
        cutoff = parse_time(release)
        best = None
        for e in self.entries():
            if e["record"]["target_id"] == target_id and parse_time(e["timestamp"]) < cutoff:
                best = e
        return best

    def preregistered(self, releases: Mapping[str, str | date | datetime]) -> dict[str, dict | None]:
        """Map each target to its last pre-release forecast (None if there is none).

        Raises RegistryError if the chain does not verify: scores must never be
        computed from a registry that may have been edited.
        """
        rep = self.verify()
        if not rep.ok:
            raise RegistryError("registry failed verification: " + "; ".join(rep.errors))
        return {t: self.latest_before(t, r) for t, r in releases.items()}
