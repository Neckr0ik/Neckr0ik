"""Append-only, hash-chained forecast registry (JSONL).

Every forecast is written *before* the official figure is released. Each line
holds a sequence number, a UTC timestamp, the hash of the previous line and the
forecast record; its own SHA-256 hash covers all of those fields. Editing,
deleting or reordering any line *before the last one* breaks every later hash.
Every line must also be exactly the canonical JSON of its entry (no duplicate
keys, no extra fields, no reformatting), so a reader can't be shown anything the
hash does not cover.

What this does and does not prove: the chain shows the file is internally
consistent. Removing entries from the *end* (truncation), or replacing the whole
file with a different valid chain, leaves a valid chain behind; both are only
detectable against a head hash and entry count published earlier
(``verify(expected_head=..., expected_n=...)`` / ``ssv verify --head --count``).
The chain cannot by itself prove wall-clock time - the machine's clock is
trusted. To make the timing auditable, publish the head hash and count somewhere
you do not control (a pre-registration on OSF, a public git commit, an e-mail to
the journal editor, or an RFC 3161 timestamp) before the release date.
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

try:  # POSIX advisory locks serialize concurrent appends; Windows falls back to no locking
    import fcntl as _fcntl
except ImportError:  # pragma: no cover - Windows
    _fcntl = None

GENESIS_HASH = "0" * 64
SCHEMA = "ssv-forecast/1"
ENTRY_KEYS = frozenset({"schema", "seq", "timestamp", "prev_hash", "record", "hash"})


class DuplicateKeyError(ValueError):
    pass


def _no_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict:
    out: dict = {}
    for k, v in pairs:
        if k in out:
            raise DuplicateKeyError(f"duplicate key {k!r}")
        out[k] = v
    return out


def _reject_constant(name: str):
    raise ValueError(f"non-finite number {name}")


def strict_loads(line: str) -> Any:
    """``json.loads`` that rejects duplicate keys (at any depth) and NaN/Infinity."""
    return json.loads(line, object_pairs_hook=_no_duplicate_keys, parse_constant=_reject_constant)


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
        # Split on "\n" only: str.splitlines() would also split on U+2028/U+0085, which
        # canonical JSON (ensure_ascii=False) may contain inside strings. A trailing
        # "\r" (CRLF checkout) is tolerated; blank lines are ignored.
        text = self.path.read_text(encoding="utf-8")
        return [ln.rstrip("\r") for ln in text.split("\n") if ln.strip()]

    def entries(self) -> list[dict]:
        return [strict_loads(ln) for ln in self._raw_lines()]

    def verify(self, expected_head: str | None = None, expected_n: int | None = None) -> VerificationReport:
        """Re-compute every hash and check the chain, sequence and clock order.

        ``expected_head`` / ``expected_n`` are a head hash and entry count that were
        published earlier. With both, entry ``expected_n`` (1-based) must carry that
        hash; entries appended later are fine. With only ``expected_head``, some
        entry must carry it; with only ``expected_n``, the file must still hold at
        least that many entries. This is the only way to detect entries removed
        from the end of the file.
        """
        errors: list[str] = []
        prev = GENESIS_HASH
        last_ts: datetime | None = None
        lines = self._raw_lines()
        hashes: list[str] = []
        for i, ln in enumerate(lines):
            try:
                e = strict_loads(ln)
            except DuplicateKeyError as exc:
                errors.append(f"line {i + 1}: {exc} (a reader could see a value the hash does not cover)")
                prev = "invalid"
                hashes.append("invalid")
                continue
            except ValueError as exc:  # JSONDecodeError is a ValueError
                errors.append(f"line {i + 1}: invalid JSON ({getattr(exc, 'msg', exc)})")
                prev = "invalid"
                hashes.append("invalid")
                continue
            if not isinstance(e, dict):
                errors.append(f"line {i + 1}: not a JSON object")
                prev = "invalid"
                hashes.append("invalid")
                continue
            missing = ENTRY_KEYS - set(e)
            if missing:
                errors.append(f"line {i + 1}: missing field(s) {sorted(missing)}")
                prev = "invalid"
                hashes.append("invalid")
                continue
            extra = set(e) - ENTRY_KEYS
            if extra:
                errors.append(f"line {i + 1}: unexpected field(s) {sorted(extra)} not covered by the hash")
            try:
                if canonical_json(e) != ln:
                    errors.append(f"line {i + 1}: line is not in canonical form (re-serialized or edited)")
            except (TypeError, ValueError):
                errors.append(f"line {i + 1}: line is not in canonical form")
            if type(e["seq"]) is not int or e["seq"] != i:
                errors.append(f"line {i + 1}: seq {e['seq']!r} != expected {i}")
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
            hashes.append(e["hash"])
        head = prev if lines else GENESIS_HASH
        n = len(lines)
        if expected_n is not None:
            if expected_n < 0:
                raise ValueError("expected_n must be >= 0")
            if n < expected_n:
                errors.append(f"registry has {n} entries but {expected_n} were published: entries were removed")
            elif expected_head is not None:
                at = GENESIS_HASH if expected_n == 0 else hashes[expected_n - 1]
                if at != expected_head:
                    errors.append(f"entry {expected_n} does not carry the published head hash: "
                                  "the registry was rewritten")
        elif expected_head is not None and expected_head != GENESIS_HASH and expected_head not in hashes:
            errors.append("published head hash not found in the registry: entries were removed or rewritten")
        return VerificationReport(ok=not errors, n_entries=n, head_hash=head, errors=errors)

    def head(self) -> str:
        lines = self._raw_lines()
        return strict_loads(lines[-1])["hash"] if lines else GENESIS_HASH

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
        """Register a forecast. Refuses to write onto a broken chain.

        The file is locked (``fcntl.flock``, POSIX only) from verification to the
        write, so two processes appending at once cannot both chain onto the same
        head. On Windows there is no lock: append from one process at a time.
        """
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
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with open(self.path, "a", encoding="utf-8") as fh:
            if _fcntl is not None:
                _fcntl.flock(fh.fileno(), _fcntl.LOCK_EX)
            try:
                return self._append_locked(fh, target_id, estimate, lower, upper, model=model, method=method,
                                           seed=seed, metadata=metadata)
            finally:
                if _fcntl is not None:
                    _fcntl.flock(fh.fileno(), _fcntl.LOCK_UN)

    def _append_locked(self, fh, target_id, estimate, lower, upper, *, model, method, seed, metadata) -> dict:
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
