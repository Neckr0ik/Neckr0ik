import hashlib
import json
from datetime import datetime, timedelta, timezone

import pytest

from silicon_sample_validation import GENESIS_HASH, ForecastRegistry, RegistryError
from silicon_sample_validation.registry import canonical_json, entry_hash, parse_time


class Clock:
    def __init__(self, start=datetime(2026, 11, 1, tzinfo=timezone.utc)):
        self.t = start

    def __call__(self):
        self.t += timedelta(minutes=1)
        return self.t


@pytest.fixture
def reg(tmp_path):
    return ForecastRegistry(tmp_path / "f.jsonl", clock=Clock())


def test_empty_registry(reg):
    rep = reg.verify()
    assert rep.ok and rep.n_entries == 0 and rep.head_hash == GENESIS_HASH
    assert reg.head() == GENESIS_HASH


def test_append_chain_and_hash_is_sha256_of_canonical_body(reg):
    e1 = reg.append("t1", 10.0, 8.0, 12.0, model="m", seed=1, metadata={"note": "ñ"})
    e2 = reg.append("t2", 20.0)
    assert e1["seq"] == 0 and e1["prev_hash"] == GENESIS_HASH
    assert e2["prev_hash"] == e1["hash"]
    body = {k: e1[k] for k in ("schema", "seq", "timestamp", "prev_hash", "record")}
    expected = hashlib.sha256(
        json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
    ).hexdigest()
    assert e1["hash"] == expected == entry_hash(e1)
    assert e1["timestamp"].endswith("Z")
    rep = reg.verify()
    assert rep.ok and rep.n_entries == 2 and rep.head_hash == e2["hash"] == reg.head()


def test_known_hash_is_stable():
    entry = {"schema": "ssv-forecast/1", "seq": 0, "timestamp": "2026-01-01T00:00:00.000000Z",
             "prev_hash": GENESIS_HASH, "record": {"target_id": "x", "estimate": 1.0}}
    s = canonical_json({k: entry[k] for k in ("schema", "seq", "timestamp", "prev_hash", "record")})
    assert s.startswith('{"prev_hash":"000')
    assert entry_hash(entry) == hashlib.sha256(s.encode()).hexdigest()


def _rewrite(path, fn):
    lines = path.read_text().splitlines()
    lines = fn(lines)
    path.write_text("\n".join(lines) + "\n")


def test_detects_modified_value(reg):
    for i in range(4):
        reg.append(f"t{i}", float(i))
    _rewrite(reg.path, lambda ls: [ls[0], ls[1].replace('"estimate":1.0', '"estimate":1.5'), *ls[2:]])
    rep = reg.verify()
    assert not rep.ok
    assert any("line 2: hash mismatch" in e for e in rep.errors)


def test_detects_rehashed_edit_via_chain(reg):
    for i in range(3):
        reg.append(f"t{i}", float(i))
    # attacker edits line 1 AND recomputes its hash: line 2's prev_hash breaks
    def edit(ls):
        e = json.loads(ls[0])
        e["record"]["estimate"] = 99.0
        e["hash"] = entry_hash(e)
        return [canonical_json(e)] + ls[1:]
    _rewrite(reg.path, edit)
    rep = reg.verify()
    assert not rep.ok
    assert any("line 2: prev_hash" in e for e in rep.errors)


def test_detects_deletion_and_reordering(reg, tmp_path):
    for i in range(3):
        reg.append(f"t{i}", float(i))
    _rewrite(reg.path, lambda ls: [ls[0], ls[2]])
    assert not reg.verify().ok
    reg2 = ForecastRegistry(tmp_path / "g.jsonl", clock=Clock())
    for i in range(3):
        reg2.append(f"t{i}", float(i))
    _rewrite(reg2.path, lambda ls: [ls[1], ls[0], ls[2]])
    assert any("seq" in e for e in reg2.verify().errors)


def test_truncating_tail_changes_head(reg):
    for i in range(3):
        reg.append(f"t{i}", float(i))
    published_head = reg.head()
    _rewrite(reg.path, lambda ls: ls[:2])
    rep = reg.verify()
    assert rep.ok  # internally consistent...
    assert rep.head_hash != published_head  # ...but no longer matches the published head


def test_invalid_json_line(reg):
    reg.append("t0", 1.0)
    with open(reg.path, "a") as fh:
        fh.write("{not json\n")
    rep = reg.verify()
    assert not rep.ok and "invalid JSON" in rep.errors[0]


def test_refuses_to_append_to_broken_chain(reg):
    reg.append("t0", 1.0)
    reg.append("t1", 2.0)
    _rewrite(reg.path, lambda ls: [ls[0].replace("1.0", "3.0"), ls[1]])
    with pytest.raises(RegistryError):
        reg.append("t2", 3.0)


def test_rejects_backwards_clock(tmp_path):
    times = iter([datetime(2026, 5, 2, tzinfo=timezone.utc), datetime(2026, 5, 1, tzinfo=timezone.utc)])
    reg = ForecastRegistry(tmp_path / "f.jsonl", clock=lambda: next(times))
    reg.append("t", 1.0)
    with pytest.raises(RegistryError):
        reg.append("t", 2.0)


@pytest.mark.parametrize(
    "kwargs",
    [
        {"target_id": "", "estimate": 1.0},
        {"target_id": "t", "estimate": float("nan")},
        {"target_id": "t", "estimate": 1.0, "lower": 2.0, "upper": 1.0},
        {"target_id": "t", "estimate": 5.0, "lower": 1.0, "upper": 2.0},
        {"target_id": "t", "estimate": 0.0, "lower": 1.0},
    ],
)
def test_validation(reg, kwargs):
    with pytest.raises(ValueError):
        reg.append(**kwargs)


def test_latest_before_release(reg):
    reg.append("t", 1.0)   # 00:01
    reg.append("t", 2.0)   # 00:02
    reg.append("t", 3.0)   # 00:03
    assert reg.latest_before("t", "2026-11-01T00:02:30Z")["record"]["estimate"] == 2.0
    assert reg.latest_before("t", "2026-11-01") is None
    assert reg.latest_before("other", "2027-01-01") is None
    pre = reg.preregistered({"t": "2027-01-01", "u": "2027-01-01"})
    assert pre["t"]["record"]["estimate"] == 3.0 and pre["u"] is None


def test_preregistered_refuses_broken_registry(reg):
    reg.append("t", 1.0)
    _rewrite(reg.path, lambda ls: [ls[0].replace("1.0", "2.0")])
    with pytest.raises(RegistryError):
        reg.preregistered({"t": "2027-01-01"})


def test_parse_time():
    assert parse_time("2026-03-01") == datetime(2026, 3, 1, tzinfo=timezone.utc)
    assert parse_time("2026-03-01T10:00:00-06:00").hour == 16
    with pytest.raises(ValueError):
        parse_time("2026-03-01T10:00:00")
    with pytest.raises(ValueError):
        parse_time(datetime(2026, 1, 1))
