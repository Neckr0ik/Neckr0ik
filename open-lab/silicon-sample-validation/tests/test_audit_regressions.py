"""Regression tests from the adversarial audit: registry tampering that the hash alone
did not catch, verdicts on too few units, and multi-number probe answers."""

import json
import multiprocessing
from datetime import datetime, timedelta, timezone

import numpy as np
import pytest

from silicon_sample_validation import ForecastRegistry, compare_to_baselines, parse_numeric_answer
from silicon_sample_validation.cli import main
from silicon_sample_validation.compare import NOT_EVALUABLE_DEGENERATE, NOT_EVALUABLE_FEW


class Clock:
    def __init__(self):
        self.t = datetime(2026, 1, 1, tzinfo=timezone.utc)

    def __call__(self):
        self.t += timedelta(hours=1)
        return self.t


@pytest.fixture
def reg3(tmp_path):
    reg = ForecastRegistry(tmp_path / "r.jsonl", clock=Clock())
    reg.append("T1", 10.0, 8, 12)
    reg.append("T1", 30.0, 25, 35)
    reg.append("T2", 5.0)
    return reg, reg.path.read_text(encoding="utf-8").splitlines()


def _write(reg, lines):
    reg.path.write_text("\n".join(lines) + "\n", encoding="utf-8")


# -- registry --------------------------------------------------------------------------------------

def test_extra_unhashed_field_is_rejected(reg3):
    reg, lines = reg3
    e = json.loads(lines[1])
    e["withdrawn"] = True
    _write(reg, [lines[0], json.dumps(e, sort_keys=True, separators=(",", ":")), lines[2]])
    rep = reg.verify()
    assert not rep.ok and any("unexpected field" in x for x in rep.errors)


def test_duplicate_key_is_rejected(reg3):
    reg, lines = reg3
    fake = lines[1].replace('{"hash"', '{"record":{"estimate":99.0,"target_id":"T1"},"hash"', 1)
    _write(reg, [lines[0], fake, lines[2]])
    rep = reg.verify()
    assert not rep.ok and any("duplicate key 'record'" in x for x in rep.errors)
    nested = lines[1].replace('"estimate":30.0', '"estimate":30.0,"estimate":99.0', 1)
    _write(reg, [lines[0], nested, lines[2]])
    assert not reg.verify().ok


def test_non_canonical_line_is_rejected(reg3):
    reg, lines = reg3
    e = json.loads(lines[1])
    _write(reg, [lines[0], json.dumps(e), lines[2]])  # same content, different serialization
    rep = reg.verify()
    assert not rep.ok and any("canonical" in x for x in rep.errors)
    e["seq"] = True  # True == 1 in Python
    _write(reg, [lines[0], json.dumps(e, sort_keys=True, separators=(",", ":")), lines[2]])
    assert not reg.verify().ok


def test_crlf_and_line_separator_characters_are_tolerated(tmp_path):
    reg = ForecastRegistry(tmp_path / "r.jsonl", clock=Clock())
    reg.append("T1", 1.0, metadata={"note": "a b\u0085c"})  # valid in canonical JSON strings
    reg.append("T2", 2.0)
    assert reg.verify().ok
    reg.path.write_bytes(reg.path.read_bytes().replace(b"\n", b"\r\n"))
    assert reg.verify().ok and reg.verify().n_entries == 2


def test_truncation_detected_only_against_published_head_and_count(reg3):
    reg, lines = reg3
    published_head, published_n = reg.head(), 3
    _write(reg, lines[:-1])  # drop the last (unfavourable) forecast
    assert reg.verify().ok  # the chain alone cannot tell
    rep = reg.verify(expected_head=published_head, expected_n=published_n)
    assert not rep.ok and any("removed" in x for x in rep.errors)
    assert not reg.verify(expected_head=published_head).ok
    assert not reg.verify(expected_n=published_n).ok


def test_published_head_allows_later_appends_but_not_rewrites(reg3, tmp_path):
    reg, lines = reg3
    head2 = json.loads(lines[1])["hash"]
    assert reg.verify(expected_head=head2, expected_n=2).ok  # one entry appended after publication
    assert not reg.verify(expected_head=head2, expected_n=3).ok
    other = ForecastRegistry(tmp_path / "other.jsonl", clock=Clock())
    other.append("T1", 99.0)
    other.append("T1", 98.0)
    assert other.verify().ok and not other.verify(expected_head=head2, expected_n=2).ok


def test_cli_verify_with_published_head_and_count(reg3, capsys):
    reg, lines = reg3
    assert main(["head", str(reg.path), "--count"]) == 0
    head, n = capsys.readouterr().out.split()
    assert n == "3" and head == reg.head()
    assert main(["verify", str(reg.path), "--head", head, "--count", n]) == 0
    _write(reg, lines[:-1])
    assert main(["verify", str(reg.path)]) == 0
    capsys.readouterr()
    assert main(["verify", str(reg.path), "--head", head, "--count", n]) == 1
    assert "were removed" in capsys.readouterr().out


def _append_many(path, worker, k):
    reg = ForecastRegistry(path)
    for i in range(k):
        reg.append(f"w{worker}-{i}", float(i))


@pytest.mark.skipif(not hasattr(__import__("os"), "fork"), reason="needs fork")
def test_concurrent_appends_from_processes_keep_the_chain_valid(tmp_path):
    path = tmp_path / "shared.jsonl"
    ctx = multiprocessing.get_context("fork")
    procs = [ctx.Process(target=_append_many, args=(path, w, 15)) for w in range(4)]
    for p in procs:
        p.start()
    for p in procs:
        p.join(30)
    assert all(p.exitcode == 0 for p in procs)
    rep = ForecastRegistry(path).verify()
    assert rep.ok, rep.errors[:3]
    assert rep.n_entries == 60


# -- baselines verdict -----------------------------------------------------------------------------

def test_too_few_units_is_not_evaluable():
    y = np.arange(9, dtype=float)
    r = compare_to_baselines(y, y + 0.1, {"flat": np.full(9, 4.0)}, n_boot=200)
    assert r.verdict == NOT_EVALUABLE_FEW and not r.beats_all_baselines
    assert any("minimum 10" in n for n in r.notes)


def test_zero_bootstrap_spread_is_not_evaluable():
    y = np.arange(12, dtype=float)
    r = compare_to_baselines(y, y + 1.0, {"shifted": y + 3.0}, n_boot=200)  # every unit: |1| - |3| = -2
    assert r.vs_baselines["shifted"].boot_sd == 0
    assert r.verdict == NOT_EVALUABLE_DEGENERATE and not r.beats_all_baselines


# -- probe parser ----------------------------------------------------------------------------------

@pytest.mark.parametrize("text,value", [
    ("In 2020, 45.3%", 45.3),
    ("45.3% (2020)", 45.3),
    ("Según la ENIGH 2024: 31,5", 31.5),
    ("The value was 12 in 2022", 12.0),
    ("2020", 2020.0),  # a lone year-like number is still a number
    ("0,125", 0.125),
    ("1 234,5", 1234.5),
    ("1.234.567", 1234567.0),
    ("In 2021 there were 3 surveys; the rate was 27.5 percent", 27.5),
    ("31.4 por ciento en 2024", 31.4),
])
def test_parse_prefers_percent_and_skips_years(text, value):
    assert parse_numeric_answer(text) == value


def test_parse_prefers_number_next_to_the_unit():
    assert parse_numeric_answer("In 2023, 3 states averaged 1,200 pesos", unit="pesos") == 1200.0
