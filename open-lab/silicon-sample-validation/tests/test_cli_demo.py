from datetime import datetime, timezone

from silicon_sample_validation import SYNTHETIC_LABEL, ForecastRegistry, make_synthetic_dataset
from silicon_sample_validation.cli import main
from silicon_sample_validation.demo import run_demo


def test_synthetic_dataset_is_labelled_and_reproducible():
    a = make_synthetic_dataset(seed=1)
    assert a == make_synthetic_dataset(seed=1)
    assert all(r["synthetic"] is True and r["unit_id"].startswith("SYNTHETIC-UNIT-") for r in a)
    assert all(r["lower"] <= r["simulated_anchored"] <= r["upper"] for r in a)


def test_demo_runs_offline(tmp_path):
    lines = []
    out = run_demo(tmp_path, out=lines.append)
    text = "\n".join(lines)
    assert text.count(SYNTHETIC_LABEL) >= 2
    assert out["tamper_detected"]
    assert out["probe"].n_flagged == 2
    assert ForecastRegistry(out["registry"]).verify().ok
    assert out["report"].n_units == 28


def test_cli_verify_and_head(tmp_path, capsys):
    reg = ForecastRegistry(tmp_path / "r.jsonl", clock=lambda: datetime(2026, 1, 1, tzinfo=timezone.utc))
    reg.append("t", 1.0)
    assert main(["verify", str(reg.path)]) == 0
    assert "OK: 1 entries" in capsys.readouterr().out
    assert main(["head", str(reg.path)]) == 0
    assert capsys.readouterr().out.strip() == reg.head()
    reg.path.write_text(reg.path.read_text().replace("1.0", "2.0"))
    assert main(["verify", str(reg.path), "--json"]) == 1
