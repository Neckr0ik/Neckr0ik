import json

import pandas as pd

from mx_census_sampler.cli import main

from .conftest import FIXTURE


def test_cli_sample_writes_csv_and_summary(tmp_path, capsys):
    out, js = tmp_path / "s.csv", tmp_path / "s.json"
    rc = main(["sample", "--data", str(FIXTURE), "-n", "20", "--seed", "1",
               "--per-unit", "2", "--out", str(out), "--summary-json", str(js)])
    assert rc == 0
    df = pd.read_csv(out, dtype={"cvegeo": str})
    assert len(df) == 40
    summary = json.loads(js.read_text())
    assert summary["sample"]["respondents"] == 40
    assert "Kish ESS" in capsys.readouterr().out


def test_cli_filters_and_errors(tmp_path, capsys):
    out = tmp_path / "s.csv"
    assert main(["sample", "--data", str(FIXTURE), "-n", "5", "--state", "09", "--out", str(out), "--quiet"]) == 0
    assert set(pd.read_csv(out, dtype={"cve_ent": str})["cve_ent"]) == {"09"}
    assert main(["sample", "--data", str(FIXTURE), "-n", "5", "--state", "31"]) == 2
    assert main(["info", "--data", str(FIXTURE)]) == 0
    assert "metro" in capsys.readouterr().out
