import json

import pytest

from llm_survey_bias_kit.cli import main


def write(path, header, rows, sep=","):
    path.write_text(sep.join(header) + "\n" + "\n".join(sep.join(map(str, r)) for r in rows) + "\n", encoding="utf-8")
    return str(path)


@pytest.fixture
def paired_csv(tmp_path):
    rows = []
    for u in range(20):
        for rep in range(3):
            rows.append((u, "A", 6 + (u % 3) + 0.1 * rep, rep))
            rows.append((u, "B", 5 + (u % 3), rep))
    return write(tmp_path / "paired.csv", ["unit_id", "message", "score", "replicate"], rows)


def test_cli_paired_text(paired_csv, capsys):
    assert main(["paired", paired_csv, "--a", "A", "--b", "B"]) == 0
    out = capsys.readouterr().out
    assert "DISTINGUISHABLE" in out and "units=20 replicates=3" in out


def test_cli_paired_json(paired_csv, capsys):
    assert main(["paired", paired_csv, "--a", "A", "--b", "B", "--json"]) == 0
    d = json.loads(capsys.readouterr().out)
    assert d["verdict"] == "distinguishable"
    assert d["diff"] == pytest.approx(1.1)


def test_cli_aa_split(paired_csv, capsys):
    assert main(["aa", paired_csv, "--split", "B", "--json"]) == 0
    out = capsys.readouterr().out
    d = json.loads(out)
    # 3 replicates split 1 + 2: the A/A is not evaluable, so there is no noise floor
    assert d["comparison"]["verdict"] == "not evaluable"
    assert d["noise_floor"] is None and "Infinity" not in out and "NaN" not in out


def test_cli_aa_requires_labels(paired_csv):
    with pytest.raises(SystemExit):
        main(["aa", paired_csv])


def test_cli_order_semicolon_csv(tmp_path, capsys):
    rows = [("forward", "si")] * 40 + [("reversed", "no")] * 40
    p = write(tmp_path / "order.csv", ["direction", "choice"], rows, sep=";")
    assert main(["order", p, "--options", "si,no"]) == 0
    assert "ORDER-SENSITIVE" in capsys.readouterr().out


def test_cli_homogeneity_categorical(tmp_path, capsys):
    sim = write(tmp_path / "sim.csv", ["choice"], [("a",)] * 30)
    ref = write(tmp_path / "ref.csv", ["category", "share"], [("a", 0.5), ("b", 0.5)])
    assert main(["homogeneity", sim, "--reference", ref]) == 0
    assert "TOO HOMOGENEOUS" in capsys.readouterr().out


def test_cli_homogeneity_numeric(tmp_path, capsys):
    sim = write(tmp_path / "sim.csv", ["score"], [(x,) for x in [4, 6] * 10])
    assert main(["homogeneity", sim, "--numeric", "--value-col", "score", "--reference-sd", "3", "--json"]) == 0
    d = json.loads(capsys.readouterr().out)
    assert d["too_homogeneous"] is True


def test_cli_subgroups_strict(tmp_path, capsys):
    rows = [(i, "north") for i in range(12)] + [(100 + i, "south") for i in range(3)]
    p = write(tmp_path / "s.csv", ["unit_id", "region"], rows)
    assert main(["subgroups", p, "--by", "region"]) == 0
    assert main(["subgroups", p, "--by", "region", "--strict"]) == 2
    assert "TOO FEW UNITS" in capsys.readouterr().out


def test_cli_kish(tmp_path, capsys):
    p = write(tmp_path / "w.csv", ["state", "weight"], [("X", 1), ("X", 1), ("X", 1), ("X", 3)])
    assert main(["kish", p, "--by", "state", "--json"]) == 0
    d = json.loads(capsys.readouterr().out)
    assert d["overall"]["effective_n"] == pytest.approx(3.0)


def test_cli_missing_column_is_error(tmp_path, capsys):
    p = write(tmp_path / "x.csv", ["foo"], [(1,)])
    assert main(["kish", p]) == 1
    assert "missing column" in capsys.readouterr().err


def test_cli_order_uses_unit_column_when_present(tmp_path, capsys):
    rows = []
    for u in range(40):
        d = "forward" if u % 2 == 0 else "reversed"
        for _ in range(5):
            rows.append((f"U{u}", d, "si" if u % 4 < 2 else "no"))  # per-unit preference, no order effect
    p = write(tmp_path / "order.csv", ["unit_id", "direction", "choice"], rows)
    assert main(["order", p, "--options", "si,no", "--json"]) == 0
    d = json.loads(capsys.readouterr().out)
    assert d["resampling"] == "unit" and d["n_units_forward"] == 20 and d["n_forward"] == 100
    assert main(["order", p, "--options", "si,no", "--unit-col", "missing"]) == 0
    assert "responses treated as independent" in capsys.readouterr().out


def test_read_csv_handles_quoted_newlines_and_bom(tmp_path):
    from llm_survey_bias_kit.csvio import read_csv

    p = tmp_path / "q.csv"
    p.write_bytes("\ufeffunit_id,comment,score\r\n1,\"line one\r\nline two\",3\r\n2,plain,4\r\n".encode("utf-8"))
    rows = read_csv(p)
    assert [r["unit_id"] for r in rows] == ["1", "2"]
    assert rows[0]["comment"] == "line one\r\nline two" and rows[1]["score"] == "4"
    empty = tmp_path / "e.csv"
    empty.write_text("", encoding="utf-8")
    with pytest.raises(ValueError, match="empty CSV"):
        read_csv(empty)
