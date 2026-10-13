"""End-to-end on SYNTHETIC microdata (random values, not INEGI data)."""

import numpy as np
import pandas as pd
import pytest

from endutih_media_profiles import profile
from endutih_media_profiles.cli import main
from endutih_media_profiles.indicators import HOUSEHOLD_INDICATORS, PERSON_INDICATORS

from .synthetic import make_frames


def test_tables_shape(synthetic_tables):
    p = pd.read_csv(synthetic_tables / "endutih2025_persons.csv", dtype={"state": str})
    h = pd.read_csv(synthetic_tables / "endutih2025_households.csv", dtype={"state": str})
    assert set(p["state"]) == {"all", "01", "09"}
    assert set(p["age"]) <= {"all", "6-11", "12-17", "18-29", "30-44", "45-59", "60+", "18+"}
    for i in PERSON_INDICATORS:
        assert i.key in p.columns and f"{i.key}_se" in p.columns
    for i in HOUSEHOLD_INDICATORS:
        assert i.key in h.columns
    assert (p.loc[p["n"] < 30, ["internet_user", "pop"]].isna()).all().all()
    assert p.loc[p["n"] >= 30, "internet_user"].notna().all()
    assert (synthetic_tables / "PROVENANCE.md").is_file()


def test_national_share_equals_weighted_mean(synthetic_tables):
    u, u2, h = make_frames()
    w = u["FAC_PER"].astype(float)
    expected = (w * (u["P7_1"] == "1")).sum() / w.sum()
    row = profile(directory=synthetic_tables).set_index("indicator").loc["internet_user"]
    assert row["share"] == pytest.approx(expected, abs=5e-5)
    # gated item: share of ALL persons, non-internet users count as 0
    exp_fb = (w * (u["P7_16_1"] == "1")).sum() / w.sum()
    fb = profile(directory=synthetic_tables).set_index("indicator").loc["facebook"]
    assert fb["share"] == pytest.approx(exp_fb, abs=5e-5)
    # 'no sabe' (9) excluded from the denominator
    ok = u["P7_13_6"] != "9"
    exp_r = (w[ok] * (u.loc[ok, "P7_13_6"] == "1")).sum() / w[ok].sum()
    r = profile(directory=synthetic_tables).set_index("indicator").loc["online_radio"]
    assert r["share"] == pytest.approx(exp_r, abs=5e-5) and r["n"] == ok.sum()


def test_profile_filters_and_errors(synthetic_tables):
    df = profile(state="9", sex="female", age="18+", directory=synthetic_tables)
    assert df.attrs["cell"] == {"state": "09", "sex": "female", "age": "18+", "area": "all"}
    assert "national_share" in df.columns
    hh = profile(state="01", area="urban", table="households", directory=synthetic_tables)
    assert set(hh["indicator"]) == {i.key for i in HOUSEHOLD_INDICATORS}
    with pytest.raises(ValueError):
        profile(state="40", directory=synthetic_tables)
    with pytest.raises(ValueError):
        profile(age="20-25", directory=synthetic_tables)
    with pytest.raises(ValueError):
        profile(sex="female", table="households", directory=synthetic_tables)


def test_cli(synthetic_tables, capsys):
    assert main(["--state", "09", "--age", "18-29", "--data-dir", str(synthetic_tables)]) == 0
    out = capsys.readouterr().out
    assert "internet_user" in out and "Fuente: INEGI" in out
    assert main(["--format", "json", "--data-dir", str(synthetic_tables), "--indicators", "tiktok"]) == 0
    assert '"tiktok"' in capsys.readouterr().out
    assert main(["--state", "77", "--data-dir", str(synthetic_tables)]) == 2
    assert main(["--list"]) == 0
