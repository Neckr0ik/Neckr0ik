"""Checks on the committed REAL aggregated tables (no microdata needed).

INEGI's ENDUTIH 2025 results report (16 June 2026) publishes 86.1% internet
users among people 6+, 88.9% urban, 75.2% rural. Our tables, computed
independently from the public microdata, must reproduce these.
"""

import pandas as pd
import pytest

from endutih_media_profiles import profile

from .conftest import REAL_DATA

pytestmark = pytest.mark.skipif(
    not (REAL_DATA / "endutih2025_persons.csv").is_file(), reason="committed tables absent"
)


@pytest.mark.parametrize("area,published", [(None, 0.861), ("urban", 0.889), ("rural", 0.752)])
def test_reproduces_inegi_headline(area, published):
    row = profile(area=area, directory=REAL_DATA, indicators=["internet_user"]).iloc[0]
    # tables keep 4 decimals; INEGI publishes 1 decimal of a percentage
    assert row["share"] == pytest.approx(published, abs=0.00051)


PERSON_PARTS = {
    "state": [[f"{i:02d}" for i in range(1, 33)]],
    "sex": [["male", "female"]],
    "age": [["6-11", "12-17", "18-29", "30-44", "45-59", "60+"], ["6-11", "12-17", "18+"]],
    "area": [["urban", "rural"]],
}
ADULT = ["18-29", "30-44", "45-59", "60+"]


def _load(table):
    return pd.read_csv(REAL_DATA / f"endutih2025_{table}.csv", dtype={"state": str},
                       keep_default_na=False, na_values=[""])


def test_suppression_rule_holds():
    p = _load("persons")
    assert len(p) == 2371
    assert (p.loc[p["n"] < 30, "internet_user"].isna()).all()
    assert ((p["suppression"] == "primary") == (p["n"] < 30)).all()
    assert (p["suppressed"] == (p["suppression"] != "none")).all()
    assert p["suppression"].value_counts().to_dict() == {"none": 1704, "complementary": 387, "primary": 280}
    h = _load("households")
    assert len(h) == 99 and h["suppression"].value_counts().to_dict() == {"none": 95, "complementary": 3, "primary": 1}


def _groups(df, dims, parts_by_dim, extra=()):
    for d, partitions in parts_by_dim.items():
        others = [x for x in dims if x != d]
        for _, g in df.groupby(others):
            g = g.set_index(d)
            for total, parts in [("all", ps) for ps in partitions] + [r for r in extra if r[0] in g.index and d == "age"]:
                members = [m for m in [total, *parts] if m in g.index]
                if len(members) >= 2:
                    yield g, members


@pytest.mark.parametrize("table", ["persons", "households"])
def test_no_blank_is_recoverable_from_a_single_margin(table):
    """For every published total and its parts along one dimension, never exactly one blank:
    a lone blank would follow from the total minus the published parts."""
    df = _load(table)
    dims = ["state", "sex", "age", "area"] if table == "persons" else ["state", "area"]
    parts = PERSON_PARTS if table == "persons" else {k: PERSON_PARTS[k] for k in dims}
    cols = ["pop"] + [c[:-3] for c in df.columns if c.endswith("_se")]
    leaks = 0
    for g, members in _groups(df, dims, parts, extra=[("18+", ADULT)]):
        leaks += int((g.loc[members, cols].isna().sum() == 1).sum())
    assert leaks == 0
