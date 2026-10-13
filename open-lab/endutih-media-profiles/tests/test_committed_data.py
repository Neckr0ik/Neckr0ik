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


def test_suppression_rule_holds():
    p = pd.read_csv(REAL_DATA / "endutih2025_persons.csv", dtype={"state": str})
    assert (p.loc[p["n"] < 30, "internet_user"].isna()).all()
    assert (p["suppressed"] == (p["n"] < 30)).all()
    assert len(p) > 2000
