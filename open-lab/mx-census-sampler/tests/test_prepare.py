"""prepare.py on a SYNTHETIC miniature ITER file (made-up numbers)."""

import io
import zipfile

import pandas as pd
import pytest

from mx_census_sampler.prepare import (
    COLUMN_MAP,
    ITER_MEMBER,
    aggregate_municipalities,
    iter_columns,
    read_iter,
)


def synthetic_iter() -> pd.DataFrame:
    """Two synthetic municipalities, one locality each, plus total rows."""
    rows = []
    def row(ent, mun, loc, nom_loc, scale):
        r = {c: str(scale) for c in iter_columns()}
        r.update(ENTIDAD=ent, NOM_ENT="Synthetic State", MUN=mun, NOM_MUN=f"Mun {mun}", LOC=loc, NOM_LOC=nom_loc)
        r["P_18YMAS"] = str(2 * scale)
        r["P_18YMAS_F"] = str(scale)
        r["P_18YMAS_M"] = str(scale)
        r["GRAPROES"] = "9.5"
        return r
    rows.append(row("00", "000", "0000", "Total nacional", 30))
    rows.append(row("99", "000", "0000", "Total de la Entidad", 30))
    rows.append(row("99", "001", "0000", "Total del Municipio", 10))
    rows.append(row("99", "001", "0001", "Locality A", 10))
    rows.append(row("99", "002", "0000", "Total del Municipio", 20))
    rows.append(row("99", "002", "0001", "Locality B", 20))
    df = pd.DataFrame(rows)
    df["POBTOT"] = ["30", "30", "10", "10", "20", "20"]
    return df


def test_aggregate_keeps_only_municipal_totals():
    out = aggregate_municipalities(synthetic_iter(), expected=2)
    assert list(out["cvegeo"]) == ["99001", "99002"]
    assert list(out["pobtot"]) == [10, 20]
    assert list(out["p_18ymas"]) == [20, 40]
    # multi-part columns are summed: 65+ = five quinquennial groups
    assert out.loc[0, "f_65_plus"] == 5 * 10
    assert out.loc[0, "p15_pri"] == 2 * 10
    assert set(COLUMN_MAP) <= set(out.columns)


def test_rejects_wrong_row_count_and_suppressed_values():
    with pytest.raises(ValueError, match="Expected"):
        aggregate_municipalities(synthetic_iter(), expected=2469)
    bad = synthetic_iter()
    bad.loc[2, "P15YM_SE"] = "*"
    with pytest.raises(ValueError, match="non-numeric"):
        aggregate_municipalities(bad, expected=2)


def test_rejects_inconsistent_national_total():
    bad = synthetic_iter()
    bad.loc[0, "POBTOT"] = "31"
    with pytest.raises(ValueError, match="national"):
        aggregate_municipalities(bad, expected=2)


def test_read_iter_from_zip(tmp_path):
    raw = synthetic_iter()
    raw["EXTRA_COLUMN"] = "x"
    z = tmp_path / "iter.zip"
    with zipfile.ZipFile(z, "w") as zf:
        zf.writestr(ITER_MEMBER, "﻿" + raw.to_csv(index=False))
    got = read_iter(z)
    assert "EXTRA_COLUMN" not in got.columns
    assert len(aggregate_municipalities(got, expected=2)) == 2
