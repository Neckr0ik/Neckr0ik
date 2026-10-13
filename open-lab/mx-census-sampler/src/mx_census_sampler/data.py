"""Loading and describing the municipal frame derived from INEGI ITER 2020."""

from __future__ import annotations

import os
from importlib import resources
from pathlib import Path

import numpy as np
import pandas as pd

DATA_FILENAME = "municipios_cpv2020.csv"
ENV_VAR = "MX_CENSUS_SAMPLER_DATA"

SEXES = ("F", "M")
AGE_BANDS = ("18-24", "25-34", "35-44", "45-54", "55-64", "65+")
SCHOOLING = ("none", "primary", "secondary", "post_basic")

# Column in the derived CSV for each (sex, age band) cell, e.g. "f_18_24".
AGE_SEX_COLUMNS = {
    (s, a): f"{s.lower()}_{a.replace('-', '_').replace('+', '_plus')}"
    for s in SEXES
    for a in AGE_BANDS
}

# Municipality size bands on total population (POBTOT). Lower bound inclusive.
SIZE_BANDS = {
    "micro": (0, 5_000),
    "small": (5_000, 20_000),
    "medium": (20_000, 100_000),
    "large": (100_000, 500_000),
    "metro": (500_000, float("inf")),
}

STRING_COLUMNS = ("cvegeo", "cve_ent", "nom_ent", "cve_mun", "nom_mun")

REQUIRED_COLUMNS = (
    *STRING_COLUMNS,
    "pobtot",
    "p_18ymas",
    "p_18ymas_f",
    "p_18ymas_m",
    *AGE_SEX_COLUMNS.values(),
    "p18ym_pb_f",
    "p18ym_pb_m",
    "p15ym_se",
    "p15_pri",
    "p15_sec",
)


def default_data_path() -> Path:
    """Locate the committed municipal CSV.

    Order: $MX_CENSUS_SAMPLER_DATA, the copy bundled in an installed wheel,
    then ``data/`` next to the package source (editable / source checkout).
    """
    env = os.environ.get(ENV_VAR)
    if env:
        return Path(env)
    try:
        bundled = resources.files("mx_census_sampler") / "data" / DATA_FILENAME
        if bundled.is_file():
            return Path(str(bundled))
    except (ModuleNotFoundError, FileNotFoundError):  # pragma: no cover
        pass
    return Path(__file__).resolve().parents[2] / "data" / DATA_FILENAME


def load_frame(path: str | os.PathLike | None = None) -> pd.DataFrame:
    """Read the municipal frame and validate its schema."""
    p = Path(path) if path is not None else default_data_path()
    if not p.is_file():
        raise FileNotFoundError(
            f"Municipal frame not found at {p}. Run `mx-census-sampler prepare` "
            f"or pass --data / set {ENV_VAR}."
        )
    df = pd.read_csv(p, dtype={c: str for c in STRING_COLUMNS}, encoding="utf-8")
    missing = [c for c in REQUIRED_COLUMNS if c not in df.columns]
    if missing:
        raise ValueError(f"{p} is missing columns: {missing}")
    for c in (c for c in REQUIRED_COLUMNS if c not in STRING_COLUMNS):
        vals = pd.to_numeric(df[c], errors="coerce")
        bad = ~np.isfinite(vals.to_numpy(dtype=float)) | (vals.to_numpy(dtype=float) < 0)
        if bad.any():
            first = df.loc[bad, "cvegeo"].iloc[0] if "cvegeo" in df else "?"
            raise ValueError(
                f"{p}: column {c!r} must hold finite counts >= 0; {int(bad.sum())} row(s) do not "
                f"(first: cvegeo {first}, value {df.loc[bad, c].iloc[0]!r})"
            )
        df[c] = vals
    df["size_band"] = size_band(df["pobtot"])
    return df.sort_values("cvegeo", kind="mergesort").reset_index(drop=True)


def size_band(pobtot: pd.Series) -> pd.Series:
    out = pd.Series(index=pobtot.index, dtype=object)
    for name, (lo, hi) in SIZE_BANDS.items():
        out[(pobtot >= lo) & (pobtot < hi)] = name
    return out.astype(str)


def filter_frame(
    df: pd.DataFrame,
    states: list[str] | None = None,
    size_bands: list[str] | None = None,
    municipalities: list[str] | None = None,
    min_adults: int = 1,
) -> pd.DataFrame:
    """Restrict the frame. ``states`` are 2-digit INEGI codes (``"09"``),
    ``municipalities`` are 5-digit CVEGEO codes, ``size_bands`` names from
    :data:`SIZE_BANDS`."""
    out = df
    if states:
        codes = [s.zfill(2) for s in states]
        out = out[out["cve_ent"].isin(codes)]
    if municipalities:
        codes = [m.zfill(5) for m in municipalities]
        out = out[out["cvegeo"].isin(codes)]
    if size_bands:
        unknown = set(size_bands) - set(SIZE_BANDS)
        if unknown:
            raise ValueError(f"Unknown size band(s): {sorted(unknown)}; use {list(SIZE_BANDS)}")
        out = out[out["size_band"].isin(size_bands)]
    out = out[out["p_18ymas"] >= min_adults]
    if out.empty:
        raise ValueError("No municipalities left after filtering.")
    return out.reset_index(drop=True)
