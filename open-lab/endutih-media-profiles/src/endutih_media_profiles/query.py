"""Query the committed aggregated tables."""

from __future__ import annotations

import math
import os
from importlib import resources
from pathlib import Path

import pandas as pd

from .estimate import ALL
from .indicators import BY_KEY, HOUSEHOLD_INDICATORS, PERSON_INDICATORS
from .states import STATE_NAMES

DEFAULT_EDITION = 2025
ENV_VAR = "ENDUTIH_PROFILES_DATA"
SEX_ALIASES = {"male": "male", "hombre": "male", "1": "male", "female": "female", "mujer": "female", "2": "female"}
AREA_ALIASES = {"urban": "urban", "urbano": "urban", "u": "urban", "rural": "rural", "r": "rural"}
DIMENSIONS = {"persons": ("state", "sex", "age", "area"), "households": ("state", "area")}


def data_dir() -> Path:
    env = os.environ.get(ENV_VAR)
    if env:
        return Path(env)
    try:
        bundled = resources.files("endutih_media_profiles") / "data"
        if bundled.is_dir():
            return Path(str(bundled))
    except (ModuleNotFoundError, FileNotFoundError):  # pragma: no cover
        pass
    return Path(__file__).resolve().parents[2] / "data"


def load_table(table: str = "persons", edition: int = DEFAULT_EDITION, directory: str | Path | None = None) -> pd.DataFrame:
    if table not in DIMENSIONS:
        raise ValueError(f"table must be one of {list(DIMENSIONS)}")
    d = Path(directory) if directory else data_dir()
    path = d / f"endutih{edition}_{table}.csv"
    if not path.is_file():
        raise FileNotFoundError(f"{path} not found; run `endutih-profiles-prepare --edition {edition}`.")
    dtypes = {k: str for k in DIMENSIONS[table]}
    return pd.read_csv(path, dtype=dtypes, keep_default_na=False, na_values=[""])


def normalize(state=None, sex=None, age=None, area=None) -> dict[str, str]:
    out = {}
    if state is None or str(state).lower() in (ALL, "00", "nacional", "national"):
        out["state"] = ALL
    else:
        s = str(state).zfill(2)
        if s not in STATE_NAMES:
            raise ValueError(f"Unknown state code {state!r} (use 01–32).")
        out["state"] = s
    if sex is None or str(sex).lower() == ALL:
        out["sex"] = ALL
    else:
        try:
            out["sex"] = SEX_ALIASES[str(sex).lower()]
        except KeyError:
            raise ValueError(f"Unknown sex {sex!r}; use male/female.") from None
    out["age"] = ALL if age is None else str(age).replace(" ", "")
    if area is None or str(area).lower() == ALL:
        out["area"] = ALL
    else:
        try:
            out["area"] = AREA_ALIASES[str(area).lower()]
        except KeyError:
            raise ValueError(f"Unknown area {area!r}; use urban/rural.") from None
    return out


CI_NOT_ESTIMABLE = "CI not estimable (se = 0)"


def wilson_ci(share: float, se: float, z: float = 1.959964) -> tuple[float, float]:
    """95% Wilson interval on the design-effect-adjusted sample size.

    ``n_eff = p(1-p)/se²`` carries the survey design (weights, clustering,
    strata) into the Wilson score interval, which stays inside [0, 1] and is not
    symmetric near 0 or 1, unlike the Wald ``p ± 1.96·se``. With ``se = 0``
    (typically ``p`` = 0 or 1 in a small cell) the design effect is unknown and
    the interval is not estimable: ``(nan, nan)``.
    """
    if share is None or se is None or not (math.isfinite(share) and math.isfinite(se)):
        return float("nan"), float("nan")
    if se <= 0 or share <= 0 or share >= 1:
        return float("nan"), float("nan")
    n_eff = share * (1 - share) / (se * se)
    z2 = z * z
    denom = 1 + z2 / n_eff
    center = (share + z2 / (2 * n_eff)) / denom
    half = z * math.sqrt(se * se + z2 / (4 * n_eff * n_eff)) / denom
    return max(0.0, center - half), min(1.0, center + half)


def _indicator_keys(table: str) -> list[str]:
    return [i.key for i in (PERSON_INDICATORS if table == "persons" else HOUSEHOLD_INDICATORS)]


def profile(
    state=None,
    sex=None,
    age=None,
    area=None,
    table: str = "persons",
    edition: int = DEFAULT_EDITION,
    indicators: list[str] | None = None,
    directory: str | Path | None = None,
    compare_national: bool = True,
) -> pd.DataFrame:
    """Return one row per indicator for the requested cell.

    Columns: indicator, label_en, label_es, share, se, ci95_low, ci95_high
    (Wilson interval on the design-effect-adjusted n; see :func:`wilson_ci`),
    ci_note, n (cell respondents), suppressed, and — if ``compare_national`` — the
    national value for the same sex/age/area (``national_share``).
    """
    df = load_table(table, edition, directory)
    want = normalize(state, sex, age, area)
    dims = DIMENSIONS[table]
    if table == "households":
        if want["sex"] != ALL or want["age"] != ALL:
            raise ValueError("Household table has no sex/age breakdown.")
    valid_ages = sorted(df["age"].unique()) if "age" in df else [ALL]
    if want.get("age", ALL) not in valid_ages:
        raise ValueError(f"Unknown age band {want['age']!r}; use one of {valid_ages}.")

    def cell(sel):
        m = pd.Series(True, index=df.index)
        for d in dims:
            m &= df[d] == sel[d]
        rows = df[m]
        if len(rows) != 1:
            return None
        return rows.iloc[0]

    row = cell(want)
    if row is None:
        raise ValueError(f"No respondents in cell {want} (empty cell).")
    nat = cell({**want, "state": ALL}) if compare_national and want["state"] != ALL else None
    keys = indicators or _indicator_keys(table)
    unknown = [k for k in keys if k not in BY_KEY or k not in df.columns]
    if unknown:
        raise ValueError(f"Unknown indicator(s) {unknown}; see `endutih-profiles --list`.")
    recs = []
    for k in keys:
        share, se = row[k], row[f"{k}_se"]
        published = pd.notna(share)
        lo, hi = wilson_ci(float(share), float(se)) if published and pd.notna(se) else (float("nan"),) * 2
        rec = {
            "indicator": k,
            "label_en": BY_KEY[k].label_en,
            "label_es": BY_KEY[k].label_es,
            "share": share,
            "se": se,
            "ci95_low": lo,
            "ci95_high": hi,
            "ci_note": CI_NOT_ESTIMABLE if published and math.isnan(lo) else "",
            "n": int(row.get(f"{k}_n", row["n"])),
            "suppressed": not published,
        }
        if nat is not None:
            rec["national_share"] = nat[k]
        recs.append(rec)
    out = pd.DataFrame(recs)
    out.attrs.update(cell=want, n=int(row["n"]), pop=row["pop"], edition=edition, table=table,
                     state_name=row["state_name"])
    return out
