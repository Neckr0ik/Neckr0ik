"""Weighted shares with design-based standard errors.

Point estimate: the ratio ``R = Σ w·y / Σ w`` over cell members with a valid
answer (``w`` = ENDUTIH expansion factor).

Standard error: Taylor linearisation with the ultimate-cluster approximation
(PSUs = ``UPM_DIS`` nested in strata = ``EST_DIS``), treating first-stage
sampling as with replacement — the usual approach for INEGI household surveys
(e.g. ``survey::svydesign(ids=~UPM_DIS, strata=~EST_DIS, weights=~FAC_PER)``).
Domains are handled correctly: PSUs with no members in the cell still count
toward their stratum. Strata with a single PSU contribute zero variance.

Cells with fewer than ``min_n`` unweighted respondents are suppressed (shares,
SEs and weighted totals blanked; the unweighted ``n`` is always shown).
"""

from __future__ import annotations

import itertools

import numpy as np
import pandas as pd

ALL = "all"
MIN_N_DEFAULT = 30


class Design:
    def __init__(self, strata: pd.Series, psu: pd.Series, weight: pd.Series):
        key = strata.astype(str) + "|" + psu.astype(str)
        self.psu_idx, psu_keys = pd.factorize(key, sort=True)
        stratum_of_psu = pd.Series(psu_keys).str.split("|").str[0]
        self.stratum_of_psu, _ = pd.factorize(stratum_of_psu, sort=True)
        self.n_psu = np.bincount(self.stratum_of_psu)
        with np.errstate(divide="ignore", invalid="ignore"):
            self.factor = np.where(self.n_psu > 1, self.n_psu / (self.n_psu - 1), 0.0)
        self.P = len(psu_keys)
        self.w = weight.to_numpy(dtype=float)

    def ratio(self, y: np.ndarray, rows: np.ndarray) -> tuple[float, float, int]:
        """Share and SE of indicator ``y`` (NaN = missing) within ``rows``."""
        yy = y[rows]
        ok = ~np.isnan(yy)
        r = rows[ok]
        yy = yy[ok]
        n_valid = int(len(r))
        if n_valid == 0:
            return np.nan, np.nan, 0
        w = self.w[r]
        W = w.sum()
        R = float((w * yy).sum() / W)
        z = w * (yy - R) / W
        tot = np.bincount(self.psu_idx[r], weights=z, minlength=self.P)
        mean_h = np.bincount(self.stratum_of_psu, weights=tot) / self.n_psu
        dev2 = np.square(tot - mean_h[self.stratum_of_psu])
        var = float((self.factor * np.bincount(self.stratum_of_psu, weights=dev2)).sum())
        return R, float(np.sqrt(max(var, 0.0))), n_valid


def estimate_cells(
    df: pd.DataFrame,
    design: Design,
    dims: dict[str, dict[str, np.ndarray]],
    indicators: dict[str, np.ndarray],
    min_n: int = MIN_N_DEFAULT,
    digits: int = 4,
) -> pd.DataFrame:
    """Cross every level of every dimension (each including an ``"all"``
    margin) and estimate every indicator in each non-empty cell.

    ``dims`` maps dimension name → {level label → boolean mask}.
    ``indicators`` maps key → float array (1/0/NaN) aligned with ``df``.
    """
    names = list(dims)
    has_missing = {k: bool(np.isnan(v).any()) for k, v in indicators.items()}
    records = []
    for combo in itertools.product(*(dims[d].items() for d in names)):
        mask = np.ones(len(df), dtype=bool)
        for _, m in combo:
            mask &= m
        rows = np.flatnonzero(mask)
        n = int(len(rows))
        if n == 0:
            continue
        rec = {d: lvl for d, (lvl, _) in zip(names, combo)}
        rec["n"] = n
        suppressed = n < min_n
        rec["suppressed"] = suppressed
        rec["pop"] = np.nan if suppressed else round(float(design.w[rows].sum()))
        for key, y in indicators.items():
            if suppressed:
                share = se = np.nan
                nv = int((~np.isnan(y[rows])).sum())
            else:
                share, se, nv = design.ratio(y, rows)
                if nv < min_n:
                    share = se = np.nan
            rec[key] = round(share, digits) if not np.isnan(share) else np.nan
            rec[f"{key}_se"] = round(se, digits) if not np.isnan(se) else np.nan
            if has_missing[key]:
                rec[f"{key}_n"] = nv
        records.append(rec)
    out = pd.DataFrame.from_records(records)
    out["pop"] = out["pop"].astype("Int64")
    return out
