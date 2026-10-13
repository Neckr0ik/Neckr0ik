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

Complementary suppression: margins make blanks recoverable. With ``all`` = ``male``
+ ``female``, a blanked ``female`` cell follows from the published ``all`` and
``male`` cells (``share·pop`` is additive). So for every additive relation
(a total and the disjoint parts that make it up, along any one dimension with the
other dimensions fixed), a relation never holds exactly one blank: when it would,
the published part with the fewest respondents (or, if no part is left, the total)
is blanked too, repeating until no relation along any dimension has a single blank.
This runs for the whole cell (weighted total + every indicator) and again per
indicator for indicator-level blanks (too few valid answers).
"""

from __future__ import annotations

import itertools
from typing import Mapping, Sequence

import numpy as np
import pandas as pd

ALL = "all"
MIN_N_DEFAULT = 30
PRIMARY = "primary"
COMPLEMENTARY = "complementary"
NONE = "none"

Relations = Mapping[str, Sequence[tuple[str, Sequence[str]]]]


def default_relations(dims: dict[str, dict[str, np.ndarray]]) -> dict[str, list[tuple[str, list[str]]]]:
    """``ALL`` = every other level, for dimensions where that holds exactly in the data."""
    out: dict[str, list[tuple[str, list[str]]]] = {}
    for d, levels in dims.items():
        parts = [k for k in levels if k != ALL]
        if ALL in levels and parts and _is_partition(levels, ALL, parts):
            out[d] = [(ALL, parts)]
    return out


def _is_partition(levels: dict[str, np.ndarray], total: str, parts: Sequence[str]) -> bool:
    count = np.zeros(len(levels[total]), dtype=int)
    for q in parts:
        count += levels[q].astype(int)
    return bool((count <= 1).all() and np.array_equal(count == 1, levels[total]))


def _relation_groups(cells: pd.DataFrame, names: list[str], relations: Relations) -> list[tuple[int | None, list[int]]]:
    """Row indices of every (total, parts) group present in ``cells``."""
    pos = {tuple(r): i for i, r in enumerate(cells[names].itertuples(index=False, name=None))}
    groups = []
    for d, rels in relations.items():
        j = names.index(d)
        others = sorted({k[:j] + k[j + 1:] for k in pos})
        for rest in others:
            for total, parts in rels:
                key = lambda lvl: rest[:j] + (lvl,) + rest[j:]  # noqa: E731
                t = pos.get(key(total))
                ps = [pos[key(q)] for q in parts if key(q) in pos]
                if (t is not None) + len(ps) >= 2:
                    groups.append((t, ps))
    return groups


def complementary_mask(primary: np.ndarray, n: np.ndarray, groups: list[tuple[int | None, list[int]]]) -> np.ndarray:
    """Extend ``primary`` until no relation group has exactly one blank.

    Parts are blanked before totals (margins stay published where possible), the
    part with the smallest ``n`` first; ties go to the earlier row. Absent (empty)
    cells are known zeros and never count as blanks.
    """
    supp = np.asarray(primary, dtype=bool).copy()
    changed = True
    while changed:
        changed = False
        for t, ps in groups:
            members = ([t] if t is not None else []) + ps
            if sum(supp[m] for m in members) != 1:
                continue
            cands = [m for m in ps if not supp[m]] or [m for m in members if not supp[m]]
            pick = min(cands, key=lambda m: (n[m], m))
            supp[pick] = True
            changed = True
    return supp


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
    relations: Relations | None = None,
    complementary: bool = True,
) -> pd.DataFrame:
    """Cross every level of every dimension (each including an ``"all"``
    margin) and estimate every indicator in each non-empty cell.

    ``dims`` maps dimension name → {level label → boolean mask}.
    ``indicators`` maps key → float array (1/0/NaN) aligned with ``df``.
    ``relations`` maps a dimension to its additive relations ``(total, [parts])``
    (default: ``all`` = the other levels, where that is an exact partition). Each
    relation is checked against the data and must be an exact partition.
    With ``complementary=True`` (default) blanks are protected against
    recovery by subtraction (see the module docstring); the ``suppression``
    column says ``primary``, ``complementary`` or ``none``.
    """
    if relations is None:
        relations = default_relations(dims)
    for d, rels in relations.items():
        for total, parts in rels:
            if not _is_partition(dims[d], total, parts):
                raise ValueError(f"relation {d}: {total} = {' + '.join(parts)} is not an exact partition of the data")
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
        rec["suppression"] = PRIMARY if suppressed else NONE
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
    if complementary and len(out):
        groups = _relation_groups(out, names, relations)
        n_arr = out["n"].to_numpy()
        primary = out["suppressed"].to_numpy(dtype=bool)
        cell_mask = complementary_mask(primary, n_arr, groups)
        extra = cell_mask & ~primary
        out.loc[extra, "suppressed"] = True
        out.loc[extra, "suppression"] = COMPLEMENTARY
        out.loc[extra, "pop"] = np.nan
        for key in indicators:
            out.loc[extra, [key, f"{key}_se"]] = np.nan
            blank = cell_mask | out[key].isna().to_numpy()  # indicator-level blanks (too few valid answers)
            more = complementary_mask(blank, n_arr, groups) & ~blank
            out.loc[more, [key, f"{key}_se"]] = np.nan
    out["pop"] = out["pop"].astype("Int64")
    return out
