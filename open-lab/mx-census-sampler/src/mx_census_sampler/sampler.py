"""Probability-proportional-to-size (PPS) selection of municipalities.

Measure of size (MOS) is the adult population, ``p_18ymas``. Two selection
methods are offered, both seeded and reproducible:

``systematic``
    Systematic PPS (Madow 1949): units are kept in CVEGEO order (implicit
    geographic stratification), cumulated by MOS, and hit by the points
    ``r + k*I`` with ``I = X_h / n_h`` and ``r ~ U(0, I)``. A unit whose MOS
    exceeds the interval can be hit more than once; each hit is a draw.

``wr``
    PPS with replacement (Hansen–Hurwitz): ``n_h`` independent draws with
    per-draw probability ``p_i = X_i / X_h``.

For both methods each draw receives ``m`` respondents (``per_unit``) and every
respondent gets the design weight ``X_h / (n_h * m)`` — the inverse of the
person-level inclusion expectation. Without stratification (or with
proportional allocation) the design is self-weighting; disproportionate
allocations (``equal``, ``sqrt``) produce unequal weights, summarised by Kish's
effective sample size.

Randomness only ever consumes ``Generator.random()`` doubles from a PCG64
stream, which NumPy keeps stable across releases; inverse-CDF lookups are done
explicitly so results do not depend on ``Generator.choice`` internals.
"""

from __future__ import annotations

from dataclasses import dataclass

import numpy as np
import pandas as pd

METHODS = ("systematic", "wr")
ALLOCATIONS = ("proportional", "equal", "sqrt")
MOS_COLUMN = "p_18ymas"


def make_rng(seed: int) -> np.random.Generator:
    return np.random.Generator(np.random.PCG64(seed))


def largest_remainder(shares: np.ndarray, n: int) -> np.ndarray:
    """Integer allocation of ``n`` proportional to ``shares`` (Hamilton method).

    Ties in the remainder are broken by position, so the result is
    deterministic.
    """
    shares = np.asarray(shares, dtype=float)
    if n < 0 or shares.sum() <= 0:
        raise ValueError("Need n >= 0 and positive shares.")
    quotas = shares / shares.sum() * n
    base = np.floor(quotas).astype(int)
    rest = n - int(base.sum())
    if rest:
        order = np.lexsort((np.arange(len(quotas)), -(quotas - base)))
        base[order[:rest]] += 1
    return base


def allocate(mos_by_stratum: pd.Series, n: int, allocation: str = "proportional") -> pd.Series:
    if allocation not in ALLOCATIONS:
        raise ValueError(f"allocation must be one of {ALLOCATIONS}")
    x = mos_by_stratum.to_numpy(dtype=float)
    if allocation == "proportional":
        shares = x
    elif allocation == "equal":
        shares = np.ones_like(x)
    else:
        shares = np.sqrt(x)
    return pd.Series(largest_remainder(shares, n), index=mos_by_stratum.index, name="n_h")


def _min_n_without_empty(mos_h: pd.Series, allocation: str) -> int:
    """Smallest n whose allocation gives every stratum at least one draw."""
    n = len(mos_h)
    while (allocate(mos_h, n, allocation).to_numpy() == 0).any():
        n += 1
    return n


def _systematic(cum: np.ndarray, n_h: int, rng: np.random.Generator) -> np.ndarray:
    total = cum[-1]
    interval = total / n_h
    start = rng.random() * interval
    points = start + interval * np.arange(n_h)
    # Floating-point rounding can put the last point at (or past) the total; clamp to the last unit.
    return np.minimum(np.searchsorted(cum, points, side="right"), len(cum) - 1)


def _with_replacement(cum: np.ndarray, n_h: int, rng: np.random.Generator) -> np.ndarray:
    u = rng.random(n_h) * cum[-1]
    return np.minimum(np.searchsorted(cum, u, side="right"), len(cum) - 1)


@dataclass(frozen=True)
class Design:
    n: int
    method: str = "systematic"
    stratify: str | None = None  # None or "state"
    allocation: str = "proportional"
    per_unit: int = 1
    seed: int = 2027


def draw_units(frame: pd.DataFrame, design: Design, rng: np.random.Generator) -> pd.DataFrame:
    """Return one row per draw (a municipality may appear more than once)."""
    if design.method not in METHODS:
        raise ValueError(f"method must be one of {METHODS}")
    if design.n < 1 or design.per_unit < 1:
        raise ValueError("n and per_unit must be >= 1")
    f = frame[frame[MOS_COLUMN] > 0].sort_values("cvegeo", kind="mergesort")
    if design.stratify is None:
        f = f.assign(stratum="all")
    elif design.stratify == "state":
        f = f.assign(stratum=f["cve_ent"])
    else:
        raise ValueError("stratify must be None or 'state'")

    mos_h = f.groupby("stratum", sort=True)[MOS_COLUMN].sum()
    n_h = allocate(mos_h, design.n, design.allocation)
    empty = [str(s) for s in n_h.index[n_h.to_numpy() == 0]]
    if design.stratify is not None and empty:
        # A stratum with no draws is not represented at all and no weight covers its
        # population: estimates would silently exclude it.
        raise ValueError(
            f"allocation '{design.allocation}' of n={design.n} over {len(n_h)} strata leaves "
            f"{len(empty)} stratum/strata with no draws ({', '.join(empty[:10])}"
            f"{', …' if len(empty) > 10 else ''}). Use n >= {_min_n_without_empty(mos_h, design.allocation)}, "
            "restrict the frame to fewer states, or sample without stratification."
        )

    pieces = []
    for stratum in mos_h.index:  # sorted, deterministic
        k = int(n_h[stratum])
        if k == 0:
            continue
        units = f[f["stratum"] == stratum]
        cum = np.cumsum(units[MOS_COLUMN].to_numpy(dtype=float))
        if design.method == "systematic":
            idx = _systematic(cum, k, rng)
        else:
            idx = _with_replacement(cum, k, rng)
        sel = units.iloc[idx].copy()
        x_h = float(mos_h[stratum])
        sel["n_h"] = k
        sel["mos_h"] = x_h
        sel["p_draw"] = sel[MOS_COLUMN] / x_h
        sel["expected_hits"] = k * sel["p_draw"]
        sel["weight"] = x_h / (k * design.per_unit)
        pieces.append(sel)
    draws = pd.concat(pieces, ignore_index=True)
    draws.insert(0, "draw_id", np.arange(1, len(draws) + 1))
    return draws


def kish_ess(weights) -> float:
    """Kish (1965) effective sample size: (Σw)² / Σw²."""
    w = np.asarray(weights, dtype=float)
    return float(w.sum() ** 2 / np.square(w).sum())


def kish_deff(weights) -> float:
    """Design effect due to unequal weighting: n / ESS = 1 + CV²(w)."""
    w = np.asarray(weights, dtype=float)
    return float(len(w) / kish_ess(w))
