"""Accuracy and calibration metrics for estimates vs official figures."""

from __future__ import annotations

import math
from typing import Sequence

import numpy as np


def _pair(official, estimate) -> tuple[np.ndarray, np.ndarray]:
    y = np.asarray(official, dtype=float)
    x = np.asarray(estimate, dtype=float)
    if y.shape != x.shape or y.ndim != 1:
        raise ValueError("official and estimate must be 1-D arrays of equal length")
    if y.size == 0:
        raise ValueError("no units")
    if np.isnan(y).any() or np.isnan(x).any():
        raise ValueError("NaN values: drop or impute missing units explicitly before scoring")
    return y, x


def mae(official, estimate) -> float:
    y, x = _pair(official, estimate)
    return float(np.abs(x - y).mean())


def rmse(official, estimate) -> float:
    y, x = _pair(official, estimate)
    return float(math.sqrt(((x - y) ** 2).mean()))


def bias(official, estimate) -> float:
    """Mean signed error, estimate minus official (positive = overestimates)."""
    y, x = _pair(official, estimate)
    return float((x - y).mean())


def pearson(official, estimate) -> float:
    y, x = _pair(official, estimate)
    if y.size < 3 or y.std() == 0 or x.std() == 0:
        return float("nan")
    return float(np.corrcoef(y, x)[0, 1])


def _rank(v: np.ndarray) -> np.ndarray:
    order = np.argsort(v, kind="mergesort")
    ranks = np.empty(v.size)
    ranks[order] = np.arange(1, v.size + 1)
    # average ties
    for val in np.unique(v):
        idx = v == val
        if idx.sum() > 1:
            ranks[idx] = ranks[idx].mean()
    return ranks


def spearman(official, estimate) -> float:
    y, x = _pair(official, estimate)
    return pearson(_rank(y), _rank(x))


def coverage(official, lower, upper) -> float:
    """Share of official values inside [lower, upper]."""
    y = np.asarray(official, dtype=float)
    lo = np.asarray(lower, dtype=float)
    hi = np.asarray(upper, dtype=float)
    if not (y.shape == lo.shape == hi.shape):
        raise ValueError("shapes differ")
    if (lo > hi).any():
        raise ValueError("lower > upper for some unit")
    return float(((y >= lo) & (y <= hi)).mean())


def interval_score(official, lower, upper, alpha: float = 0.05) -> float:
    """Mean interval score (Gneiting & Raftery 2007); lower is better.

    ``(u - l) + (2/α)(l - y)·1[y < l] + (2/α)(y - u)·1[y > u]``. Rewards narrow
    intervals and penalises misses, so it cannot be gamed by width alone.
    """
    y = np.asarray(official, dtype=float)
    lo = np.asarray(lower, dtype=float)
    hi = np.asarray(upper, dtype=float)
    s = (hi - lo) + (2 / alpha) * (lo - y) * (y < lo) + (2 / alpha) * (y - hi) * (y > hi)
    return float(s.mean())


def score(
    official: Sequence[float],
    estimate: Sequence[float],
    lower: Sequence[float] | None = None,
    upper: Sequence[float] | None = None,
    nominal: float = 0.95,
) -> dict:
    """All point metrics, plus interval metrics when bounds are given."""
    out = {
        "n": int(len(official)),
        "mae": mae(official, estimate),
        "rmse": rmse(official, estimate),
        "bias": bias(official, estimate),
        "pearson": pearson(official, estimate),
        "spearman": spearman(official, estimate),
    }
    if lower is not None and upper is not None:
        out["coverage"] = coverage(official, lower, upper)
        out["nominal_coverage"] = nominal
        out["mean_width"] = float(np.mean(np.asarray(upper, float) - np.asarray(lower, float)))
        out["interval_score"] = interval_score(official, lower, upper, 1 - nominal)
    return out
