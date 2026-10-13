"""Naive baselines that need no LLM.

A silicon-sample method only counts if it beats these. All default baselines
use information available *before* the official release:

* ``last_published`` - the previous official value for the same unit
  (persistence forecast).
* ``national_mean`` - the previous-wave national figure (given, or the
  weighted mean of previous unit values) for every unit.
* ``demographic_regression`` - OLS of previous-wave official values on unit
  demographics (e.g. census shares), used to predict the new wave from the
  units' current demographics.

``demographic_regression_loo`` is optional and *not* pre-release: it fits on
other units' current official values (leave-one-out). Use it only as a
harder, oracle-like benchmark and label it as such.
"""

from __future__ import annotations

from typing import Mapping, Sequence

import numpy as np


def _vec(x, name: str) -> np.ndarray:
    v = np.asarray(x, dtype=float)
    if v.ndim != 1:
        raise ValueError(f"{name} must be 1-D")
    if np.isnan(v).any():
        raise ValueError(f"{name} has NaN values")
    return v


def _design(covariates) -> np.ndarray:
    X = np.asarray(covariates, dtype=float)
    if X.ndim == 1:
        X = X[:, None]
    if np.isnan(X).any():
        raise ValueError("covariates have NaN values")
    return np.column_stack([np.ones(X.shape[0]), X])


def _ols_fit(X1: np.ndarray, y: np.ndarray, ridge: float) -> np.ndarray:
    if X1.shape[0] <= X1.shape[1] and ridge == 0:
        raise ValueError("more parameters than units: add ridge > 0 or drop covariates")
    P = np.eye(X1.shape[1]) * ridge
    P[0, 0] = 0.0  # never shrink the intercept
    return np.linalg.solve(X1.T @ X1 + P, X1.T @ y)


def last_published(previous) -> np.ndarray:
    return _vec(previous, "previous").copy()


def national_mean(previous, weights=None, national_value: float | None = None) -> np.ndarray:
    prev = _vec(previous, "previous")
    if national_value is not None:
        return np.full(prev.size, float(national_value))
    w = np.ones(prev.size) if weights is None else _vec(weights, "weights")
    if w.size != prev.size or (w < 0).any() or w.sum() == 0:
        raise ValueError("weights must be non-negative, same length, not all zero")
    return np.full(prev.size, float((w * prev).sum() / w.sum()))


def demographic_regression(
    covariates_previous, previous, covariates_current=None, ridge: float = 0.0
) -> np.ndarray:
    """Fit previous official values on previous-wave demographics; predict now."""
    y = _vec(previous, "previous")
    X1 = _design(covariates_previous)
    if X1.shape[0] != y.size:
        raise ValueError("covariates and previous differ in length")
    beta = _ols_fit(X1, y, ridge)
    Xc = X1 if covariates_current is None else _design(covariates_current)
    return Xc @ beta


def demographic_regression_loo(covariates, official, ridge: float = 0.0) -> np.ndarray:
    """Leave-one-out prediction of current official values from demographics.

    NOT a pre-release baseline (uses other units' current official values).
    """
    y = _vec(official, "official")
    X1 = _design(covariates)
    out = np.empty(y.size)
    for i in range(y.size):
        m = np.ones(y.size, bool)
        m[i] = False
        out[i] = X1[i] @ _ols_fit(X1[m], y[m], ridge)
    return out


def build_baselines(
    previous: Sequence[float],
    covariates=None,
    covariates_current=None,
    weights=None,
    national_value: float | None = None,
    official_for_loo: Sequence[float] | None = None,
    ridge: float = 0.0,
) -> Mapping[str, np.ndarray]:
    """Standard baseline set. Adds the LOO benchmark only if official values are given."""
    out = {
        "last_published": last_published(previous),
        "national_mean": national_mean(previous, weights, national_value),
    }
    if covariates is not None:
        out["demographic_regression"] = demographic_regression(covariates, previous, covariates_current, ridge)
        if official_for_loo is not None:
            out["demographic_regression_loo (not pre-release)"] = demographic_regression_loo(
                covariates if covariates_current is None else covariates_current, official_for_loo, ridge
            )
    return out
