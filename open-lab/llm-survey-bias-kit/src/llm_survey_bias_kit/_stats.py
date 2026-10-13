"""Small statistical helpers with no hard SciPy dependency.

SciPy is used when installed; otherwise Student-t quantiles are computed from a
continued-fraction regularized incomplete beta function (Numerical Recipes,
Lentz's method) inverted by bisection. Accuracy is better than 1e-8, which is
far below anything that matters for a confidence interval.
"""

from __future__ import annotations

import math
from statistics import NormalDist

import numpy as np

try:  # pragma: no cover - exercised only when SciPy is present
    from scipy import stats as _sps
except Exception:  # pragma: no cover
    _sps = None


def _betacf(a: float, b: float, x: float, max_iter: int = 500, eps: float = 1e-15) -> float:
    tiny = 1e-300
    qab, qap, qam = a + b, a + 1.0, a - 1.0
    c, d = 1.0, 1.0 - qab * x / qap
    d = 1.0 / (d if abs(d) > tiny else tiny)
    h = d
    for m in range(1, max_iter + 1):
        m2 = 2 * m
        aa = m * (b - m) * x / ((qam + m2) * (a + m2))
        d = 1.0 + aa * d
        d = 1.0 / (d if abs(d) > tiny else tiny)
        c = 1.0 + aa / c
        c = c if abs(c) > tiny else tiny
        h *= d * c
        aa = -(a + m) * (qab + m) * x / ((a + m2) * (qap + m2))
        d = 1.0 + aa * d
        d = 1.0 / (d if abs(d) > tiny else tiny)
        c = 1.0 + aa / c
        c = c if abs(c) > tiny else tiny
        delta = d * c
        h *= delta
        if abs(delta - 1.0) < eps:
            break
    return h


def betainc(a: float, b: float, x: float) -> float:
    """Regularized incomplete beta function I_x(a, b)."""
    if x <= 0.0:
        return 0.0
    if x >= 1.0:
        return 1.0
    ln_front = (
        math.lgamma(a + b) - math.lgamma(a) - math.lgamma(b)
        + a * math.log(x) + b * math.log1p(-x)
    )
    front = math.exp(ln_front)
    if x < (a + 1.0) / (a + b + 2.0):
        return front * _betacf(a, b, x) / a
    return 1.0 - front * _betacf(b, a, 1.0 - x) / b


def t_cdf(t: float, df: float) -> float:
    """CDF of Student's t distribution."""
    if _sps is not None:
        return float(_sps.t.cdf(t, df))
    if math.isinf(df):
        return NormalDist().cdf(t)
    x = df / (df + t * t)
    tail = 0.5 * betainc(df / 2.0, 0.5, x)
    return 1.0 - tail if t > 0 else tail


def t_ppf(q: float, df: float) -> float:
    """Quantile function of Student's t distribution."""
    if not 0.0 < q < 1.0:
        raise ValueError("q must be in (0, 1)")
    if df <= 0:
        raise ValueError("df must be positive")
    if _sps is not None:
        return float(_sps.t.ppf(q, df))
    if math.isinf(df):
        return NormalDist().inv_cdf(q)
    if q == 0.5:
        return 0.0
    lo, hi = -1.0, 1.0
    while t_cdf(lo, df) > q:
        lo *= 2.0
    while t_cdf(hi, df) < q:
        hi *= 2.0
    for _ in range(200):
        mid = 0.5 * (lo + hi)
        if t_cdf(mid, df) < q:
            lo = mid
        else:
            hi = mid
        if hi - lo < 1e-12:
            break
    return 0.5 * (lo + hi)


def z_ppf(q: float) -> float:
    return NormalDist().inv_cdf(q)


def percentile_ci(samples: np.ndarray, level: float = 0.95) -> tuple[float, float]:
    alpha = 1.0 - level
    lo, hi = np.quantile(samples, [alpha / 2.0, 1.0 - alpha / 2.0])
    return float(lo), float(hi)


def shannon_entropy(probs: np.ndarray, base: float = 2.0) -> float:
    p = np.asarray(probs, dtype=float)
    p = p[p > 0]
    if p.size == 0:
        return 0.0
    p = p / p.sum()
    return float(-(p * np.log(p)).sum() / math.log(base))
