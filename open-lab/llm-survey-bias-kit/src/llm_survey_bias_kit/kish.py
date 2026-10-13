"""Kish (1965) effective sample size for design weights."""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
from typing import Iterable, Mapping, Sequence

import numpy as np


@dataclass
class KishResult:
    n: int
    effective_n: float
    design_effect: float
    efficiency: float
    cv_weights: float

    def to_dict(self) -> dict:
        return self.__dict__.copy()


def kish_effective_n(weights: Sequence[float]) -> KishResult:
    """Kish's approximation ``n_eff = (Σw)² / Σw²``.

    ``design_effect = n / n_eff = 1 + CV²(w)`` (population CV, ddof=0) and
    ``efficiency = n_eff / n``. It captures only the variance inflation from
    unequal weighting, not clustering or stratification.
    """
    w = np.asarray(weights, dtype=float)
    if w.size == 0:
        raise ValueError("no weights")
    if np.isnan(w).any():
        raise ValueError("weights contain NaN")
    if (w < 0).any():
        raise ValueError("weights must be non-negative")
    s1, s2 = float(w.sum()), float((w**2).sum())
    if s2 == 0:
        raise ValueError("all weights are zero")
    n_eff = s1 * s1 / s2
    mean = w.mean()
    cv = float(w.std(ddof=0) / mean) if mean > 0 else float("nan")
    return KishResult(
        n=int(w.size),
        effective_n=n_eff,
        design_effect=w.size / n_eff,
        efficiency=n_eff / w.size,
        cv_weights=cv,
    )


def kish_by_group(
    records: Iterable[Mapping], group_key: str, weight_key: str = "weight"
) -> dict:
    """Effective n per subgroup (e.g. per state) from long records."""
    groups: dict = defaultdict(list)
    for r in records:
        groups[r[group_key]].append(float(r[weight_key]))
    return {g: kish_effective_n(w) for g, w in sorted(groups.items(), key=lambda kv: str(kv[0]))}
