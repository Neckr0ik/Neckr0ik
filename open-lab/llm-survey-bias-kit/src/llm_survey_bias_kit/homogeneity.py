"""Homogeneity diagnostics for simulated answers.

Simulated respondents are often *too alike*: Bisbee et al. (2024) found
LLM-generated survey answers with much less variance than the human answers
they were meant to mimic. These helpers compare the dispersion of simulated
answers against a human reference and flag subgroup cuts that are too thin to
interpret.
"""

from __future__ import annotations

import math
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from typing import Iterable, Mapping, Sequence

import numpy as np

from ._stats import percentile_ci, shannon_entropy

DEFAULT_MIN_UNITS = 12


def _distribution(data, categories: Sequence[str]) -> tuple[np.ndarray, int | None]:
    """Return (probabilities, n_raw) from raw labels or a {label: weight} mapping."""
    if isinstance(data, Mapping):
        w = np.array([float(data.get(c, 0.0)) for c in categories])
        extra = set(data) - set(categories)
        if extra:
            raise ValueError(f"reference has categories not in list: {sorted(extra)}")
        if w.sum() <= 0:
            raise ValueError("reference weights must sum to a positive number")
        return w / w.sum(), None
    labels = list(data)
    unknown = set(labels) - set(categories)
    if unknown:
        raise ValueError(f"unknown categories: {sorted(map(str, unknown))}")
    counts = Counter(labels)
    w = np.array([counts.get(c, 0) for c in categories], dtype=float)
    if w.sum() == 0:
        raise ValueError("no observations")
    return w / w.sum(), len(labels)


@dataclass
class CategoricalDispersion:
    categories: list[str]
    simulated: dict[str, float]
    reference: dict[str, float]
    entropy_simulated: float
    entropy_reference: float
    entropy_ratio: float
    entropy_ratio_ci: tuple[float, float] | None
    gini_simpson_simulated: float
    gini_simpson_reference: float
    modal_share_simulated: float
    modal_share_reference: float
    categories_used_simulated: int
    tvd: float
    too_homogeneous: bool
    threshold: float
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        d = self.__dict__.copy()
        if self.entropy_ratio_ci is not None:
            d["entropy_ratio_ci"] = list(self.entropy_ratio_ci)
        return d


def _gini_simpson(p: np.ndarray) -> float:
    return float(1.0 - (p**2).sum())


def categorical_dispersion(
    simulated: Iterable[str] | Mapping[str, float],
    reference: Iterable[str] | Mapping[str, float],
    categories: Sequence[str] | None = None,
    threshold: float = 0.8,
    n_boot: int = 2000,
    seed: int | None = 0,
) -> CategoricalDispersion:
    """Compare the spread of simulated categorical answers with a human reference.

    Entropies are normalised by ``log(k)`` (1 = uniform over all k categories).
    ``too_homogeneous`` is True when ``H_sim / H_ref < threshold``. ``reference``
    may be raw human answers or a mapping of (weighted) proportions, e.g. from a
    published survey table. A bootstrap CI for the ratio is reported when the
    simulated side is raw answers (the reference is resampled too if raw).
    """
    sim_raw = None if isinstance(simulated, Mapping) else list(simulated)
    ref_raw = None if isinstance(reference, Mapping) else list(reference)
    if categories is None:
        cats: set = set()
        for src in (simulated if sim_raw is None else sim_raw, reference if ref_raw is None else ref_raw):
            cats.update(src)
        categories = sorted(cats, key=str)
    cats_list = list(categories)
    k = len(cats_list)
    if k < 2:
        raise ValueError("need at least two categories")
    ps, _ = _distribution(simulated if sim_raw is None else sim_raw, cats_list)
    pr, _ = _distribution(reference if ref_raw is None else ref_raw, cats_list)
    hs = shannon_entropy(ps, base=k)
    hr = shannon_entropy(pr, base=k)
    notes: list[str] = []
    ratio = hs / hr if hr > 0 else (math.inf if hs > 0 else float("nan"))
    if hr == 0:
        notes.append("reference has zero entropy (all answers identical); ratio undefined")

    ci = None
    if sim_raw is not None and hr > 0:
        rng = np.random.default_rng(seed)
        index = {c: i for i, c in enumerate(cats_list)}
        s_codes = np.array([index[c] for c in sim_raw])
        r_codes = None if ref_raw is None else np.array([index[c] for c in ref_raw])
        ratios = np.empty(n_boot)
        for b in range(n_boot):
            bs = np.bincount(s_codes[rng.integers(0, s_codes.size, s_codes.size)], minlength=k)
            if r_codes is not None:
                br = np.bincount(r_codes[rng.integers(0, r_codes.size, r_codes.size)], minlength=k)
                href = shannon_entropy(br, base=k)
            else:
                href = hr
            ratios[b] = shannon_entropy(bs, base=k) / href if href > 0 else np.nan
        ratios = ratios[~np.isnan(ratios)]
        if ratios.size:
            ci = percentile_ci(ratios)

    return CategoricalDispersion(
        categories=[str(c) for c in cats_list],
        simulated={str(c): float(ps[i]) for i, c in enumerate(cats_list)},
        reference={str(c): float(pr[i]) for i, c in enumerate(cats_list)},
        entropy_simulated=hs,
        entropy_reference=hr,
        entropy_ratio=float(ratio),
        entropy_ratio_ci=ci,
        gini_simpson_simulated=_gini_simpson(ps),
        gini_simpson_reference=_gini_simpson(pr),
        modal_share_simulated=float(ps.max()),
        modal_share_reference=float(pr.max()),
        categories_used_simulated=int((ps > 0).sum()),
        tvd=0.5 * float(np.abs(ps - pr).sum()),
        too_homogeneous=bool(hr > 0 and ratio < threshold),
        threshold=threshold,
        notes=notes,
    )


@dataclass
class NumericDispersion:
    n_simulated: int
    n_reference: int | None
    sd_simulated: float
    sd_reference: float
    sd_ratio: float
    variance_ratio: float
    sd_ratio_ci: tuple[float, float] | None
    too_homogeneous: bool
    threshold: float

    def to_dict(self) -> dict:
        d = self.__dict__.copy()
        if self.sd_ratio_ci is not None:
            d["sd_ratio_ci"] = list(self.sd_ratio_ci)
        return d


def numeric_dispersion(
    simulated: Sequence[float],
    reference: Sequence[float] | None = None,
    reference_sd: float | None = None,
    threshold: float = 0.8,
    n_boot: int = 2000,
    seed: int | None = 0,
) -> NumericDispersion:
    """Compare the SD of simulated numeric answers (e.g. a 0-10 scale) with humans.

    Supply either a raw human ``reference`` sample or a published
    ``reference_sd``. ``too_homogeneous`` is True when ``SD_sim / SD_ref <
    threshold``.
    """
    s = np.asarray(simulated, dtype=float)
    s = s[~np.isnan(s)]
    if s.size < 2:
        raise ValueError("need at least two simulated values")
    if (reference is None) == (reference_sd is None):
        raise ValueError("give exactly one of reference or reference_sd")
    r = None
    if reference is not None:
        r = np.asarray(reference, dtype=float)
        r = r[~np.isnan(r)]
        if r.size < 2:
            raise ValueError("need at least two reference values")
        sd_r = float(r.std(ddof=1))
    else:
        sd_r = float(reference_sd)
    if sd_r <= 0:
        raise ValueError("reference SD must be positive")
    sd_s = float(s.std(ddof=1))
    rng = np.random.default_rng(seed)
    boots = np.empty(n_boot)
    for b in range(n_boot):
        bs = s[rng.integers(0, s.size, s.size)].std(ddof=1)
        br = r[rng.integers(0, r.size, r.size)].std(ddof=1) if r is not None else sd_r
        boots[b] = bs / br if br > 0 else np.nan
    boots = boots[~np.isnan(boots)]
    ratio = sd_s / sd_r
    return NumericDispersion(
        n_simulated=int(s.size),
        n_reference=None if r is None else int(r.size),
        sd_simulated=sd_s,
        sd_reference=sd_r,
        sd_ratio=ratio,
        variance_ratio=ratio**2,
        sd_ratio_ci=percentile_ci(boots) if boots.size else None,
        too_homogeneous=bool(ratio < threshold),
        threshold=threshold,
    )


@dataclass
class SubgroupCell:
    group: dict
    n_units: int
    n_rows: int
    reportable: bool


def subgroup_sizes(
    records: Iterable[Mapping],
    group_keys: Sequence[str],
    unit_key: str = "unit_id",
    min_units: int = DEFAULT_MIN_UNITS,
) -> list[SubgroupCell]:
    """Count distinct simulated units per subgroup cut and flag thin cells.

    A cell is ``reportable`` only if it holds at least ``min_units`` distinct
    units (default 12). Replicates of one unit do not add information about
    the subgroup, so rows are not counted as units.
    """
    if not group_keys:
        raise ValueError("give at least one group key")
    units: dict = defaultdict(set)
    rows: Counter = Counter()
    for rec in records:
        key = tuple(rec[g] for g in group_keys)
        units[key].add(rec[unit_key])
        rows[key] += 1
    cells = [
        SubgroupCell(
            group=dict(zip(group_keys, key)),
            n_units=len(units[key]),
            n_rows=rows[key],
            reportable=len(units[key]) >= min_units,
        )
        for key in sorted(units, key=lambda t: tuple(map(str, t)))
    ]
    return cells
