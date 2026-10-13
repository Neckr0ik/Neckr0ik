"""Paired A/B and A/A comparisons of messages over the same simulated units.

Design assumed: every simulated unit (a synthetic respondent) answers both
message A and message B, ``R`` times each (replicates = independent LLM calls).
The analysis unit is the simulated unit: replicates are averaged within unit,
then the paired difference ``mean_A - mean_B`` is analysed across units.

Verdicts:

* ``"not evaluable"`` - fewer than two replicates (one call per unit and
  message cannot separate the model's own sampling noise from a message
  effect), or fewer than two units.
* ``"distinguishable"`` - both the t and bootstrap 95% CIs exclude zero and,
  if an A/A noise floor is supplied, ``|diff|`` exceeds it. When the
  difference has zero variance across units (every unit moved by exactly the
  same amount) the CIs collapse to a point, so ``|diff|`` must also exceed a
  small numerical tolerance; a floating-point residue is never a difference.
* ``"indistinguishable"`` - otherwise. This is *not* evidence of equality;
  compare the observed difference with the minimum detectable effect.
"""

from __future__ import annotations

import math
import warnings
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Iterable, Mapping

import numpy as np

from ._stats import percentile_ci, t_ppf

_ZERO_TOL = 1e-9  # relative tolerance for "numerically zero" differences and SEs

DISTINGUISHABLE = "distinguishable"
INDISTINGUISHABLE = "indistinguishable"
NOT_EVALUABLE = "not evaluable"


@dataclass
class PairedResult:
    label_a: str
    label_b: str
    n_units: int
    n_replicates: int
    mean_a: float
    mean_b: float
    diff: float
    sd_diff: float
    se_diff: float
    ci_t: tuple[float, float]
    ci_boot: tuple[float, float]
    mde: float
    replicate_sd: float
    noise_floor: float | None
    verdict: str
    reasons: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        d = self.__dict__.copy()
        d["ci_t"] = list(self.ci_t)
        d["ci_boot"] = list(self.ci_boot)
        return d


def minimum_detectable_effect(
    n: int, sd: float, alpha: float = 0.05, power: float = 0.80
) -> float:
    """Smallest true paired mean difference detectable with the given power.

    ``MDE = (t_{1-α/2, n-1} + t_{power, n-1}) · sd / √n`` for a two-sided
    one-sample (paired) t-test.
    """
    if n < 2:
        return math.inf
    if sd < 0:
        raise ValueError("sd must be non-negative")
    df = n - 1
    return (t_ppf(1 - alpha / 2, df) + t_ppf(power, df)) * sd / math.sqrt(n)


def required_units(
    effect: float, sd: float, alpha: float = 0.05, power: float = 0.80, max_n: int = 10**7
) -> int:
    """Smallest number of units whose MDE is <= ``effect``."""
    if effect <= 0:
        raise ValueError("effect must be positive")
    if sd == 0:
        return 2
    n = 2
    while minimum_detectable_effect(n, sd, alpha, power) > effect:
        n = n * 2 if n < 64 else int(n * 1.25) + 1
        if n > max_n:
            raise ValueError("required n exceeds max_n")
    lo, hi = max(2, n // 2), n
    while lo < hi:
        mid = (lo + hi) // 2
        if minimum_detectable_effect(mid, sd, alpha, power) <= effect:
            hi = mid
        else:
            lo = mid + 1
    return lo


def _as_matrix(x) -> np.ndarray:
    m = np.asarray(x, dtype=float)
    if m.ndim == 1:
        m = m[:, None]
    if m.ndim != 2:
        raise ValueError("scores must be 1-D (units) or 2-D (units x replicates)")
    return m


def _pooled_within_sd(*mats: np.ndarray) -> float:
    num, den = 0.0, 0
    for m in mats:
        for row in m:
            row = row[~np.isnan(row)]
            if row.size >= 2:
                num += float(((row - row.mean()) ** 2).sum())
                den += row.size - 1
    return math.sqrt(num / den) if den > 0 else float("nan")


def paired_ab(
    scores_a,
    scores_b,
    label_a: str = "A",
    label_b: str = "B",
    alpha: float = 0.05,
    power: float = 0.80,
    n_boot: int = 5000,
    noise_floor: float | None = None,
    seed: int | None = 0,
) -> PairedResult:
    """Paired comparison of two messages over the same simulated units.

    ``scores_a`` and ``scores_b`` are arrays of shape (n_units, n_replicates)
    whose rows refer to the same unit. NaN marks a missing replicate. A 1-D
    array is treated as one replicate per unit (and is therefore not
    evaluable).
    """
    a, b = _as_matrix(scores_a), _as_matrix(scores_b)
    if a.shape[0] != b.shape[0]:
        raise ValueError("A and B must have the same number of units (rows)")
    reasons: list[str] = []
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", RuntimeWarning)  # all-NaN rows -> NaN
        ua = np.nanmean(a, axis=1) if a.size else np.full(a.shape[0], np.nan)
        ub = np.nanmean(b, axis=1) if b.size else np.full(b.shape[0], np.nan)
    keep = ~(np.isnan(ua) | np.isnan(ub))
    if (~keep).any():
        reasons.append(f"dropped {int((~keep).sum())} unit(s) with no valid score for A or B")
    a, b, ua, ub = a[keep], b[keep], ua[keep], ub[keep]
    n = int(keep.sum())
    reps_a = np.sum(~np.isnan(a), axis=1) if n else np.array([0])
    reps_b = np.sum(~np.isnan(b), axis=1) if n else np.array([0])
    n_reps = int(min(reps_a.min(), reps_b.min())) if n else 0

    d = ua - ub
    diff = float(d.mean()) if n else float("nan")
    sd = float(d.std(ddof=1)) if n >= 2 else float("nan")
    se = sd / math.sqrt(n) if n >= 2 else float("nan")
    if n >= 2:
        tq = t_ppf(1 - alpha / 2, n - 1)
        ci_t = (diff - tq * se, diff + tq * se)
        rng = np.random.default_rng(seed)
        idx = rng.integers(0, n, size=(n_boot, n))
        ci_boot = percentile_ci(d[idx].mean(axis=1), 1 - alpha)
        mde = minimum_detectable_effect(n, sd, alpha, power)
    else:
        ci_t = ci_boot = (float("nan"), float("nan"))
        mde = math.inf

    if n < 2:
        verdict = NOT_EVALUABLE
        reasons.append("fewer than two units with valid scores")
    elif n_reps < 2:
        verdict = NOT_EVALUABLE
        reasons.append(
            "fewer than two replicates per unit and message: model sampling "
            "noise cannot be separated from a message effect"
        )
    else:
        excludes_zero = (ci_t[0] > 0 or ci_t[1] < 0) and (ci_boot[0] > 0 or ci_boot[1] < 0)
        tol = _ZERO_TOL * max(1.0, abs(float(ua.mean())), abs(float(ub.mean())))
        if not se > tol:  # zero (or numerically zero) variance: CIs are a single point
            if abs(diff) <= tol:
                excludes_zero = False
            reasons.append("the paired difference has zero variance across units: the CIs are a point")
        above_floor = noise_floor is None or abs(diff) > noise_floor
        if excludes_zero and above_floor:
            verdict = DISTINGUISHABLE
        else:
            verdict = INDISTINGUISHABLE
            if excludes_zero and not above_floor:
                reasons.append("CIs exclude zero but |diff| is within the A/A noise floor")
            elif abs(diff) < mde:
                reasons.append("observed |diff| is below the minimum detectable effect")
    return PairedResult(
        label_a=label_a,
        label_b=label_b,
        n_units=n,
        n_replicates=n_reps,
        mean_a=float(ua.mean()) if n else float("nan"),
        mean_b=float(ub.mean()) if n else float("nan"),
        diff=diff,
        sd_diff=sd,
        se_diff=se,
        ci_t=(float(ci_t[0]), float(ci_t[1])),
        ci_boot=(float(ci_boot[0]), float(ci_boot[1])),
        mde=float(mde),
        replicate_sd=_pooled_within_sd(a, b),
        noise_floor=noise_floor,
        verdict=verdict,
        reasons=reasons,
    )


@dataclass
class AAResult:
    comparison: PairedResult
    noise_floor: float

    def to_dict(self) -> dict:
        return {"comparison": self.comparison.to_dict(), "noise_floor": self.noise_floor}


def aa_test(run_1, run_2, label: str = "A", **kwargs) -> AAResult:
    """A/A test: the same message simulated twice over the same units.

    The noise floor is the largest absolute value inside the 95% t CI of the
    A/A difference: an A/B difference smaller than this is within what the
    pipeline produces when nothing changes. A ``"distinguishable"`` A/A verdict
    is a red flag (non-independent replicates, caching, drift between runs).

    When the A/A comparison is ``"not evaluable"`` (fewer than two units or
    two replicates) there is no usable floor: ``noise_floor`` is ``inf``
    (``null`` in JSON), so passing it to ``paired_ab`` can never yield
    ``"distinguishable"``.
    """
    res = paired_ab(run_1, run_2, label_a=f"{label} (run 1)", label_b=f"{label} (run 2)", **kwargs)
    if res.verdict == NOT_EVALUABLE:
        floor = math.inf
        res.reasons.append("A/A comparison not evaluable: no noise floor (inf)")
    else:
        floor = max(abs(res.ci_t[0]), abs(res.ci_t[1]))
    if res.verdict == DISTINGUISHABLE:
        res.reasons.append("A/A runs differ: check replicate independence and run-to-run drift")
    return AAResult(res, float(floor))


def aa_split_replicates(scores, label: str = "A", seed: int | None = 0, **kwargs) -> AAResult:
    """A/A from a single run: randomly split each unit's replicates in two halves.

    Scale: each half averages only ``R/2`` replicates, while the A/B analysis
    averages all ``R``. The replicate-noise part of this floor is therefore
    about ``√2`` times larger than it would be at the A/B's ``R``, so the floor
    is conservative (it makes ``"distinguishable"`` harder to reach). With
    fewer than 4 replicates each half has a single replicate and the A/A is
    not evaluable (floor ``inf``).
    """
    m = _as_matrix(scores)
    r = m.shape[1]
    if r < 2:
        raise ValueError("need at least two replicates to split")
    rng = np.random.default_rng(seed)
    h = r // 2
    first = np.empty((m.shape[0], h))
    second = np.full((m.shape[0], r - h), np.nan)
    for i, row in enumerate(m):
        p = rng.permutation(r)
        first[i] = row[p[:h]]
        second[i] = row[p[h:]]
    res = aa_test(first, second, label=label, seed=seed, **kwargs)
    if r < 4:
        res.comparison.reasons.append(
            f"only {r} replicates: each half has fewer than two; use >= 4 replicates to split"
        )
    return res


def matrices_from_records(
    records: Iterable[Mapping],
    unit_key: str,
    message_key: str,
    value_key: str,
    message_a: str,
    message_b: str,
) -> tuple[list, np.ndarray, np.ndarray, list[str]]:
    """Long-format records -> (unit_ids, A matrix, B matrix, notes).

    Replicates are taken in order of appearance; unequal replicate counts are
    padded with NaN. Units lacking either message are dropped.
    """
    vals: dict = defaultdict(lambda: {message_a: [], message_b: []})
    for rec in records:
        msg = str(rec[message_key])
        if msg not in (message_a, message_b):
            continue
        v = rec[value_key]
        if v is None or (isinstance(v, str) and v.strip() == ""):
            continue
        vals[rec[unit_key]][msg].append(float(v))
    notes: list[str] = []
    units = [u for u, d in vals.items() if d[message_a] and d[message_b]]
    dropped = len(vals) - len(units)
    if dropped:
        notes.append(f"dropped {dropped} unit(s) missing one of the messages")
    r = max([max(len(vals[u][message_a]), len(vals[u][message_b])) for u in units], default=0)
    A = np.full((len(units), r), np.nan)
    B = np.full((len(units), r), np.nan)
    for i, u in enumerate(units):
        A[i, : len(vals[u][message_a])] = vals[u][message_a]
        B[i, : len(vals[u][message_b])] = vals[u][message_b]
    return units, A, B, notes


def paired_ab_from_records(
    records: Iterable[Mapping],
    message_a: str,
    message_b: str,
    unit_key: str = "unit_id",
    message_key: str = "message",
    value_key: str = "score",
    **kwargs,
) -> PairedResult:
    _, A, B, notes = matrices_from_records(
        records, unit_key, message_key, value_key, message_a, message_b
    )
    res = paired_ab(A, B, label_a=message_a, label_b=message_b, **kwargs)
    res.reasons = notes + res.reasons
    return res
