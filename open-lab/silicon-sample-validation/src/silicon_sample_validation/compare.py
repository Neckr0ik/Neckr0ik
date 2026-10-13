"""Compare simulated estimates with official figures and with baselines.

The method "counts" only if it beats every baseline: its MAE must be lower and
the paired bootstrap 95% CI of ``MAE_method - MAE_baseline`` (resampling units)
must lie entirely below zero.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Mapping, Sequence

import numpy as np

from . import metrics


@dataclass
class PairwiseComparison:
    name_a: str
    name_b: str
    mae_a: float
    mae_b: float
    diff: float  # mae_a - mae_b (negative = a is better)
    ci: tuple[float, float]
    skill: float  # 1 - mae_a / mae_b
    a_better: bool

    def to_dict(self) -> dict:
        d = self.__dict__.copy()
        d["ci"] = list(self.ci)
        return d


def compare_two(
    official,
    estimate_a,
    estimate_b,
    name_a: str = "a",
    name_b: str = "b",
    n_boot: int = 5000,
    level: float = 0.95,
    seed: int | None = 0,
) -> PairwiseComparison:
    """Paired bootstrap of the MAE difference between two sets of estimates."""
    y, a = metrics._pair(official, estimate_a)
    _, b = metrics._pair(official, estimate_b)
    ea, eb = np.abs(a - y), np.abs(b - y)
    d = ea - eb
    rng = np.random.default_rng(seed)
    idx = rng.integers(0, y.size, size=(n_boot, y.size))
    boots = d[idx].mean(axis=1)
    alpha = 1 - level
    lo, hi = np.quantile(boots, [alpha / 2, 1 - alpha / 2])
    mae_a, mae_b = float(ea.mean()), float(eb.mean())
    skill = 1 - mae_a / mae_b if mae_b > 0 else (0.0 if mae_a == 0 else -np.inf)
    return PairwiseComparison(
        name_a=name_a,
        name_b=name_b,
        mae_a=mae_a,
        mae_b=mae_b,
        diff=float(d.mean()),
        ci=(float(lo), float(hi)),
        skill=float(skill),
        a_better=bool(hi < 0),
    )


@dataclass
class ComparisonReport:
    method: str
    n_units: int
    method_scores: dict
    baseline_scores: dict[str, dict]
    vs_baselines: dict[str, PairwiseComparison]
    beats_all_baselines: bool
    verdict: str
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "method": self.method,
            "n_units": self.n_units,
            "method_scores": self.method_scores,
            "baseline_scores": self.baseline_scores,
            "vs_baselines": {k: v.to_dict() for k, v in self.vs_baselines.items()},
            "beats_all_baselines": self.beats_all_baselines,
            "verdict": self.verdict,
            "notes": self.notes,
        }

    def table(self) -> str:
        rows = [f"{'estimator':<46}{'MAE':>8}{'RMSE':>8}{'bias':>8}{'r':>7}"]
        def line(name, s):
            return f"{name:<46}{s['mae']:>8.3f}{s['rmse']:>8.3f}{s['bias']:>8.3f}{s['pearson']:>7.3f}"
        rows.append(line(self.method + " (method)", self.method_scores))
        for k, s in self.baseline_scores.items():
            rows.append(line(k, s))
        return "\n".join(rows)


def compare_to_baselines(
    official: Sequence[float],
    estimate: Sequence[float],
    baselines: Mapping[str, Sequence[float]],
    lower: Sequence[float] | None = None,
    upper: Sequence[float] | None = None,
    method: str = "silicon sample",
    nominal: float = 0.95,
    n_boot: int = 5000,
    seed: int | None = 0,
) -> ComparisonReport:
    if not baselines:
        raise ValueError("at least one baseline is required: a method with no baseline cannot 'count'")
    y = np.asarray(official, dtype=float)
    ms = metrics.score(y, estimate, lower, upper, nominal)
    bs = {k: metrics.score(y, v) for k, v in baselines.items()}
    vs = {
        k: compare_two(y, estimate, v, method, k, n_boot=n_boot, seed=seed)
        for k, v in baselines.items()
    }
    beats = all(c.a_better for c in vs.values())
    lost = [k for k, c in vs.items() if not c.a_better]
    notes: list[str] = []
    if y.size < 20:
        notes.append(f"only {y.size} units: CIs are wide and the bootstrap is approximate")
    if "coverage" in ms:
        gap = ms["coverage"] - nominal
        if abs(gap) > 0.10:
            notes.append(
                f"interval coverage {ms['coverage']:.2f} vs nominal {nominal:.2f}: intervals are "
                + ("too narrow (overconfident)" if gap < 0 else "too wide (underconfident)")
            )
    verdict = (
        "beats all baselines"
        if beats
        else "does not beat: " + ", ".join(lost) + " (report as a negative result)"
    )
    return ComparisonReport(method, int(y.size), ms, bs, vs, beats, verdict, notes)
