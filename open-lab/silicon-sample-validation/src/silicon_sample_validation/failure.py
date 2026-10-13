"""Failure analysis: where does the silicon sample miss?

Breaks absolute and signed errors down by user-supplied columns such as
region, urbanization, presence of indigenous-language speakers, or the
dispersion of simulated answers. Numeric columns are cut into quantile bins.
"""

from __future__ import annotations

import math
from dataclasses import dataclass
from typing import Iterable, Mapping, Sequence

import numpy as np


@dataclass
class GroupError:
    column: str
    level: str
    n: int
    mae: float
    rmse: float
    bias: float
    share_of_abs_error: float
    small: bool


def _is_number(v) -> bool:
    if isinstance(v, bool):
        return False
    try:
        return math.isfinite(float(v))
    except (TypeError, ValueError):
        return False


def _levels(values: list, n_bins: int, treat_numeric: bool | None) -> list[str]:
    numeric = all(_is_number(v) for v in values) if treat_numeric is None else treat_numeric
    if numeric and len(set(values)) > n_bins:
        x = np.asarray([float(v) for v in values])
        edges = np.unique(np.quantile(x, np.linspace(0, 1, n_bins + 1)))
        out = []
        for v in x:
            k = int(np.searchsorted(edges, v, side="right") - 1)
            k = min(max(k, 0), len(edges) - 2)
            out.append(f"Q{k + 1} [{edges[k]:.3g}, {edges[k + 1]:.3g}]")
        return out
    return [str(v) for v in values]


def error_breakdown(
    records: Iterable[Mapping],
    by: Sequence[str],
    official_key: str = "official",
    estimate_key: str = "estimate",
    n_bins: int = 3,
    numeric: Mapping[str, bool] | None = None,
    min_n: int = 5,
) -> list[GroupError]:
    """Marginal error breakdown for each column in ``by``.

    ``numeric`` can force a column to be binned (True) or treated as
    categorical (False); by default numeric-looking columns with more than
    ``n_bins`` distinct values are binned into quantiles. Groups with fewer
    than ``min_n`` units are marked ``small`` - do not read much into them.
    """
    recs = list(records)
    if not recs:
        raise ValueError("no records")
    y = np.asarray([float(r[official_key]) for r in recs])
    x = np.asarray([float(r[estimate_key]) for r in recs])
    err = x - y
    total_abs = float(np.abs(err).sum()) or 1.0
    out: list[GroupError] = []
    for col in by:
        vals = [r[col] for r in recs]
        lv = _levels(vals, n_bins, None if numeric is None else numeric.get(col))
        for level in sorted(set(lv)):
            m = np.asarray([v == level for v in lv])
            e = err[m]
            out.append(
                GroupError(
                    column=col,
                    level=level,
                    n=int(m.sum()),
                    mae=float(np.abs(e).mean()),
                    rmse=float(math.sqrt((e**2).mean())),
                    bias=float(e.mean()),
                    share_of_abs_error=float(np.abs(e).sum() / total_abs),
                    small=bool(m.sum() < min_n),
                )
            )
    return out


def worst_units(
    records: Iterable[Mapping],
    k: int = 5,
    official_key: str = "official",
    estimate_key: str = "estimate",
    id_key: str = "unit_id",
) -> list[tuple[str, float]]:
    """The ``k`` units with the largest absolute error, as (id, signed error)."""
    rows = [(str(r[id_key]), float(r[estimate_key]) - float(r[official_key])) for r in records]
    rows.sort(key=lambda t: -abs(t[1]))
    return rows[:k]


def format_breakdown(groups: Sequence[GroupError]) -> str:
    lines = [f"{'column':<22}{'level':<26}{'n':>4}{'MAE':>8}{'bias':>8}{'share':>8}"]
    for g in groups:
        flag = "  (small n)" if g.small else ""
        lines.append(
            f"{g.column:<22}{g.level:<26}{g.n:>4}{g.mae:>8.3f}{g.bias:>8.3f}{g.share_of_abs_error:>8.2f}{flag}"
        )
    return "\n".join(lines)
