"""Answer-order (position) bias.

LLMs answering multiple-choice survey items are sensitive to the order in which
options are listed (Dominguez-Olmedo, Hardt & Mendler-Dünner, 2024). The
standard remedy is counterbalancing: half of the batches see the options in
their canonical ("forward") order and half in reversed order. Comparing the two
halves estimates the order effect; averaging them gives an order-balanced
distribution.

Repeated answers from the same simulated unit (replicates, or several items
from one persona) are not independent. When the direction is assigned per
unit, pass ``unit_key`` so the test permutes direction labels across *units*
and bootstraps *units*; treating every response as independent makes the
p-value far too small (a per-unit preference looks like an order effect).
"""

from __future__ import annotations

import warnings
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Iterable, Mapping, Sequence

import numpy as np

from ._stats import percentile_ci

FORWARD = "forward"
REVERSED = "reversed"


@dataclass(frozen=True)
class OrderPlan:
    """Option order to show in one batch."""

    batch: int
    direction: str
    order: tuple[str, ...]


def build_option_orders(
    options: Sequence[str],
    n_batches: int,
    scheme: str = "reverse",
) -> list[OrderPlan]:
    """Build counterbalanced option orders for ``n_batches`` batches.

    ``scheme="reverse"`` alternates forward / reversed (batch 0 forward).
    ``scheme="rotate"`` cycles through the k rotations of the option list,
    labelling each ``rotation-i``; use it when you also want to separate
    primacy from specific-position effects.
    """
    opts = tuple(options)
    if len(opts) < 2:
        raise ValueError("need at least two options")
    if len(set(opts)) != len(opts):
        raise ValueError("options must be unique")
    if n_batches < 1:
        raise ValueError("n_batches must be >= 1")
    plans: list[OrderPlan] = []
    for b in range(n_batches):
        if scheme == "reverse":
            if b % 2 == 0:
                plans.append(OrderPlan(b, FORWARD, opts))
            else:
                plans.append(OrderPlan(b, REVERSED, tuple(reversed(opts))))
        elif scheme == "rotate":
            r = b % len(opts)
            plans.append(OrderPlan(b, f"rotation-{r}", opts[r:] + opts[:r]))
        else:
            raise ValueError("scheme must be 'reverse' or 'rotate'")
    return plans


def assign_directions(unit_ids: Sequence, seed: int | None = 0) -> dict:
    """Randomly assign units to forward/reversed so each half has ~n/2 units."""
    ids = list(unit_ids)
    rng = np.random.default_rng(seed)
    perm = rng.permutation(len(ids))
    out = {}
    for rank, idx in enumerate(perm):
        out[ids[idx]] = FORWARD if rank % 2 == 0 else REVERSED
    return out


@dataclass
class OrderEffect:
    options: tuple[str, ...]
    n_forward: int
    n_reversed: int
    share_forward: dict[str, float]
    share_reversed: dict[str, float]
    shift: dict[str, float]
    shift_ci: dict[str, tuple[float, float]]
    tvd: float
    tvd_ci: tuple[float, float]
    p_value: float
    primacy_index: float
    balanced_share: dict[str, float]
    flagged: bool
    notes: list[str] = field(default_factory=list)
    n_units_forward: int | None = None  # set when the analysis is clustered by unit
    n_units_reversed: int | None = None
    resampling: str = "response"  # "unit" when unit_key was given

    def to_dict(self) -> dict:
        d = self.__dict__.copy()
        d["options"] = list(self.options)
        d["shift_ci"] = {k: list(v) for k, v in self.shift_ci.items()}
        d["tvd_ci"] = list(self.tvd_ci)
        return d


def _shares(codes: np.ndarray, k: int) -> np.ndarray:
    if codes.size == 0:
        return np.full(k, np.nan)
    return np.bincount(codes, minlength=k) / codes.size


def _pooled(counts: np.ndarray) -> np.ndarray:
    """Share of each option over all responses of the selected units (rows)."""
    col = counts.sum(axis=0)
    return col / col.sum()


def _unit_counts(responses, index, direction_key, choice_key, unit_key):
    """Group responses by unit -> (units x options count matrix, is-forward vector)."""
    k = len(index)
    by_unit: dict = defaultdict(lambda: np.zeros(k, dtype=float))
    unit_dir: dict = {}
    for r in responses:
        d = str(r[direction_key]).strip().lower()
        c = r[choice_key]
        if c not in index:
            raise ValueError(f"choice {c!r} not among options")
        if d not in (FORWARD, REVERSED):
            raise ValueError(f"direction must be forward/reversed, got {d!r}")
        u = r[unit_key]
        if unit_dir.setdefault(u, d) != d:
            raise ValueError(
                f"unit {u!r} has both forward and reversed responses; the unit-level test needs one "
                "direction per unit (assign_directions). For a within-unit design, analyse each "
                "unit's forward-minus-reversed difference with paired_ab instead"
            )
        by_unit[u][index[c]] += 1
    units = list(by_unit)
    counts = np.array([by_unit[u] for u in units]) if units else np.zeros((0, k))
    is_fwd = np.array([unit_dir[u] == FORWARD for u in units], dtype=bool)
    return counts, is_fwd

def estimate_order_effect(
    responses: Iterable[Mapping],
    options: Sequence[str],
    direction_key: str = "direction",
    choice_key: str = "choice",
    n_boot: int = 2000,
    n_perm: int = 2000,
    alpha: float = 0.05,
    seed: int | None = 0,
    unit_key: str | None = None,
) -> OrderEffect:
    """Estimate the answer-order effect from forward vs reversed responses.

    Each response is a mapping with a direction (``"forward"``/``"reversed"``)
    and the chosen option label (in canonical terms, not its displayed
    position). Returns per-option share shifts (forward minus reversed) with
    bootstrap CIs, the total-variation distance (TVD) between the two
    distributions with a permutation p-value, and a primacy index:

    ``primacy_index = ½[(f[first] - r[first]) + (r[last] - f[last])]``

    where ``first``/``last`` are the canonical first/last options. Positive
    values mean options gain share when shown first (primacy); negative values
    mean recency. A model that always picks the first displayed option scores
    +1; one that ignores order scores 0.

    ``unit_key`` names the simulated-unit id. With it, the direction labels are
    permuted across units and the bootstrap resamples units (a cluster
    bootstrap), so several answers from one unit count as one draw; each unit
    must have a single direction. Without it every response is treated as an
    independent draw, which is only valid with one response per unit; a
    ``UserWarning`` says so.
    """
    opts = tuple(options)
    k = len(opts)
    index = {o: i for i, o in enumerate(opts)}
    if unit_key is not None:
        return _clustered_order_effect(responses, opts, index, direction_key, choice_key, unit_key,
                                       n_boot, n_perm, alpha, seed)
    warnings.warn(
        "estimate_order_effect: no unit_key given, so every response is treated as an independent "
        "draw. If units answered more than once, pass unit_key or the p-value will be too small.",
        UserWarning, stacklevel=2)
    fwd, rev = [], []
    notes = ["responses treated as independent (no unit_key): valid only with one response per unit"]
    for r in responses:
        d = str(r[direction_key]).strip().lower()
        c = r[choice_key]
        if c not in index:
            raise ValueError(f"choice {c!r} not among options")
        if d == FORWARD:
            fwd.append(index[c])
        elif d == REVERSED:
            rev.append(index[c])
        else:
            raise ValueError(f"direction must be forward/reversed, got {d!r}")
    f = np.asarray(fwd, dtype=int)
    r_ = np.asarray(rev, dtype=int)
    if f.size == 0 or r_.size == 0:
        raise ValueError("need responses in both forward and reversed order")
    if min(f.size, r_.size) < 30:
        notes.append("fewer than 30 responses in one direction: estimates are noisy")

    pf, pr = _shares(f, k), _shares(r_, k)
    shift = pf - pr
    tvd = 0.5 * float(np.abs(shift).sum())

    rng = np.random.default_rng(seed)
    boot_shift = np.empty((n_boot, k))
    boot_tvd = np.empty(n_boot)
    for b in range(n_boot):
        bf = _shares(f[rng.integers(0, f.size, f.size)], k)
        br = _shares(r_[rng.integers(0, r_.size, r_.size)], k)
        boot_shift[b] = bf - br
        boot_tvd[b] = 0.5 * np.abs(bf - br).sum()

    pooled = np.concatenate([f, r_])
    exceed = 0
    for _ in range(n_perm):
        perm = rng.permutation(pooled)
        pf_p = _shares(perm[: f.size], k)
        pr_p = _shares(perm[f.size:], k)
        if 0.5 * np.abs(pf_p - pr_p).sum() >= tvd - 1e-12:
            exceed += 1
    p_value = (exceed + 1) / (n_perm + 1)

    primacy = 0.5 * ((pf[0] - pr[0]) + (pr[-1] - pf[-1]))
    balanced = 0.5 * (pf + pr)
    if f.size != r_.size:
        notes.append("unequal forward/reversed counts: balanced share weights each direction equally")

    return OrderEffect(
        options=opts,
        n_forward=int(f.size),
        n_reversed=int(r_.size),
        share_forward={o: float(pf[i]) for i, o in enumerate(opts)},
        share_reversed={o: float(pr[i]) for i, o in enumerate(opts)},
        shift={o: float(shift[i]) for i, o in enumerate(opts)},
        shift_ci={o: percentile_ci(boot_shift[:, i]) for i, o in enumerate(opts)},
        tvd=tvd,
        tvd_ci=percentile_ci(boot_tvd),
        p_value=float(p_value),
        primacy_index=float(primacy),
        balanced_share={o: float(balanced[i]) for i, o in enumerate(opts)},
        flagged=bool(p_value < alpha),
        notes=notes,
    )


def _clustered_order_effect(responses, opts, index, direction_key, choice_key, unit_key,
                            n_boot, n_perm, alpha, seed) -> OrderEffect:
    k = len(opts)
    counts, is_fwd = _unit_counts(responses, index, direction_key, choice_key, unit_key)
    uf, ur = counts[is_fwd], counts[~is_fwd]
    if uf.shape[0] == 0 or ur.shape[0] == 0:
        raise ValueError("need responses in both forward and reversed order")
    n_f, n_r = int(uf.sum()), int(ur.sum())
    notes: list[str] = []
    if min(uf.shape[0], ur.shape[0]) < 30:
        notes.append("fewer than 30 units in one direction: estimates are noisy")
    if min(uf.shape[0], ur.shape[0]) < 10:
        notes.append("fewer than 10 units in one direction: the permutation test has little power")

    pf, pr = _pooled(uf), _pooled(ur)
    shift = pf - pr
    tvd = 0.5 * float(np.abs(shift).sum())

    rng = np.random.default_rng(seed)
    # Cluster bootstrap: resample units within each direction.
    boot_shift = np.empty((n_boot, k))
    for b in range(n_boot):
        boot_shift[b] = (_pooled(uf[rng.integers(0, uf.shape[0], uf.shape[0])])
                         - _pooled(ur[rng.integers(0, ur.shape[0], ur.shape[0])]))
    boot_tvd = 0.5 * np.abs(boot_shift).sum(axis=1)

    # Permutation: shuffle direction labels across units (keeping the number of units per direction).
    n_units, n_fu = counts.shape[0], uf.shape[0]
    total = counts.sum(axis=0)
    exceed = 0
    for _ in range(n_perm):
        sel = rng.permutation(n_units)[:n_fu]
        cf = counts[sel].sum(axis=0)
        cr = total - cf
        sf, sr = cf.sum(), cr.sum()
        if sf == 0 or sr == 0:
            continue  # cannot happen with >= 1 response per unit; kept for safety
        if 0.5 * np.abs(cf / sf - cr / sr).sum() >= tvd - 1e-12:
            exceed += 1
    p_value = (exceed + 1) / (n_perm + 1)

    primacy = 0.5 * ((pf[0] - pr[0]) + (pr[-1] - pf[-1]))
    balanced = 0.5 * (pf + pr)
    if n_f != n_r:
        notes.append("unequal forward/reversed counts: balanced share weights each direction equally")
    return OrderEffect(
        options=opts,
        n_forward=n_f,
        n_reversed=n_r,
        share_forward={o: float(pf[i]) for i, o in enumerate(opts)},
        share_reversed={o: float(pr[i]) for i, o in enumerate(opts)},
        shift={o: float(shift[i]) for i, o in enumerate(opts)},
        shift_ci={o: percentile_ci(boot_shift[:, i]) for i, o in enumerate(opts)},
        tvd=tvd,
        tvd_ci=percentile_ci(boot_tvd),
        p_value=float(p_value),
        primacy_index=float(primacy),
        balanced_share={o: float(balanced[i]) for i, o in enumerate(opts)},
        flagged=bool(p_value < alpha),
        notes=notes,
        n_units_forward=int(uf.shape[0]),
        n_units_reversed=int(ur.shape[0]),
        resampling="unit",
    )
