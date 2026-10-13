"""End-to-end walk-through on SYNTHETIC data (no network, no LLM).

Run with ``ssv demo`` or ``python examples/demo_synthetic.py``. Every number
printed is computed from invented data and is NOT a result about any real
method, model, survey or place.
"""

from __future__ import annotations

import shutil
import tempfile
from datetime import datetime, timezone
from pathlib import Path

import numpy as np

from .baselines import build_baselines
from .compare import compare_to_baselines, compare_two
from .cutoff import filter_post_cutoff
from .failure import error_breakdown, format_breakdown, worst_units
from .probe import MockLLM, ProbeTarget, run_memorization_probe
from .registry import ForecastRegistry
from .synthetic import SYNTHETIC_LABEL, make_synthetic_dataset

TRAINING_CUTOFF = "2026-06-30"  # declared cutoff of the (imaginary) model
SEED = 2027


def run_demo(workdir: str | Path | None = None, out=print) -> dict:
    banner = "=" * 72
    out(banner)
    out(f"  {SYNTHETIC_LABEL}")
    out("  Every figure below comes from a random-number generator (seed 2027).")
    out("  It demonstrates the harness; it says nothing about any real method.")
    out(banner)

    rows = make_synthetic_dataset(seed=SEED)
    tmp = Path(workdir) if workdir else Path(tempfile.mkdtemp(prefix="ssv-demo-"))
    reg_path = tmp / "synthetic_forecasts.jsonl"
    if reg_path.exists():
        reg_path.unlink()

    # 1. Pre-register forecasts (fixed clock so the demo is reproducible).
    clock = lambda: datetime(2026, 12, 1, 12, 0, tzinfo=timezone.utc)  # noqa: E731
    reg = ForecastRegistry(reg_path, clock=clock)
    for r in rows:
        reg.append(
            r["unit_id"], r["simulated_anchored"], r["lower"], r["upper"],
            model="mock-model (synthetic)", method="anchored", seed=SEED,
            metadata={"synthetic": True},
        )
    rep = reg.verify()
    out(f"\n[1] Registry: {rep.n_entries} synthetic forecasts, chain ok={rep.ok}")
    out(f"    head hash (publish this before release): {rep.head_hash[:16]}...")

    # 2. Guards: pre-registration + training cutoff.
    pre = reg.preregistered({r["unit_id"]: r["published_at"] for r in rows})
    not_prereg = [u for u, e in pre.items() if e is None]
    cut = filter_post_cutoff(rows, TRAINING_CUTOFF)
    eligible = [r for r in cut.eligible if pre[r["unit_id"]] is not None]
    out(f"\n[2] Training cutoff {TRAINING_CUTOFF}: {len(cut.eligible)} eligible, {len(cut.excluded)} excluded")
    for t, why in cut.excluded[:2]:
        out(f"    excluded {t['unit_id']}: {why}")
    out(f"    forecasts registered after release (not scored): {len(not_prereg)}")
    out(f"    scored units: {len(eligible)}")

    # 3. Compare with naive baselines.
    y = np.array([r["official"] for r in eligible])
    est = np.array([pre[r["unit_id"]]["record"]["estimate"] for r in eligible])
    lo = np.array([pre[r["unit_id"]]["record"]["lower"] for r in eligible])
    hi = np.array([pre[r["unit_id"]]["record"]["upper"] for r in eligible])
    X = np.array([[r["urbanization"], r["share_university"], r["share_over_65"]] for r in eligible])
    prev = np.array([r["previous"] for r in eligible])
    base = build_baselines(prev, covariates=X)
    report = compare_to_baselines(y, est, base, lo, hi, method="anchored (synthetic)", seed=SEED)
    out("\n[3] Synthetic method vs naive baselines")
    out("    " + report.table().replace("\n", "\n    "))
    for k, c in report.vs_baselines.items():
        out(f"    vs {k:<24} dMAE={c.diff:+.3f} 95% CI [{c.ci[0]:+.3f}, {c.ci[1]:+.3f}] skill={c.skill:+.2f}")
    ms = report.method_scores
    out(f"    interval coverage {ms['coverage']:.2f} (nominal 0.95), mean width {ms['mean_width']:.2f}")
    out(f"    verdict on SYNTHETIC data: {report.verdict}")
    for n in report.notes:
        out(f"    note: {n}")

    # 4. Anchored vs demographics-only.
    demo = np.array([r["simulated_demographic_only"] for r in eligible])
    rq3 = compare_two(y, est, demo, "anchored", "demographics-only", seed=SEED)
    out("\n[4] Anchored vs demographics-only (synthetic)")
    out(f"    MAE {rq3.mae_a:.3f} vs {rq3.mae_b:.3f}; dMAE 95% CI [{rq3.ci[0]:+.3f}, {rq3.ci[1]:+.3f}]"
        f" -> anchored better: {rq3.a_better}")

    # 5. Failure analysis.
    recs = [dict(r, estimate=pre[r["unit_id"]]["record"]["estimate"]) for r in eligible]
    groups = error_breakdown(recs, ["region", "urbanization", "indigenous_language", "dispersion"])
    out("\n[5] Where the synthetic method misses")
    out("    " + format_breakdown(groups).replace("\n", "\n    "))
    out("    worst units: " + ", ".join(f"{u} ({e:+.1f})" for u, e in worst_units(recs, 3)))

    # 6. Memorization probe with a mock that 'knows' two figures.
    targets = [
        ProbeTarget(r["unit_id"], "synthetic indicator (%)", r["unit_id"], "synthetic survey",
                    "2026", r["official"], unit="%", naive_guess=float(np.mean(prev)))
        for r in eligible
    ]
    mock = MockLLM.memorizing(targets, ids=[targets[0].target_id, targets[5].target_id])
    probe = run_memorization_probe(mock, targets)
    out("\n[6] Memorization probe (MockLLM that 'memorized' 2 synthetic figures)")
    out(f"    asked {probe.n_targets}, answered {probe.n_answered}, flagged {probe.n_flagged}: {probe.flagged_ids}")

    # 7. Tamper detection.
    tampered = tmp / "tampered.jsonl"
    shutil.copy(reg_path, tampered)
    lines = tampered.read_text(encoding="utf-8").splitlines()
    lines[3] = lines[3].replace('"estimate":', '"estimate":1', 1)
    tampered.write_text("\n".join(lines) + "\n", encoding="utf-8")
    trep = ForecastRegistry(tampered).verify()
    out("\n[7] Editing one past forecast breaks the chain:")
    out(f"    ok={trep.ok}; first error: {trep.errors[0] if trep.errors else '-'}")
    out("\n" + banner)
    out(f"  {SYNTHETIC_LABEL}")
    out(banner)
    return {
        "registry": str(reg_path),
        "report": report,
        "anchored_vs_demographic": rq3,
        "breakdown": groups,
        "probe": probe,
        "tamper_detected": not trep.ok,
    }
