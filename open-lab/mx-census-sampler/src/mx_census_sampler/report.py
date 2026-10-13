"""Summary report for a drawn sample."""

from __future__ import annotations

import pandas as pd

from .profiles import frame_targets
from .sampler import MOS_COLUMN


def _weighted_dist(df: pd.DataFrame, col: str, order) -> pd.Series:
    s = df.groupby(col)["weight"].sum().reindex(list(order), fill_value=0.0)
    return s / s.sum()


def summarize(result) -> dict:
    d, frame, draws, resp = result.design, result.frame, result.draws, result.respondents
    targets = frame_targets(frame)
    dims = {}
    for col, target in targets.items():
        dims[col] = {
            k: {"frame": float(target[k]), "sample_weighted": float(v)}
            for k, v in _weighted_dist(resp, col, target.index).items()
        }
    strata = (
        draws.groupby("stratum")
        .agg(n_h=("n_h", "first"), mos_h=("mos_h", "first"), distinct_units=("cvegeo", "nunique"))
        .reset_index()
    )
    w = resp["weight"]
    return {
        "design": {
            "method": d.method,
            "n_draws": d.n,
            "per_unit": d.per_unit,
            "stratify": d.stratify,
            "allocation": d.allocation,
            "seed": d.seed,
        },
        "frame": {
            "municipalities": int(len(frame)),
            "states": int(frame["cve_ent"].nunique()),
            "adults_18plus": int(frame[MOS_COLUMN].sum()),
        },
        "sample": {
            "draws": int(len(draws)),
            "distinct_municipalities": int(draws["cvegeo"].nunique()),
            "multi_hit_municipalities": int((draws["cvegeo"].value_counts() > 1).sum()),
            "respondents": int(len(resp)),
            "sum_weights": float(w.sum()),
            "weight_min": float(w.min()),
            "weight_max": float(w.max()),
            "kish_ess": result.ess,
            "kish_deff": result.deff,
        },
        "strata": strata.to_dict(orient="records"),
        "distributions": dims,
        "fingerprint": result.fingerprint(),
    }


def format_summary(s: dict) -> str:
    d, f, sm = s["design"], s["frame"], s["sample"]
    lines = [
        "mx-census-sampler — sample summary",
        f"  design      : {d['method']} PPS, n={d['n_draws']} draws × {d['per_unit']} per unit, "
        f"stratify={d['stratify'] or 'none'}, allocation={d['allocation']}, seed={d['seed']}",
        f"  frame       : {f['municipalities']:,} municipalities in {f['states']} state(s), "
        f"{f['adults_18plus']:,} adults 18+ (INEGI Censo 2020, ITER)",
        f"  sample      : {sm['respondents']:,} respondents in {sm['distinct_municipalities']:,} distinct "
        f"municipalities ({sm['multi_hit_municipalities']} hit more than once)",
        f"  weights     : sum={sm['sum_weights']:,.0f}  min={sm['weight_min']:,.1f}  max={sm['weight_max']:,.1f}",
        f"  Kish ESS    : {sm['kish_ess']:,.1f}  (deff_w = {sm['kish_deff']:.3f})",
    ]
    for dim, rows in s["distributions"].items():
        lines.append(f"  {dim:<11} : " + "  ".join(
            f"{k} {v['sample_weighted']:.1%} (census {v['frame']:.1%})" for k, v in rows.items()
        ))
    if len(s["strata"]) > 1:
        lines.append("  strata      : " + ", ".join(f"{r['stratum']}:{r['n_h']}" for r in s["strata"]))
    lines.append(f"  fingerprint : {s['fingerprint']}")
    lines.append("  note        : simulated respondents for research design — not survey results.")
    return "\n".join(lines)
