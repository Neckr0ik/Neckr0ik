"""Command-line interface: ``llm-bias-kit <command> FILE.csv [options]``."""

from __future__ import annotations

import argparse
import json
import math
import sys
from typing import Sequence

from . import __version__
from .csvio import read_csv, require_columns
from .homogeneity import categorical_dispersion, numeric_dispersion, subgroup_sizes
from .kish import kish_by_group, kish_effective_n
from .order import estimate_order_effect
from .paired import aa_split_replicates, aa_test, matrices_from_records, paired_ab


def _fmt(x) -> str:
    if isinstance(x, float):
        if math.isnan(x):
            return "nan"
        if math.isinf(x):
            return "inf"
        return f"{x:.4f}"
    return str(x)


def _json_default(o):
    if isinstance(o, float) and (math.isnan(o) or math.isinf(o)):
        return None
    return str(o)


def _emit(obj: dict, as_json: bool, lines: list[str]) -> None:
    if as_json:
        print(json.dumps(obj, indent=2, ensure_ascii=False, default=_json_default))
    else:
        print("\n".join(lines))


def _paired_lines(r) -> list[str]:
    out = [
        f"{r.label_a} vs {r.label_b}: units={r.n_units} replicates={r.n_replicates}",
        f"  mean {r.label_a}={_fmt(r.mean_a)}  mean {r.label_b}={_fmt(r.mean_b)}",
        f"  paired diff={_fmt(r.diff)}  95% CI t=[{_fmt(r.ci_t[0])}, {_fmt(r.ci_t[1])}]"
        f"  bootstrap=[{_fmt(r.ci_boot[0])}, {_fmt(r.ci_boot[1])}]",
        f"  MDE (80% power)={_fmt(r.mde)}  within-unit replicate SD={_fmt(r.replicate_sd)}",
        f"  verdict: {r.verdict.upper()}",
    ]
    out += [f"  note: {x}" for x in r.reasons]
    return out


def cmd_order(a) -> int:
    rows = read_csv(a.file)
    require_columns(rows, [a.direction_col, a.choice_col], a.file)
    opts = [o.strip() for o in a.options.split(",")]
    r = estimate_order_effect(rows, opts, a.direction_col, a.choice_col, seed=a.seed)
    lines = [f"Answer-order effect: forward n={r.n_forward}, reversed n={r.n_reversed}"]
    for o in r.options:
        lo, hi = r.shift_ci[o]
        lines.append(
            f"  {o:<20} fwd={_fmt(r.share_forward[o])} rev={_fmt(r.share_reversed[o])}"
            f" shift={_fmt(r.shift[o])} [{_fmt(lo)}, {_fmt(hi)}] balanced={_fmt(r.balanced_share[o])}"
        )
    lines.append(f"  TVD={_fmt(r.tvd)} permutation p={_fmt(r.p_value)} primacy index={_fmt(r.primacy_index)}")
    lines.append("  ORDER-SENSITIVE" if r.flagged else "  no significant order effect detected")
    lines += [f"  note: {x}" for x in r.notes]
    _emit(r.to_dict(), a.json, lines)
    return 0


def _matrices(a, label_a, label_b, rows):
    require_columns(rows, [a.unit_col, a.message_col, a.value_col], a.file)
    return matrices_from_records(rows, a.unit_col, a.message_col, a.value_col, label_a, label_b)


def cmd_paired(a) -> int:
    rows = read_csv(a.file)
    _, A, B, notes = _matrices(a, a.a, a.b, rows)
    r = paired_ab(A, B, a.a, a.b, noise_floor=a.noise_floor, seed=a.seed)
    r.reasons = notes + r.reasons
    _emit(r.to_dict(), a.json, _paired_lines(r))
    return 0


def cmd_aa(a) -> int:
    rows = read_csv(a.file)
    if a.split:
        _, A, _, notes = _matrices(a, a.split, a.split, rows)
        res = aa_split_replicates(A, label=a.split, seed=a.seed)
    else:
        if not (a.a and a.b):
            raise SystemExit("aa: give --a and --b (two runs of the same message) or --split")
        _, A, B, notes = _matrices(a, a.a, a.b, rows)
        res = aa_test(A, B, label=a.a, seed=a.seed)
    res.comparison.reasons = notes + res.comparison.reasons
    lines = ["A/A test (same message twice)"] + _paired_lines(res.comparison)
    lines.append(f"  noise floor (max |95% CI bound|)={_fmt(res.noise_floor)}")
    _emit(res.to_dict(), a.json, lines)
    return 0


def cmd_homogeneity(a) -> int:
    rows = read_csv(a.file)
    require_columns(rows, [a.value_col], a.file)
    values = [r[a.value_col] for r in rows if r[a.value_col].strip() != ""]
    if a.numeric:
        sim = [float(v) for v in values]
        if a.reference_sd is not None:
            r = numeric_dispersion(sim, reference_sd=a.reference_sd, threshold=a.threshold, seed=a.seed)
        else:
            if not a.reference:
                raise SystemExit("homogeneity --numeric: give --reference CSV or --reference-sd")
            ref_rows = read_csv(a.reference)
            require_columns(ref_rows, [a.value_col], a.reference)
            ref = [float(x[a.value_col]) for x in ref_rows if x[a.value_col].strip() != ""]
            r = numeric_dispersion(sim, ref, threshold=a.threshold, seed=a.seed)
        lines = [
            f"Numeric dispersion: SD sim={_fmt(r.sd_simulated)} SD ref={_fmt(r.sd_reference)}"
            f" ratio={_fmt(r.sd_ratio)}"
            + (f" CI=[{_fmt(r.sd_ratio_ci[0])}, {_fmt(r.sd_ratio_ci[1])}]" if r.sd_ratio_ci else ""),
            "  TOO HOMOGENEOUS" if r.too_homogeneous else "  dispersion within threshold",
        ]
    else:
        if not a.reference:
            raise SystemExit("homogeneity: give --reference CSV with columns category,share")
        ref_rows = read_csv(a.reference)
        require_columns(ref_rows, [a.ref_category_col, a.ref_share_col], a.reference)
        ref = {x[a.ref_category_col]: float(x[a.ref_share_col]) for x in ref_rows}
        cats = list(ref)
        cats += sorted(set(values) - set(cats))
        r = categorical_dispersion(values, ref, cats, threshold=a.threshold, seed=a.seed)
        lines = [f"Categorical dispersion over {len(r.categories)} categories"]
        for c in r.categories:
            lines.append(f"  {c:<20} sim={_fmt(r.simulated[c])} ref={_fmt(r.reference[c])}")
        ci = r.entropy_ratio_ci
        lines.append(
            f"  normalised entropy sim={_fmt(r.entropy_simulated)} ref={_fmt(r.entropy_reference)}"
            f" ratio={_fmt(r.entropy_ratio)}" + (f" CI=[{_fmt(ci[0])}, {_fmt(ci[1])}]" if ci else "")
        )
        lines.append(f"  TVD={_fmt(r.tvd)} modal share sim={_fmt(r.modal_share_simulated)} ref={_fmt(r.modal_share_reference)}")
        lines.append("  TOO HOMOGENEOUS" if r.too_homogeneous else "  dispersion within threshold")
    _emit(r.to_dict(), a.json, lines)
    return 0


def cmd_subgroups(a) -> int:
    rows = read_csv(a.file)
    keys = [k.strip() for k in a.by.split(",")]
    require_columns(rows, keys + [a.unit_col], a.file)
    cells = subgroup_sizes(rows, keys, a.unit_col, a.min_units)
    lines = [f"Subgroup cuts by {', '.join(keys)} (min units = {a.min_units})"]
    for c in cells:
        label = ", ".join(f"{k}={v}" for k, v in c.group.items())
        lines.append(f"  {label:<40} units={c.n_units:<5} rows={c.n_rows:<6} {'ok' if c.reportable else 'TOO FEW UNITS'}")
    thin = sum(not c.reportable for c in cells)
    lines.append(f"  {thin} of {len(cells)} cell(s) below the minimum")
    _emit({"min_units": a.min_units, "cells": [c.__dict__ for c in cells]}, a.json, lines)
    return 0 if thin == 0 or not a.strict else 2


def cmd_kish(a) -> int:
    rows = read_csv(a.file)
    require_columns(rows, [a.weight_col] + ([a.by] if a.by else []), a.file)
    overall = kish_effective_n([float(r[a.weight_col]) for r in rows])
    lines = [
        f"Kish effective n: n={overall.n} n_eff={_fmt(overall.effective_n)}"
        f" deff={_fmt(overall.design_effect)} efficiency={_fmt(overall.efficiency)}"
    ]
    obj: dict = {"overall": overall.to_dict()}
    if a.by:
        groups = kish_by_group(rows, a.by, a.weight_col)
        obj["by_group"] = {str(g): k.to_dict() for g, k in groups.items()}
        for g, k in groups.items():
            lines.append(f"  {a.by}={g:<20} n={k.n:<5} n_eff={_fmt(k.effective_n)} deff={_fmt(k.design_effect)}")
    _emit(obj, a.json, lines)
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="llm-bias-kit", description=__doc__)
    p.add_argument("--version", action="version", version=__version__)
    sub = p.add_subparsers(dest="command", required=True)

    def common(sp, long=True):
        sp.add_argument("file", help="CSV of responses")
        sp.add_argument("--json", action="store_true", help="print JSON")
        sp.add_argument("--seed", type=int, default=0)
        if long:
            sp.add_argument("--unit-col", default="unit_id")
            sp.add_argument("--message-col", default="message")
            sp.add_argument("--value-col", default="score")

    sp = sub.add_parser("order", help="answer-order (position) effect")
    common(sp, long=False)
    sp.add_argument("--options", required=True, help="comma-separated options in canonical order")
    sp.add_argument("--direction-col", default="direction")
    sp.add_argument("--choice-col", default="choice")
    sp.set_defaults(func=cmd_order)

    sp = sub.add_parser("paired", help="paired A/B comparison of two messages")
    common(sp)
    sp.add_argument("--a", required=True)
    sp.add_argument("--b", required=True)
    sp.add_argument("--noise-floor", type=float, default=None)
    sp.set_defaults(func=cmd_paired)

    sp = sub.add_parser("aa", help="A/A test (noise floor)")
    common(sp)
    sp.add_argument("--a", help="label of run 1")
    sp.add_argument("--b", help="label of run 2")
    sp.add_argument("--split", help="split this message's replicates into two halves")
    sp.set_defaults(func=cmd_aa)

    sp = sub.add_parser("homogeneity", help="dispersion vs a human reference")
    sp.add_argument("file")
    sp.add_argument("--json", action="store_true")
    sp.add_argument("--seed", type=int, default=0)
    sp.add_argument("--value-col", default="choice")
    sp.add_argument("--reference", help="reference CSV")
    sp.add_argument("--ref-category-col", default="category")
    sp.add_argument("--ref-share-col", default="share")
    sp.add_argument("--numeric", action="store_true", help="treat answers as numeric")
    sp.add_argument("--reference-sd", type=float, default=None)
    sp.add_argument("--threshold", type=float, default=0.8)
    sp.set_defaults(func=cmd_homogeneity)

    sp = sub.add_parser("subgroups", help="flag subgroup cuts with too few units")
    sp.add_argument("file")
    sp.add_argument("--json", action="store_true")
    sp.add_argument("--by", required=True, help="comma-separated grouping columns")
    sp.add_argument("--unit-col", default="unit_id")
    sp.add_argument("--min-units", type=int, default=12)
    sp.add_argument("--strict", action="store_true", help="exit 2 if any cell is too thin")
    sp.set_defaults(func=cmd_subgroups)

    sp = sub.add_parser("kish", help="Kish effective sample size")
    sp.add_argument("file")
    sp.add_argument("--json", action="store_true")
    sp.add_argument("--weight-col", default="weight")
    sp.add_argument("--by", default=None)
    sp.set_defaults(func=cmd_kish)
    return p


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except (ValueError, KeyError, FileNotFoundError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
