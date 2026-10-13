"""Command line interface: ``mx-census-sampler {prepare,sample,info}``."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import sample as draw_sample
from .data import SIZE_BANDS, filter_frame, load_frame
from .sampler import ALLOCATIONS, METHODS

PKG_ROOT = Path(__file__).resolve().parents[2]


def _csv_list(value: str | None) -> list[str] | None:
    return [v.strip() for v in value.split(",") if v.strip()] if value else None


def cmd_prepare(args) -> int:
    from .prepare import ITER_URL, run

    zip_path = Path(args.zip) if args.zip else None
    frame = run(
        out_csv=Path(args.out),
        raw_dir=Path(args.raw_dir),
        url=args.url or ITER_URL,
        zip_path=zip_path,
        force_download=args.force,
    )
    print(
        f"Wrote {args.out}: {len(frame):,} municipalities, "
        f"{int(frame['p_18ymas'].sum()):,} adults 18+.",
        file=sys.stderr,
    )
    return 0


def _frame(args):
    frame = load_frame(args.data)
    return filter_frame(
        frame,
        states=_csv_list(args.state),
        size_bands=_csv_list(args.size_band),
        municipalities=_csv_list(args.municipality),
    )


def cmd_sample(args) -> int:
    frame = _frame(args)
    result = draw_sample(
        frame,
        n=args.n,
        seed=args.seed,
        method=args.method,
        per_unit=args.per_unit,
        stratify=None if args.stratify == "none" else args.stratify,
        allocation=args.allocation,
    )
    if args.out == "-":
        result.to_csv(sys.stdout)
    elif args.out:
        result.to_csv(args.out)
        print(f"Wrote {len(result.respondents):,} respondents to {args.out}", file=sys.stderr)
    if args.summary_json:
        Path(args.summary_json).write_text(json.dumps(result.summary(), indent=2, ensure_ascii=False))
    if not args.quiet:
        print(result.summary_text(), file=sys.stderr if args.out == "-" else sys.stdout)
    return 0


def cmd_info(args) -> int:
    frame = _frame(args)
    print(f"{len(frame):,} municipalities, {int(frame['p_18ymas'].sum()):,} adults 18+")
    by_band = frame.groupby("size_band").agg(municipalities=("cvegeo", "size"), adults=("p_18ymas", "sum"))
    for band, (lo, hi) in SIZE_BANDS.items():
        if band in by_band.index:
            r = by_band.loc[band]
            hi_s = "∞" if hi == float("inf") else f"{int(hi):,}"
            print(f"  {band:<7} POBTOT [{int(lo):>7,}, {hi_s:>7}): {int(r.municipalities):>5,} municipalities, "
                  f"{int(r.adults):>12,} adults")
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="mx-census-sampler",
        description="PPS sampling of Mexican municipalities by adult population (INEGI Censo 2020, ITER).",
    )
    sub = p.add_subparsers(dest="command", required=True)

    pp = sub.add_parser("prepare", help="download ITER 2020 and rebuild data/municipios_cpv2020.csv")
    pp.add_argument("--out", default=str(PKG_ROOT / "data" / "municipios_cpv2020.csv"))
    pp.add_argument("--raw-dir", default=str(PKG_ROOT / "raw"), help="where the raw zip is cached (gitignored)")
    pp.add_argument("--zip", help="use an already-downloaded ITER zip instead of downloading")
    pp.add_argument("--url", help="override the ITER download URL")
    pp.add_argument("--force", action="store_true", help="re-download even if the zip is cached")
    pp.set_defaults(func=cmd_prepare)

    def add_frame_args(sp):
        sp.add_argument("--data", help="path to the municipal CSV (default: bundled data/)")
        sp.add_argument("--state", help="comma-separated 2-digit state codes, e.g. 09,15")
        sp.add_argument("--municipality", help="comma-separated 5-digit CVEGEO codes")
        sp.add_argument("--size-band", help=f"comma-separated size bands: {','.join(SIZE_BANDS)}")

    sp = sub.add_parser("sample", help="draw a PPS sample and assign respondent profiles")
    add_frame_args(sp)
    sp.add_argument("-n", "--n", type=int, required=True, help="number of PPS draws (units)")
    sp.add_argument("--per-unit", type=int, default=1, help="respondents per draw (default 1)")
    sp.add_argument("--seed", type=int, default=2027)
    sp.add_argument("--method", choices=METHODS, default="systematic")
    sp.add_argument("--stratify", choices=["none", "state"], default="none")
    sp.add_argument("--allocation", choices=ALLOCATIONS, default="proportional")
    sp.add_argument("--out", help="write respondents CSV here ('-' for stdout)")
    sp.add_argument("--summary-json", help="also write the summary as JSON")
    sp.add_argument("--quiet", action="store_true", help="do not print the summary")
    sp.set_defaults(func=cmd_sample)

    ip = sub.add_parser("info", help="describe the (filtered) frame")
    add_frame_args(ip)
    ip.set_defaults(func=cmd_info)
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except (ValueError, FileNotFoundError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
