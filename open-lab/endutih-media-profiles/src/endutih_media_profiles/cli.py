"""CLIs: ``endutih-profiles`` (query) and ``endutih-profiles-prepare`` (build)."""

from __future__ import annotations

import argparse
import json
import math
import sys
from pathlib import Path

from .indicators import HOUSEHOLD_INDICATORS, PERSON_INDICATORS
from .query import DEFAULT_EDITION, profile

PKG_ROOT = Path(__file__).resolve().parents[2]


def _pct(x) -> str:
    return "  —  " if x is None or (isinstance(x, float) and math.isnan(x)) else f"{100 * x:5.1f}%"


def format_table(df) -> str:
    a = df.attrs
    c = a["cell"]
    head = (
        f"ENDUTIH {a['edition']} · {a['table']} · state={c['state']} ({a['state_name']})"
        + (f" · sex={c['sex']} · age={c['age']}" if a["table"] == "persons" else "")
        + f" · area={c['area']}"
    )
    pop = a["pop"]
    lines = [
        head,
        f"unweighted n = {a['n']:,}" + ("" if pop is None or (isinstance(pop, float) and math.isnan(pop))
                                         else f" · weighted = {int(pop):,}"),
        "",
    ]
    has_nat = "national_share" in df.columns
    hdr = f"{'indicator':<24} {'share':>6} {'95% CI':>15} {'n':>6}" + (f" {'national':>8}" if has_nat else "")
    lines += [hdr, "-" * len(hdr)]
    for r in df.itertuples():
        ci = "" if r.suppressed else f"{100 * r.ci95_low:5.1f}–{100 * r.ci95_high:5.1f}%"
        line = f"{r.indicator:<24} {_pct(r.share):>6} {ci:>15} {r.n:>6}"
        if has_nat:
            line += f" {_pct(r.national_share):>8}"
        lines.append(line)
    lines += [
        "",
        "Weighted with ENDUTIH expansion factors; cells with n < 30 suppressed (—).",
        "Shares are of all persons 6+ (or households) in the cell. Estimates computed",
        "from INEGI public microdata — not official INEGI tabulations.",
        f"Fuente: INEGI, ENDUTIH {a['edition']}.",
    ]
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(
        prog="endutih-profiles",
        description="Query media & technology use profiles for Mexico (INEGI ENDUTIH).",
    )
    p.add_argument("--state", help="2-digit INEGI state code (01–32); default national")
    p.add_argument("--sex", help="male | female (default all)")
    p.add_argument("--age", help="6-11 | 12-17 | 18-29 | 30-44 | 45-59 | 60+ | 18+ (default all)")
    p.add_argument("--area", help="urban | rural (default all)")
    p.add_argument("--households", action="store_true", help="query the household table (state × area)")
    p.add_argument("--indicators", help="comma-separated indicator keys (default all)")
    p.add_argument("--edition", type=int, default=DEFAULT_EDITION)
    p.add_argument("--data-dir", help="directory with the aggregated CSVs (default bundled data/)")
    p.add_argument("--format", choices=["table", "csv", "json"], default="table")
    p.add_argument("--no-national", action="store_true", help="omit the national comparison column")
    p.add_argument("--list", action="store_true", help="list indicator keys and exit")
    args = p.parse_args(argv)

    if args.list:
        for i in (*PERSON_INDICATORS, *HOUSEHOLD_INDICATORS):
            print(f"{i.table:<10} {i.key:<24} {i.label_en}")
        return 0
    try:
        df = profile(
            state=args.state, sex=args.sex, age=args.age, area=args.area,
            table="households" if args.households else "persons",
            edition=args.edition,
            indicators=[k.strip() for k in args.indicators.split(",")] if args.indicators else None,
            directory=args.data_dir,
            compare_national=not args.no_national,
        )
    except (ValueError, FileNotFoundError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    if args.format == "csv":
        sys.stdout.write(df.to_csv(index=False, lineterminator="\n"))
    elif args.format == "json":
        payload = {
            "edition": df.attrs["edition"], "table": df.attrs["table"], "cell": df.attrs["cell"],
            "n": df.attrs["n"], "source": f"INEGI, ENDUTIH {df.attrs['edition']} (estimates from public microdata)",
            "indicators": json.loads(df.to_json(orient="records")),
        }
        print(json.dumps(payload, indent=2, ensure_ascii=False))
    else:
        print(format_table(df))
    return 0


def main_prepare(argv: list[str] | None = None) -> int:
    from .prepare import DEFAULT_EDITION as ED, run

    p = argparse.ArgumentParser(prog="endutih-profiles-prepare",
                                description="Download ENDUTIH microdata and rebuild the aggregated tables.")
    p.add_argument("--edition", type=int, default=ED)
    p.add_argument("--zip", help="use an already-downloaded ENDUTIH CSV zip")
    p.add_argument("--url", help="override the download URL")
    p.add_argument("--raw-dir", default=str(PKG_ROOT / "raw"), help="cache for raw microdata (gitignored)")
    p.add_argument("--out-dir", default=str(PKG_ROOT / "data"))
    p.add_argument("--min-n", type=int, default=30, help="suppress cells with fewer respondents (default 30)")
    p.add_argument("--force", action="store_true")
    a = p.parse_args(argv)
    paths = run(Path(a.out_dir), Path(a.raw_dir), edition=a.edition, url=a.url,
                zip_path=Path(a.zip) if a.zip else None, min_n=a.min_n, force_download=a.force)
    for k, v in paths.items():
        print(f"wrote {k}: {v}", file=sys.stderr)
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
