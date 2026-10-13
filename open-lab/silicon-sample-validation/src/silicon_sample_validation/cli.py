"""``ssv`` command line: verify / inspect a forecast registry, run the synthetic demo."""

from __future__ import annotations

import argparse
import json
import sys
from typing import Sequence

from . import __version__
from .registry import ForecastRegistry


def main(argv: Sequence[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="ssv", description=__doc__)
    p.add_argument("--version", action="version", version=__version__)
    sub = p.add_subparsers(dest="command", required=True)
    v = sub.add_parser("verify", help="verify a registry's hash chain")
    v.add_argument("registry")
    v.add_argument("--json", action="store_true")
    h = sub.add_parser("head", help="print the head hash to publish")
    h.add_argument("registry")
    d = sub.add_parser("demo", help="run the end-to-end demo on SYNTHETIC data")
    d.add_argument("--workdir", default=None)
    a = p.parse_args(argv)

    if a.command == "verify":
        rep = ForecastRegistry(a.registry).verify()
        if a.json:
            print(json.dumps(rep.__dict__, indent=2))
        else:
            print(f"{'OK' if rep.ok else 'FAILED'}: {rep.n_entries} entries, head {rep.head_hash}")
            for e in rep.errors:
                print(f"  {e}")
        return 0 if rep.ok else 1
    if a.command == "head":
        print(ForecastRegistry(a.registry).head())
        return 0
    from .demo import run_demo

    run_demo(a.workdir)
    return 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
