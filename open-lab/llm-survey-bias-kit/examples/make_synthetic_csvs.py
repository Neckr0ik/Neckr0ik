"""Write small SYNTHETIC CSVs to try the CLI. All values are random draws.

    python examples/make_synthetic_csvs.py OUTDIR
    llm-bias-kit paired OUTDIR/paired.csv --a msg_A --b msg_B
"""

import csv
import sys
from pathlib import Path

import numpy as np


def write(path, header, rows):
    with open(path, "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(header)
        w.writerows(rows)


def main(outdir: str) -> None:
    out = Path(outdir)
    out.mkdir(parents=True, exist_ok=True)
    rng = np.random.default_rng(2027)
    n_units, n_reps = 120, 3
    regions = ["synthetic-north", "synthetic-center", "synthetic-south", "synthetic-islands"]
    unit_effect = rng.normal(0, 1.2, n_units)
    region = [regions[0] if i < 50 else regions[1] if i < 90 else regions[2] if i < 112 else regions[3]
              for i in range(n_units)]

    rows = []
    for u in range(n_units):
        for r in range(n_reps):
            for msg, shift in (("msg_A", 0.35), ("msg_B", 0.0), ("msg_A_rerun", 0.35)):
                score = float(np.clip(5 + unit_effect[u] + shift + rng.normal(0, 0.8), 0, 10))
                rows.append((f"SYN-{u:03d}", region[u], msg, r, round(score, 2)))
    write(out / "paired.csv", ["unit_id", "region", "message", "replicate", "score"], rows)

    opts = ["agree", "neutral", "disagree"]
    p_fwd, p_rev = [0.50, 0.30, 0.20], [0.38, 0.30, 0.32]  # built-in primacy effect
    # One answer per synthetic unit (ORD-000 ... ORD-599), so units and responses coincide.
    order_rows = [("forward", rng.choice(opts, p=p_fwd)) for _ in range(300)]
    order_rows += [("reversed", rng.choice(opts, p=p_rev)) for _ in range(300)]
    order_rows = [(f"ORD-{i:03d}", d, c) for i, (d, c) in enumerate(order_rows)]
    write(out / "order.csv", ["unit_id", "direction", "choice"], order_rows)

    sim = rng.choice(opts, p=[0.70, 0.25, 0.05], size=400)
    write(out / "sim_choices.csv", ["choice"], [(c,) for c in sim])
    write(out / "reference.csv", ["category", "share"], [("agree", 0.42), ("neutral", 0.28), ("disagree", 0.30)])

    w = rng.lognormal(0, 0.6, n_units)
    write(out / "weights.csv", ["unit_id", "region", "weight"],
          [(f"SYN-{u:03d}", region[u], round(float(w[u]), 4)) for u in range(n_units)])
    print(f"wrote SYNTHETIC example CSVs to {out}")


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else "synthetic_csv")
