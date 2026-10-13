"""A clearly SYNTHETIC demo dataset.

Everything produced here is invented by a random-number generator. Unit names
are "SYNTHETIC-UNIT-01" and so on; no value corresponds to any real state,
city, survey or model run. It exists only to exercise the code. Never quote
numbers computed on it as results.
"""

from __future__ import annotations

import numpy as np

SYNTHETIC_LABEL = "SYNTHETIC DEMO DATA - not real, not results"

REGIONS = ("synthetic-north", "synthetic-center", "synthetic-south")


def make_synthetic_dataset(n_units: int = 32, seed: int = 2027) -> list[dict]:
    """Return ``n_units`` synthetic records with every column the harness uses.

    Columns: ``unit_id``, ``synthetic`` (always True), ``region``,
    ``urbanization`` (0-1), ``indigenous_language`` ("yes"/"no"),
    ``share_university``, ``share_over_65``, ``previous`` (last published
    value), ``official`` (the new figure), ``simulated_anchored`` with
    ``lower``/``upper``, ``simulated_demographic_only``, ``dispersion`` (SD of
    simulated answers within the unit), ``published_at``.

    The generating process deliberately builds in a failure mode - larger
    errors where ``indigenous_language == "yes"`` - so the failure analysis has
    something to find. That is a property of this fake data, not a finding.
    """
    rng = np.random.default_rng(seed)
    rows: list[dict] = []
    for i in range(n_units):
        urb = float(rng.uniform(0.3, 0.98))
        univ = float(np.clip(0.05 + 0.25 * urb + rng.normal(0, 0.04), 0.02, 0.5))
        old = float(np.clip(rng.normal(0.11, 0.025), 0.05, 0.2))
        indig = bool(rng.random() < 0.3)
        region = REGIONS[i % 3]
        latent = 55 - 30 * urb - 25 * univ + 40 * old + (6 if indig else 0)
        official = latent + rng.normal(0, 2.5)
        previous = official - rng.normal(1.0, 2.0)  # a drift since the last wave
        err_sd = 4.5 if indig else 1.8
        anchored = official + rng.normal(0.4, err_sd)
        half_width = 1.96 * 2.2
        demo_only = latent + rng.normal(-1.0, 3.5) - (5 if indig else 0)
        rows.append(
            {
                "unit_id": f"SYNTHETIC-UNIT-{i + 1:02d}",
                "synthetic": True,
                "region": region,
                "urbanization": round(urb, 3),
                "indigenous_language": "yes" if indig else "no",
                "share_university": round(univ, 3),
                "share_over_65": round(old, 3),
                "previous": round(previous, 2),
                "official": round(official, 2),
                "simulated_anchored": round(anchored, 2),
                "lower": round(anchored - half_width, 2),
                "upper": round(anchored + half_width, 2),
                "simulated_demographic_only": round(demo_only, 2),
                "dispersion": round(float(rng.uniform(0.5, 3.0)), 3),
                "published_at": "2027-02-15" if i >= 4 else "2026-03-01",
            }
        )
    return rows
