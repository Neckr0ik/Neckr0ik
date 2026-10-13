"""mx-census-sampler — PPS sampling of Mexican municipalities (INEGI Censo 2020).

Typical use::

    from mx_census_sampler import load_frame, sample
    frame = load_frame()
    result = sample(frame, n=400, seed=2027)
    result.respondents.head()
    print(result.summary_text())
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field

import pandas as pd

from .data import AGE_BANDS, SCHOOLING, SEXES, SIZE_BANDS, filter_frame, load_frame
from .profiles import assign_profiles
from .sampler import Design, draw_units, kish_deff, kish_ess, make_rng

__version__ = "0.1.0"

__all__ = [
    "AGE_BANDS",
    "SCHOOLING",
    "SEXES",
    "SIZE_BANDS",
    "Design",
    "SampleResult",
    "filter_frame",
    "kish_deff",
    "kish_ess",
    "load_frame",
    "sample",
]

OUTPUT_COLUMNS = [
    "respondent_id",
    "draw_id",
    "person_in_draw",
    "stratum",
    "cvegeo",
    "cve_ent",
    "nom_ent",
    "nom_mun",
    "size_band",
    "p_18ymas",
    "p_draw",
    "expected_hits",
    "sex",
    "age_band",
    "schooling",
    "weight",
]


@dataclass
class SampleResult:
    design: Design
    frame: pd.DataFrame
    draws: pd.DataFrame
    respondents: pd.DataFrame = field(repr=False)

    @property
    def ess(self) -> float:
        return kish_ess(self.respondents["weight"])

    @property
    def deff(self) -> float:
        return kish_deff(self.respondents["weight"])

    def to_csv(self, path_or_buf=None) -> str | None:
        return self.respondents[OUTPUT_COLUMNS].to_csv(
            path_or_buf, index=False, float_format="%.10g", lineterminator="\n"
        )

    def fingerprint(self) -> str:
        """SHA-256 of the canonical CSV; used by the golden regression test."""
        return hashlib.sha256(self.to_csv().encode("utf-8")).hexdigest()

    def summary(self) -> dict:
        from .report import summarize

        return summarize(self)

    def summary_text(self) -> str:
        from .report import format_summary

        return format_summary(self.summary())


def sample(
    frame: pd.DataFrame,
    n: int,
    seed: int = 2027,
    method: str = "systematic",
    per_unit: int = 1,
    stratify: str | None = None,
    allocation: str = "proportional",
) -> SampleResult:
    """Draw ``n`` PPS units (municipality hits) and ``per_unit`` profiled
    respondents per unit. Same inputs + same seed ⇒ identical output."""
    design = Design(
        n=n, method=method, stratify=stratify, allocation=allocation, per_unit=per_unit, seed=seed
    )
    rng = make_rng(seed)
    draws = draw_units(frame, design, rng)
    respondents = assign_profiles(draws, per_unit, rng)
    return SampleResult(design=design, frame=frame, draws=draws, respondents=respondents)
