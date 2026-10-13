"""Respondent profiles from municipal census marginals.

For each selected respondent we draw, from the municipality's own ITER counts:

1. **sex × age band** jointly, from the 12 cells ``{f,m}_{18_24 … 65_plus}``
   (an exact census joint distribution);
2. **schooling given sex**:

   * ``P(post_basic | sex) = P18YM_PB_<sex> / P_18YMAS_<sex>``;
   * the remaining mass is split into ``none`` / ``primary`` / ``secondary``
     in the municipality's **15+** proportions of ``P15YM_SE`` :
     ``P15PRI_*`` : ``P15SEC_*`` (ITER does not publish these levels for 18+).

Schooling is therefore assumed independent of age within sex and
municipality — a real limitation (younger adults are more schooled); see the
README. Age-unspecified and schooling-unspecified people are excluded from the
denominators.
"""

from __future__ import annotations

import numpy as np
import pandas as pd

from .data import AGE_BANDS, AGE_SEX_COLUMNS, SCHOOLING, SEXES

CELLS = [(s, a) for s in SEXES for a in AGE_BANDS]


def age_sex_probs(frame: pd.DataFrame) -> np.ndarray:
    counts = frame[[AGE_SEX_COLUMNS[c] for c in CELLS]].to_numpy(dtype=float)
    tot = counts.sum(axis=1, keepdims=True)
    if (tot <= 0).any():
        raise ValueError("Municipality with no adults in any age band.")
    return counts / tot


def schooling_probs(frame: pd.DataFrame, sex: str) -> np.ndarray:
    """Rows: municipalities; columns: :data:`SCHOOLING`."""
    s = sex.lower()
    adults = frame[f"p_18ymas_{s}"].to_numpy(dtype=float)
    pb = np.divide(
        frame[f"p18ym_pb_{s}"].to_numpy(dtype=float),
        adults,
        out=np.zeros_like(adults),
        where=adults > 0,
    )
    pb = np.clip(pb, 0.0, 1.0)
    basic = frame[["p15ym_se", "p15_pri", "p15_sec"]].to_numpy(dtype=float)
    btot = basic.sum(axis=1, keepdims=True)
    split = np.divide(basic, btot, out=np.full_like(basic, 1 / 3), where=btot > 0)
    return np.column_stack([split * (1.0 - pb)[:, None], pb])


def _pick(probs: np.ndarray, u: np.ndarray) -> np.ndarray:
    cum = np.cumsum(probs, axis=1)
    cum[:, -1] = 1.0  # guard against round-off
    return (u[:, None] >= cum).sum(axis=1)


def assign_profiles(draws: pd.DataFrame, per_unit: int, rng: np.random.Generator) -> pd.DataFrame:
    """Expand draws into ``per_unit`` respondents each and assign profiles."""
    people = draws.loc[draws.index.repeat(per_unit)].reset_index(drop=True)
    people.insert(1, "person_in_draw", np.tile(np.arange(1, per_unit + 1), len(draws)))
    people.insert(0, "respondent_id", np.arange(1, len(people) + 1))

    u = rng.random((len(people), 2))  # col 0: sex×age, col 1: schooling
    cell = _pick(age_sex_probs(people), u[:, 0])
    sex = np.array([CELLS[i][0] for i in cell])
    age = np.array([CELLS[i][1] for i in cell])

    school = np.empty(len(people), dtype=object)
    for s in SEXES:
        mask = sex == s
        if mask.any():
            pr = schooling_probs(people.loc[mask], s)
            school[mask] = np.array(SCHOOLING)[_pick(pr, u[mask, 1])]
    people["sex"] = sex
    people["age_band"] = age
    people["schooling"] = school
    return people


def frame_targets(frame: pd.DataFrame) -> dict[str, pd.Series]:
    """Population distributions of the frame, for the summary report."""
    w = {c: frame[AGE_SEX_COLUMNS[c]].sum() for c in CELLS}
    tot = sum(w.values())
    sex = pd.Series({s: sum(v for (cs, _), v in w.items() if cs == s) / tot for s in SEXES})
    age = pd.Series({a: sum(v for (_, ca), v in w.items() if ca == a) / tot for a in AGE_BANDS})
    school = pd.Series(0.0, index=list(SCHOOLING))
    for s in SEXES:
        pr = schooling_probs(frame, s)
        school += (pr * frame[f"p_18ymas_{s.lower()}"].to_numpy(dtype=float)[:, None]).sum(axis=0)
    school /= school.sum()
    return {"sex": sex, "age_band": age, "schooling": school}
