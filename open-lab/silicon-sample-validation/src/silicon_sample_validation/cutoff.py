"""Training-cutoff guard: only score targets the model cannot have seen.

A target is eligible only if its official figure was *published after* the
model's declared training cutoff (plus an optional safety margin). Optionally,
the reference period of the data can be required to end after the cutoff too
(stricter: no earlier releases about the same period, such as preliminary
figures, could have leaked). Targets with missing or unparseable dates are
excluded - the guard fails closed.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import date, datetime, timedelta
from typing import Iterable, Mapping


def to_date(value) -> date:
    if isinstance(value, datetime):
        return value.date()
    if isinstance(value, date):
        return value
    s = str(value).strip()
    if not s:
        raise ValueError("empty date")
    return date.fromisoformat(s[:10])


@dataclass
class CutoffResult:
    training_cutoff: date
    margin_days: int
    eligible: list[Mapping] = field(default_factory=list)
    excluded: list[tuple[Mapping, str]] = field(default_factory=list)

    @property
    def eligible_ids(self) -> list:
        return [t.get("target_id") for t in self.eligible]


def filter_post_cutoff(
    targets: Iterable[Mapping],
    training_cutoff,
    published_key: str = "published_at",
    period_end_key: str | None = None,
    margin_days: int = 0,
) -> CutoffResult:
    """Split targets into eligible (published after cutoff + margin) and excluded."""
    cutoff = to_date(training_cutoff)
    if margin_days < 0:
        raise ValueError("margin_days must be >= 0")
    threshold = cutoff + timedelta(days=margin_days)
    res = CutoffResult(training_cutoff=cutoff, margin_days=margin_days)
    for t in targets:
        try:
            pub = to_date(t.get(published_key, ""))
        except (ValueError, TypeError):
            res.excluded.append((t, f"missing or invalid {published_key}"))
            continue
        if pub <= threshold:
            res.excluded.append((t, f"published {pub} is not after {threshold} (cutoff {cutoff} + {margin_days}d)"))
            continue
        if period_end_key is not None:
            try:
                end = to_date(t.get(period_end_key, ""))
            except (ValueError, TypeError):
                res.excluded.append((t, f"missing or invalid {period_end_key}"))
                continue
            if end <= cutoff:
                res.excluded.append((t, f"reference period ends {end}, not after cutoff {cutoff}"))
                continue
        res.eligible.append(t)
    return res
