from datetime import date

import pytest

from silicon_sample_validation import filter_post_cutoff

T = [
    {"target_id": "before", "published_at": "2026-05-01", "period_end": "2025-12-31"},
    {"target_id": "on", "published_at": "2026-06-30", "period_end": "2026-03-31"},
    {"target_id": "after", "published_at": "2026-07-01", "period_end": "2026-03-31"},
    {"target_id": "later", "published_at": "2026-09-15T08:00:00Z", "period_end": "2026-08-31"},
    {"target_id": "missing"},
    {"target_id": "garbage", "published_at": "soon"},
]


def test_strictly_after_cutoff():
    r = filter_post_cutoff(T, "2026-06-30")
    assert r.eligible_ids == ["after", "later"]
    reasons = {t["target_id"]: why for t, why in r.excluded}
    assert "not after" in reasons["on"]
    assert "invalid" in reasons["missing"] and "invalid" in reasons["garbage"]
    assert r.training_cutoff == date(2026, 6, 30)


def test_margin_days():
    r = filter_post_cutoff(T, date(2026, 6, 30), margin_days=30)
    assert r.eligible_ids == ["later"]
    with pytest.raises(ValueError):
        filter_post_cutoff(T, "2026-06-30", margin_days=-1)


def test_period_end_rule_is_stricter():
    r = filter_post_cutoff(T, "2026-06-30", period_end_key="period_end")
    assert r.eligible_ids == ["later"]
    assert any("reference period" in why for _, why in r.excluded)
