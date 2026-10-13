import pytest

from silicon_sample_validation import error_breakdown, format_breakdown, worst_units

RECS = [
    {"unit_id": "u1", "official": 10, "estimate": 11, "region": "n", "urb": 0.1, "ind": "yes"},
    {"unit_id": "u2", "official": 10, "estimate": 13, "region": "n", "urb": 0.2, "ind": "yes"},
    {"unit_id": "u3", "official": 10, "estimate": 9, "region": "s", "urb": 0.5, "ind": "no"},
    {"unit_id": "u4", "official": 10, "estimate": 10, "region": "s", "urb": 0.6, "ind": "no"},
    {"unit_id": "u5", "official": 10, "estimate": 6, "region": "s", "urb": 0.9, "ind": "no"},
    {"unit_id": "u6", "official": 10, "estimate": 11, "region": "s", "urb": 0.95, "ind": "no"},
]


def by(groups, col):
    return {g.level: g for g in groups if g.column == col}


def test_categorical_breakdown_known_values():
    g = by(error_breakdown(RECS, ["region"], min_n=3), "region")
    assert g["n"].n == 2 and g["n"].mae == pytest.approx(2.0) and g["n"].bias == pytest.approx(2.0)
    assert g["s"].mae == pytest.approx(6 / 4) and g["s"].bias == pytest.approx(-4 / 4)
    assert g["n"].share_of_abs_error == pytest.approx(4 / 10)
    assert g["n"].small and not g["s"].small


def test_numeric_column_is_binned():
    g = by(error_breakdown(RECS, ["urb"], n_bins=2), "urb")
    assert len(g) == 2 and all(k.startswith("Q") for k in g)
    assert sum(x.n for x in g.values()) == 6


def test_force_categorical():
    g = by(error_breakdown(RECS, ["urb"], numeric={"urb": False}), "urb")
    assert len(g) == 6


def test_worst_units_and_format():
    assert worst_units(RECS, 2) == [("u5", -4.0), ("u2", 3.0)]
    txt = format_breakdown(error_breakdown(RECS, ["ind"]))
    assert "yes" in txt and "(small n)" in txt
    with pytest.raises(ValueError):
        error_breakdown([], ["x"])
