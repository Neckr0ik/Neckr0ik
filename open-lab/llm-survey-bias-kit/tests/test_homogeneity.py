import pytest

from llm_survey_bias_kit import categorical_dispersion, numeric_dispersion, subgroup_sizes

CATS = ["a", "b", "c", "d"]


def test_uniform_vs_uniform():
    sim = CATS * 25
    r = categorical_dispersion(sim, {c: 0.25 for c in CATS}, CATS, n_boot=200)
    assert r.entropy_simulated == pytest.approx(1.0)
    assert r.entropy_ratio == pytest.approx(1.0)
    assert r.tvd == pytest.approx(0.0)
    assert not r.too_homogeneous


def test_collapsed_simulation_is_flagged():
    sim = ["a"] * 100
    ref = ["a"] * 40 + ["b"] * 30 + ["c"] * 20 + ["d"] * 10
    r = categorical_dispersion(sim, ref, CATS, n_boot=200)
    assert r.entropy_simulated == 0.0
    assert r.entropy_ratio == 0.0
    assert r.modal_share_simulated == 1.0
    assert r.categories_used_simulated == 1
    assert r.tvd == pytest.approx(0.6)
    assert r.too_homogeneous


def test_gini_simpson_known():
    r = categorical_dispersion(["a", "b"] * 10, {"a": 0.9, "b": 0.1}, ["a", "b"], n_boot=50)
    assert r.gini_simpson_simulated == pytest.approx(0.5)
    assert r.gini_simpson_reference == pytest.approx(1 - 0.81 - 0.01)
    assert r.entropy_simulated == pytest.approx(1.0)
    assert r.entropy_ratio > 1  # simulated is MORE dispersed here


def test_categories_inferred_and_errors():
    r = categorical_dispersion(["x", "y"], ["x", "y", "z"], n_boot=20)
    assert r.categories == ["x", "y", "z"]
    with pytest.raises(ValueError):
        categorical_dispersion(["x"], {"y": 1.0}, ["y"])
    with pytest.raises(ValueError):
        categorical_dispersion(["x"], {"x": 1.0, "q": 0.0}, ["x", "y"])


def test_reference_with_zero_entropy():
    r = categorical_dispersion(["a", "b"], {"a": 1.0}, ["a", "b"], n_boot=20)
    assert not r.too_homogeneous
    assert r.notes


def test_numeric_half_sd():
    ref = [0, 10] * 50
    sim = [2.5, 7.5] * 50
    r = numeric_dispersion(sim, ref, n_boot=200)
    assert r.sd_ratio == pytest.approx(0.5)
    assert r.variance_ratio == pytest.approx(0.25)
    assert r.too_homogeneous
    lo, hi = r.sd_ratio_ci
    assert lo <= 0.5 <= hi


def test_numeric_reference_sd():
    sim = [1, 3] * 10
    sd = numeric_dispersion(sim, reference_sd=1.0).sd_simulated
    r = numeric_dispersion(sim, reference_sd=sd)
    assert r.sd_ratio == pytest.approx(1.0)
    assert not r.too_homogeneous
    with pytest.raises(ValueError):
        numeric_dispersion(sim)
    with pytest.raises(ValueError):
        numeric_dispersion(sim, [1, 2], reference_sd=1)
    with pytest.raises(ValueError):
        numeric_dispersion([1], reference_sd=1)


def test_subgroup_min_units_default_12():
    recs = []
    for u in range(12):
        recs += [{"unit_id": f"n{u}", "region": "north"}] * 3  # replicates
    for u in range(11):
        recs.append({"unit_id": f"s{u}", "region": "south"})
    cells = {c.group["region"]: c for c in subgroup_sizes(recs, ["region"])}
    assert cells["north"].n_units == 12 and cells["north"].n_rows == 36
    assert cells["north"].reportable
    assert cells["south"].n_units == 11 and not cells["south"].reportable


def test_subgroup_two_keys_and_custom_min():
    recs = [{"unit_id": i, "sex": "f" if i % 2 else "m", "age": "18-29"} for i in range(10)]
    cells = subgroup_sizes(recs, ["sex", "age"], min_units=5)
    assert len(cells) == 2 and all(c.reportable for c in cells)
    with pytest.raises(ValueError):
        subgroup_sizes(recs, [])
