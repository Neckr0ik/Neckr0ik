import numpy as np
import pytest

from silicon_sample_validation import (
    build_baselines,
    compare_to_baselines,
    compare_two,
    demographic_regression,
    demographic_regression_loo,
    last_published,
    national_mean,
)


def test_last_published_and_national_mean():
    prev = [1.0, 2.0, 3.0, 6.0]
    assert list(last_published(prev)) == prev
    assert list(national_mean(prev)) == [3.0] * 4
    assert list(national_mean(prev, weights=[1, 1, 1, 0])) == [2.0] * 4
    assert list(national_mean(prev, national_value=9.5)) == [9.5] * 4
    with pytest.raises(ValueError):
        national_mean(prev, weights=[0, 0, 0, 0])
    with pytest.raises(ValueError):
        last_published([1.0, float("nan")])


def test_demographic_regression_recovers_linear_rule():
    X = np.array([[0.1, 1.0], [0.4, 0.0], [0.7, 2.0], [0.9, 1.0], [0.2, 3.0]])
    prev = 5 + 10 * X[:, 0] - 2 * X[:, 1]
    Xnow = X + 0.1
    pred = demographic_regression(X, prev, Xnow)
    assert pred == pytest.approx(5 + 10 * Xnow[:, 0] - 2 * Xnow[:, 1])
    with pytest.raises(ValueError):
        demographic_regression(X[:2], prev[:2])  # 3 params, 2 units
    # ridge makes an underdetermined fit possible
    assert demographic_regression(X[:2], prev[:2], ridge=1.0).shape == (2,)


def test_loo_is_exact_on_noiseless_linear_data():
    x = np.arange(6, dtype=float)
    y = 2 + 3 * x
    assert demographic_regression_loo(x, y) == pytest.approx(y)


def test_build_baselines_keys():
    prev = [1.0, 2.0, 3.0, 4.0, 5.0]
    X = [[0.1], [0.2], [0.3], [0.5], [0.4]]
    b = build_baselines(prev, X)
    assert set(b) == {"last_published", "national_mean", "demographic_regression"}
    b2 = build_baselines(prev, X, official_for_loo=[1.0, 2.0, 3.0, 4.0, 5.5])
    assert any("not pre-release" in k for k in b2)


def test_compare_two_known_difference():
    y = np.zeros(50)
    a = np.full(50, 1.0)  # |e| = 1
    b = np.full(50, 3.0)  # |e| = 3
    c = compare_two(y, a, b, "a", "b", n_boot=500)
    assert c.mae_a == 1.0 and c.mae_b == 3.0 and c.diff == -2.0
    assert c.ci == (-2.0, -2.0)
    assert c.skill == pytest.approx(1 - 1 / 3)
    assert c.a_better


def test_compare_two_tie_is_not_better():
    y = np.zeros(30)
    a = np.ones(30)
    c = compare_two(y, a, -a, n_boot=200)
    assert c.diff == 0 and not c.a_better


def test_method_must_beat_every_baseline():
    rng = np.random.default_rng(0)
    y = rng.normal(50, 10, 80)
    good = y + rng.normal(0, 1, 80)
    baselines = {"noisy": y + rng.normal(0, 5, 80), "flat": np.full(80, y.mean())}
    r = compare_to_baselines(y, good, baselines, n_boot=1000)
    assert r.beats_all_baselines and r.verdict == "beats all baselines"
    baselines["oracle"] = y.copy()
    r2 = compare_to_baselines(y, good, baselines, n_boot=1000)
    assert not r2.beats_all_baselines and "oracle" in r2.verdict and "negative result" in r2.verdict
    assert "oracle" in r2.table()
    with pytest.raises(ValueError):
        compare_to_baselines(y, good, {})


def test_coverage_note_and_small_n_note():
    y = np.arange(10, dtype=float)
    est = y + 0.5
    r = compare_to_baselines(y, est, {"z": np.zeros(10)}, lower=est - 0.1, upper=est + 0.1, n_boot=100)
    assert r.method_scores["coverage"] == 0.0
    assert any("overconfident" in n for n in r.notes)
    assert any("only 10 units" in n for n in r.notes)
    d = r.to_dict()
    assert d["vs_baselines"]["z"]["a_better"] is True
