import math

import numpy as np
import pytest

from silicon_sample_validation import bias, coverage, interval_score, mae, pearson, rmse, score, spearman

Y = [10.0, 20.0, 30.0, 40.0]
X = [12.0, 18.0, 33.0, 40.0]  # errors +2, -2, +3, 0


def test_point_metrics_known_values():
    assert mae(Y, X) == pytest.approx(7 / 4)
    assert rmse(Y, X) == pytest.approx(math.sqrt(17 / 4))
    assert bias(Y, X) == pytest.approx(3 / 4)


def test_perfect_and_constant():
    assert mae(Y, Y) == 0 and pearson(Y, Y) == pytest.approx(1.0)
    assert math.isnan(pearson(Y, [5.0] * 4))


def test_spearman_monotone_and_ties():
    assert spearman([1, 2, 3, 4], [10, 100, 1000, 10000]) == pytest.approx(1.0)
    assert spearman([1, 2, 3, 4], [4, 3, 2, 1]) == pytest.approx(-1.0)
    # with ties: ranks (1.5,1.5,3,4) vs (1,2,3,4)
    expected = np.corrcoef([1.5, 1.5, 3, 4], [1, 2, 3, 4])[0, 1]
    assert spearman([1, 1, 2, 3], [1, 2, 3, 4]) == pytest.approx(expected)


def test_coverage_and_interval_score():
    lo = [9, 21, 28, 35]
    hi = [11, 25, 32, 45]
    assert coverage(Y, lo, hi) == pytest.approx(0.75)  # 20 is below 21
    # widths 2+4+4+10=20 -> 5 mean; miss penalty (2/0.05)*(21-20)=40 -> /4 = 10
    assert interval_score(Y, lo, hi, alpha=0.05) == pytest.approx(5 + 10)
    with pytest.raises(ValueError):
        coverage(Y, hi, lo)


def test_score_bundle_and_validation():
    s = score(Y, X, [y - 5 for y in X], [y + 5 for y in X])
    assert s["n"] == 4 and s["coverage"] == 1.0 and s["mean_width"] == pytest.approx(10)
    assert "coverage" not in score(Y, X)
    with pytest.raises(ValueError):
        mae(Y, X[:3])
    with pytest.raises(ValueError):
        mae([1.0, float("nan")], [1.0, 2.0])
    with pytest.raises(ValueError):
        mae([], [])
