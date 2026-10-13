import math

import pytest

from llm_survey_bias_kit import _stats


@pytest.fixture(params=["default", "no_scipy"])
def stats(request, monkeypatch):
    if request.param == "no_scipy":
        monkeypatch.setattr(_stats, "_sps", None)
    return _stats


def test_betainc_known_values():
    assert _stats.betainc(1, 1, 0.3) == pytest.approx(0.3)
    # I_0.4(2,3) = sum_{j=2..4} C(4,j) .4^j .6^(4-j) = 0.5248
    assert _stats.betainc(2, 3, 0.4) == pytest.approx(0.5248, abs=1e-12)
    assert _stats.betainc(2, 3, 0.0) == 0.0
    assert _stats.betainc(2, 3, 1.0) == 1.0


@pytest.mark.parametrize(
    "q,df,expected",
    [
        (0.975, 1, 12.706204736),
        (0.975, 4, 2.776445105),
        (0.975, 10, 2.228138852),
        (0.975, 30, 2.042272456),
        (0.80, 9, 0.883403860),
        (0.025, 10, -2.228138852),
        (0.5, 7, 0.0),
    ],
)
def test_t_ppf_known_values(stats, q, df, expected):
    assert stats.t_ppf(q, df) == pytest.approx(expected, abs=1e-6)


def test_t_cdf_symmetry(stats):
    assert stats.t_cdf(0.0, 5) == pytest.approx(0.5)
    assert stats.t_cdf(1.3, 6) + stats.t_cdf(-1.3, 6) == pytest.approx(1.0)


def test_t_ppf_large_df_approaches_normal(stats):
    assert stats.t_ppf(0.975, math.inf) == pytest.approx(1.959964, abs=1e-6)
    assert stats.t_ppf(0.975, 1e6) == pytest.approx(1.959966, abs=1e-5)


def test_t_ppf_rejects_bad_input():
    with pytest.raises(ValueError):
        _stats.t_ppf(1.0, 3)
    with pytest.raises(ValueError):
        _stats.t_ppf(0.5, 0)


def test_entropy():
    assert _stats.shannon_entropy([0.5, 0.5]) == pytest.approx(1.0)
    assert _stats.shannon_entropy([1, 0, 0]) == 0.0
    assert _stats.shannon_entropy([1, 1, 1, 1], base=4) == pytest.approx(1.0)
