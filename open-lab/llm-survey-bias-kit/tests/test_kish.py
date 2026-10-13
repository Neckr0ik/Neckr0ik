import pytest

from llm_survey_bias_kit import kish_by_group, kish_effective_n


def test_equal_weights():
    r = kish_effective_n([2.0] * 50)
    assert r.effective_n == pytest.approx(50)
    assert r.design_effect == pytest.approx(1.0)
    assert r.cv_weights == pytest.approx(0.0)


def test_known_unequal_weights():
    r = kish_effective_n([1, 1, 1, 3])
    assert r.effective_n == pytest.approx(3.0)  # 36 / 12
    assert r.design_effect == pytest.approx(4 / 3)
    assert r.efficiency == pytest.approx(0.75)
    assert 1 + r.cv_weights**2 == pytest.approx(r.design_effect)


def test_single_dominant_weight():
    r = kish_effective_n([1000] + [1e-9] * 99)
    assert r.effective_n == pytest.approx(1.0, abs=1e-6)


def test_scale_invariance():
    assert kish_effective_n([1, 2, 3]).effective_n == pytest.approx(kish_effective_n([10, 20, 30]).effective_n)


@pytest.mark.parametrize("bad", [[], [1, -1], [0, 0], [1, float("nan")], [1, float("inf")], [float("-inf"), 1]])
def test_invalid(bad):
    with pytest.raises(ValueError):
        kish_effective_n(bad)


def test_by_group():
    recs = [{"state": "X", "weight": w} for w in (1, 1, 1, 3)] + [{"state": "Y", "weight": "2"}] * 5
    g = kish_by_group(recs, "state")
    assert g["X"].effective_n == pytest.approx(3.0)
    assert g["Y"].effective_n == pytest.approx(5.0)
