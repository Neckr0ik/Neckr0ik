import numpy as np
import pandas as pd
import pytest

from mx_census_sampler import filter_frame, kish_deff, kish_ess, sample
from mx_census_sampler.sampler import allocate, largest_remainder


def test_largest_remainder_sums_and_is_deterministic():
    a = largest_remainder(np.array([1, 1, 1]), 10)
    assert a.sum() == 10 and list(a) == [4, 3, 3]
    assert list(largest_remainder(np.array([5, 3, 2]), 7)) == [4, 2, 1]


def test_allocations():
    mos = pd.Series([900.0, 90.0, 10.0], index=["a", "b", "c"])
    assert list(allocate(mos, 10, "proportional")) == [9, 1, 0]
    assert list(allocate(mos, 9, "equal")) == [3, 3, 3]
    assert allocate(mos, 10, "sqrt").sum() == 10
    with pytest.raises(ValueError):
        allocate(mos, 10, "bogus")


@pytest.mark.parametrize("method", ["systematic", "wr"])
def test_reproducible_and_seed_sensitive(frame, method):
    a = sample(frame, n=50, seed=7, method=method)
    b = sample(frame, n=50, seed=7, method=method)
    c = sample(frame, n=50, seed=8, method=method)
    pd.testing.assert_frame_equal(a.respondents, b.respondents)
    assert a.fingerprint() == b.fingerprint() != c.fingerprint()


@pytest.mark.parametrize("method", ["systematic", "wr"])
def test_weights_sum_to_adult_population(frame, method):
    r = sample(frame, n=37, seed=1, method=method, per_unit=3)
    assert len(r.respondents) == 37 * 3
    assert r.respondents["weight"].sum() == pytest.approx(frame["p_18ymas"].sum())


def test_systematic_hits_are_floor_or_ceil_of_expected(frame):
    n = 60
    r = sample(frame, n=n, seed=3, method="systematic")
    hits = r.draws["cvegeo"].value_counts()
    expected = n * frame.set_index("cvegeo")["p_18ymas"] / frame["p_18ymas"].sum()
    for code, e in expected.items():
        h = int(hits.get(code, 0))
        assert np.floor(e) <= h <= np.ceil(e), (code, e, h)


def test_wr_selection_frequencies_match_pps(frame):
    r = sample(frame, n=200_000, seed=11, method="wr")
    freq = r.draws["cvegeo"].value_counts(normalize=True)
    p = frame.set_index("cvegeo")["p_18ymas"] / frame["p_18ymas"].sum()
    for code, pi in p.items():
        assert freq.get(code, 0.0) == pytest.approx(pi, abs=0.004)


def test_stratified_equal_allocation_is_unequally_weighted(frame):
    r = sample(frame, n=30, seed=5, stratify="state", allocation="equal")
    assert set(r.draws["stratum"]) == {"01", "09", "20"}
    assert (r.draws.groupby("stratum").size() == 10).all()
    assert r.respondents["weight"].sum() == pytest.approx(frame["p_18ymas"].sum())
    assert r.deff > 1.0 and r.ess < 30
    prop = sample(frame, n=30, seed=5, stratify="state")
    assert prop.deff == pytest.approx(1.0, abs=0.05)


def test_kish_formulas():
    assert kish_ess([1, 1, 1, 1]) == pytest.approx(4)
    # (1+1+2+4)^2 / (1+1+4+16) = 64/22
    assert kish_ess([1, 1, 2, 4]) == pytest.approx(64 / 22)
    assert kish_deff([1, 1, 2, 4]) == pytest.approx(4 / (64 / 22))
    w = np.array([1.0, 3.0, 5.0])
    assert kish_deff(w) == pytest.approx(1 + w.var() / w.mean() ** 2)


def test_filters(frame):
    assert set(filter_frame(frame, states=["9"])["cve_ent"]) == {"09"}
    assert set(filter_frame(frame, size_bands=["metro"])["cvegeo"]) == {"01001", "09007", "09010", "09015"}
    assert len(filter_frame(frame, municipalities=["20067", "1002"])) == 2
    with pytest.raises(ValueError):
        filter_frame(frame, size_bands=["huge"])
    with pytest.raises(ValueError):
        filter_frame(frame, states=["99"])
    r = sample(filter_frame(frame, states=["20"]), n=10, seed=1)
    assert set(r.respondents["cve_ent"]) == {"20"}


def test_bad_design(frame):
    with pytest.raises(ValueError):
        sample(frame, n=0)
    with pytest.raises(ValueError):
        sample(frame, n=5, method="srs")
