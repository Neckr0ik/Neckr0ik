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


def test_stratified_allocation_with_empty_strata_is_refused(frame):
    # The fixture has 3 states: n=2 leaves one of them without draws under any allocation.
    for allocation in ("proportional", "sqrt", "equal"):
        with pytest.raises(ValueError, match="no draws") as ei:
            sample(frame, n=2, seed=1, stratify="state", allocation=allocation)
    assert "Use n >= 3" in str(ei.value)  # the smallest n that covers every stratum (equal allocation)
    assert len(sample(frame, n=3, seed=1, stratify="state", allocation="equal").draws) == 3
    assert len(sample(frame, n=2, seed=1).draws) == 2  # unstratified: one stratum, always covered


class _EdgeRng:
    """Returns the largest values a uniform draw could round to, to hit the cumulative total exactly."""

    def random(self, size=None):
        return 1.0 if size is None else np.ones(size)


def test_selection_never_indexes_past_the_last_unit():
    from mx_census_sampler.sampler import _systematic, _with_replacement

    cum = np.cumsum([0.1, 0.2, 0.3])
    assert _systematic(cum, 3, _EdgeRng()).max() == 2
    assert _with_replacement(cum, 4, _EdgeRng()).tolist() == [2, 2, 2, 2]
