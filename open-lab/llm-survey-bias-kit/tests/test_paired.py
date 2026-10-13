import math

import numpy as np
import pytest

from llm_survey_bias_kit import (
    DISTINGUISHABLE,
    INDISTINGUISHABLE,
    NOT_EVALUABLE,
    aa_split_replicates,
    aa_test,
    minimum_detectable_effect,
    paired_ab,
    paired_ab_from_records,
    required_units,
)


def known_case():
    # unit-level differences 1..5, two identical replicates each
    a = np.array([[i, i] for i in range(1, 6)], dtype=float)
    b = np.zeros((5, 2))
    return a, b


def test_paired_known_answer():
    a, b = known_case()
    r = paired_ab(a, b, n_boot=2000)
    assert r.n_units == 5 and r.n_replicates == 2
    assert r.diff == pytest.approx(3.0)
    assert r.sd_diff == pytest.approx(math.sqrt(2.5))
    assert r.se_diff == pytest.approx(math.sqrt(0.5))
    half = 2.776445105 * math.sqrt(0.5)
    assert r.ci_t[0] == pytest.approx(3 - half, abs=1e-6)
    assert r.ci_t[1] == pytest.approx(3 + half, abs=1e-6)
    assert 1.0 <= r.ci_boot[0] < 3 < r.ci_boot[1] <= 5.0
    assert r.replicate_sd == pytest.approx(0.0)
    assert r.verdict == DISTINGUISHABLE


def test_single_replicate_is_not_evaluable():
    a, b = known_case()
    r = paired_ab(a[:, 0], b[:, 0])
    assert r.n_replicates == 1
    assert r.verdict == NOT_EVALUABLE
    assert any("replicates" in x for x in r.reasons)
    # the numbers are still computed
    assert r.diff == pytest.approx(3.0)


def test_identical_messages_indistinguishable():
    rng = np.random.default_rng(0)
    a = rng.normal(5, 1, size=(40, 3))
    r = paired_ab(a, a.copy())
    assert r.diff == 0.0
    assert r.verdict == INDISTINGUISHABLE


def test_noise_floor_blocks_small_effect():
    a, b = known_case()
    r = paired_ab(a, b, noise_floor=3.5)
    assert r.verdict == INDISTINGUISHABLE
    assert any("noise floor" in x for x in r.reasons)


def test_shape_mismatch_and_nan_handling():
    with pytest.raises(ValueError):
        paired_ab(np.zeros((3, 2)), np.zeros((4, 2)))
    a = np.array([[1, 2], [np.nan, np.nan], [3, 5], [2, 2]], dtype=float)
    b = np.array([[0, 0], [1, 1], [1, 1], [0, np.nan]], dtype=float)
    r = paired_ab(a, b)
    assert r.n_units == 3
    assert r.n_replicates == 1  # unit 4 has only one valid B replicate
    assert r.verdict == NOT_EVALUABLE
    assert any("dropped 1" in x for x in r.reasons)


def test_too_few_units():
    r = paired_ab([[1.0, 2.0]], [[0.0, 0.0]])
    assert r.verdict == NOT_EVALUABLE
    assert math.isinf(r.mde)


def test_mde_known_value():
    expected = (2.262157163 + 0.883403860) / math.sqrt(10)
    assert minimum_detectable_effect(10, 1.0) == pytest.approx(expected, abs=1e-6)
    assert minimum_detectable_effect(1, 1.0) == math.inf
    assert minimum_detectable_effect(50, 0.0) == 0.0
    with pytest.raises(ValueError):
        minimum_detectable_effect(10, -1)


def test_mde_shrinks_with_n():
    assert minimum_detectable_effect(400, 1) < minimum_detectable_effect(100, 1) < minimum_detectable_effect(25, 1)
    # roughly halves when n quadruples
    assert minimum_detectable_effect(400, 1) / minimum_detectable_effect(100, 1) == pytest.approx(0.5, abs=0.01)


def test_required_units_inverts_mde():
    n = required_units(0.25, 1.0)
    assert minimum_detectable_effect(n, 1.0) <= 0.25 < minimum_detectable_effect(n - 1, 1.0)
    assert 120 <= n <= 135  # normal approximation gives ~126
    with pytest.raises(ValueError):
        required_units(0, 1)


def test_aa_noise_floor():
    rng = np.random.default_rng(1)
    run1 = rng.normal(0, 1, size=(60, 3))
    run2 = rng.normal(0, 1, size=(60, 3))
    res = aa_test(run1, run2)
    c = res.comparison
    assert res.noise_floor == pytest.approx(max(abs(c.ci_t[0]), abs(c.ci_t[1])))
    assert res.noise_floor > abs(c.diff)


def test_aa_split_replicates():
    rng = np.random.default_rng(2)
    m = rng.normal(3, 1, size=(30, 4))
    res = aa_split_replicates(m, seed=5)
    assert res.comparison.n_replicates == 2
    assert res.comparison.verdict in (INDISTINGUISHABLE, DISTINGUISHABLE)
    with pytest.raises(ValueError):
        aa_split_replicates(m[:, :1])


def test_from_records_long_format():
    recs = []
    for u in range(6):
        for rep in range(2):
            recs.append({"unit_id": u, "message": "A", "score": str(u + 1)})
            recs.append({"unit_id": u, "message": "B", "score": "0"})
    recs.append({"unit_id": 99, "message": "A", "score": "5"})  # no B
    recs.append({"unit_id": 0, "message": "C", "score": "7"})  # ignored message
    recs.append({"unit_id": 0, "message": "A", "score": ""})  # blank ignored
    r = paired_ab_from_records(recs, "A", "B")
    assert r.n_units == 6
    assert r.diff == pytest.approx(3.5)
    assert r.verdict == DISTINGUISHABLE
    assert any("dropped 1 unit" in x for x in r.reasons)


def test_reproducible_bootstrap():
    a, b = known_case()
    assert paired_ab(a, b, seed=9).ci_boot == paired_ab(a, b, seed=9).ci_boot


def test_split_with_three_replicates_is_not_evaluable():
    m = np.random.default_rng(3).normal(size=(20, 3))
    res = aa_split_replicates(m)
    assert res.comparison.verdict == NOT_EVALUABLE
    assert any(">= 4 replicates" in x for x in res.comparison.reasons)
