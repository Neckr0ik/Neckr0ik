import numpy as np
import pytest

from mx_census_sampler import AGE_BANDS, SCHOOLING, SEXES, sample
from mx_census_sampler.profiles import age_sex_probs, frame_targets, schooling_probs


def test_probabilities_are_distributions(frame):
    assert np.allclose(age_sex_probs(frame).sum(axis=1), 1.0)
    for s in SEXES:
        p = schooling_probs(frame, s)
        assert p.shape == (len(frame), len(SCHOOLING))
        assert np.allclose(p.sum(axis=1), 1.0) and (p >= 0).all()


def test_post_basic_share_matches_census(frame):
    p = schooling_probs(frame, "F")
    expected = frame["p18ym_pb_f"] / frame["p_18ymas_f"]
    assert np.allclose(p[:, -1], expected)


def test_profiles_converge_to_census_targets(frame):
    r = sample(frame, n=20_000, seed=2027, per_unit=5)
    resp = r.respondents
    targets = frame_targets(frame)
    for col, order in (("sex", SEXES), ("age_band", AGE_BANDS), ("schooling", SCHOOLING)):
        got = resp.groupby(col)["weight"].sum().reindex(list(order), fill_value=0)
        got = got / got.sum()
        for k in order:
            assert got[k] == pytest.approx(targets[col][k], abs=0.01), (col, k)


def test_profile_values_are_valid(frame):
    resp = sample(frame, n=200, seed=1).respondents
    assert set(resp["sex"]) <= set(SEXES)
    assert set(resp["age_band"]) <= set(AGE_BANDS)
    assert set(resp["schooling"]) <= set(SCHOOLING)


@pytest.mark.parametrize("bad", ["-5", "inf", "nan", "*", ""])
def test_load_frame_rejects_invalid_counts(tmp_path, bad):
    from mx_census_sampler import load_frame

    from .conftest import FIXTURE

    lines = FIXTURE.read_text(encoding="utf-8").splitlines()
    header = lines[0].split(",")
    row = lines[1].split(",")
    row[header.index("p_18ymas_f")] = bad
    p = tmp_path / "bad.csv"
    p.write_text("\n".join([lines[0], ",".join(row), *lines[2:]]) + "\n", encoding="utf-8")
    with pytest.raises(ValueError, match="p_18ymas_f"):
        load_frame(p)
