import numpy as np
import pandas as pd
import pytest

from endutih_media_profiles.estimate import Design, estimate_cells
from endutih_media_profiles.indicators import Indicator
from endutih_media_profiles.prepare import code_indicator


def naive_ratio_se(y, w, strata, psu, member):
    """Independent, loop-based ultimate-cluster linearisation (reference)."""
    ok = member & ~np.isnan(y)
    W = w[ok].sum()
    R = (w[ok] * y[ok]).sum() / W
    z = np.where(ok, w * (np.nan_to_num(y) - R) / W, 0.0)
    var = 0.0
    for h in np.unique(strata):
        psus = np.unique(psu[strata == h])
        tots = np.array([z[(strata == h) & (psu == i)].sum() for i in psus])
        if len(psus) > 1:
            var += len(psus) / (len(psus) - 1) * ((tots - tots.mean()) ** 2).sum()
    return R, np.sqrt(var)


def toy(seed=1, n=300):
    rng = np.random.default_rng(seed)
    df = pd.DataFrame({
        "EST_DIS": rng.choice(["a", "b", "c"], n),
        "UPM_DIS": rng.choice([f"p{i}" for i in range(12)], n),
        "w": rng.uniform(1, 10, n),
        "g": rng.choice(["x", "y"], n),
    })
    y = (rng.random(n) < 0.4).astype(float)
    y[rng.random(n) < 0.05] = np.nan
    return df, y


def test_ratio_and_se_match_reference():
    df, y = toy()
    d = Design(df["EST_DIS"], df["UPM_DIS"], df["w"])
    member = (df["g"] == "x").to_numpy()
    R, se, nv = d.ratio(y, np.flatnonzero(member))
    # PSU labels are nested within strata in the Design (stratum|psu key)
    R0, se0 = naive_ratio_se(y, df["w"].to_numpy(), df["EST_DIS"].to_numpy(),
                             (df["EST_DIS"] + "|" + df["UPM_DIS"]).to_numpy(), member)
    assert R == pytest.approx(R0) and se == pytest.approx(se0)
    assert nv == int((member & ~np.isnan(y)).sum())


def test_suppression_and_margins():
    df, y = toy(n=100)
    d = Design(df["EST_DIS"], df["UPM_DIS"], df["w"])
    dims = {"g": {"all": np.ones(100, bool), "x": (df["g"] == "x").to_numpy(),
                  "y": (df["g"] == "y").to_numpy()},
            "tiny": {"all": np.ones(100, bool), "few": np.arange(100) < 10}}
    out = estimate_cells(df, d, dims, {"ind": y}, min_n=30)
    few = out[out["tiny"] == "few"]
    assert few["suppressed"].all() and few["ind"].isna().all() and few["pop"].isna().all()
    assert (few["n"] > 0).all()
    allrow = out[(out["g"] == "all") & (out["tiny"] == "all")].iloc[0]
    assert allrow["n"] == 100 and not allrow["suppressed"]
    assert "ind_n" in out.columns  # indicator has missing values


def test_gate_coding():
    df = pd.DataFrame({"P7_1": ["1", "1", "2", "1"], "P7_15": ["1", "2", "", "1"],
                       "P7_16_1": ["1", "", "", "9"]})
    ind = Indicator("fb", "persons", ("P7_16_1",), "", "", (("P7_1", "1"), ("P7_15", "1")))
    y = code_indicator(df, ind)
    assert y[0] == 1 and y[1] == 0 and y[2] == 0 and np.isnan(y[3])
    with pytest.raises(ValueError):
        code_indicator(df, Indicator("x", "persons", ("NOPE",), "", ""))
