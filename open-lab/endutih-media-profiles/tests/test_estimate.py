import numpy as np
import pandas as pd
import pytest

from endutih_media_profiles.estimate import Design, complementary_mask, estimate_cells
from endutih_media_profiles.query import wilson_ci
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


def _one_unknown_relations(out, dims_parts, col):
    """Independent check: (total, parts) groups along one dimension with exactly one blank."""
    names = list(dims_parts)
    found = []
    for d, parts in dims_parts.items():
        others = [x for x in names if x != d]
        for _, g in out.groupby(others):
            g = g.set_index(d)
            members = [m for m in ["all", *parts] if m in g.index]
            if len(members) >= 2 and int(g.loc[members, col].isna().sum()) == 1:
                found.append(d)
    return found


def test_complementary_suppression_blocks_recovery_by_subtraction():
    rng = np.random.default_rng(7)
    n = 400
    df = pd.DataFrame({"EST_DIS": rng.choice(["a", "b"], n), "UPM_DIS": rng.choice([f"p{i}" for i in range(20)], n),
                       "w": rng.uniform(1, 5, n)})
    g = np.where(np.arange(n) < 20, "x", np.where(np.arange(n) < 200, "y", "z"))  # x is tiny
    h = rng.choice(["u", "r"], n)
    y = (rng.random(n) < 0.5).astype(float)
    dims = {"g": {"all": np.ones(n, bool), **{k: g == k for k in ("x", "y", "z")}},
            "h": {"all": np.ones(n, bool), **{k: h == k for k in ("u", "r")}}}
    d = Design(df["EST_DIS"], df["UPM_DIS"], df["w"])
    plain = estimate_cells(df, d, dims, {"ind": y}, min_n=30, complementary=False)
    assert _one_unknown_relations(plain, {"g": ["x", "y", "z"], "h": ["u", "r"]}, "ind")  # the leak
    out = estimate_cells(df, d, dims, {"ind": y}, min_n=30)
    assert not _one_unknown_relations(out, {"g": ["x", "y", "z"], "h": ["u", "r"]}, "ind")
    assert not _one_unknown_relations(out, {"g": ["x", "y", "z"], "h": ["u", "r"]}, "pop")
    comp = out[out["suppression"] == "complementary"]
    assert len(comp) and comp["suppressed"].all() and comp[["ind", "ind_se", "pop"]].isna().all().all()
    assert (comp["n"] >= 30).all()
    assert ((out["suppression"] == "primary") == (out["n"] < 30)).all()
    margin = out[(out["g"] == "all") & (out["h"] == "all")].iloc[0]
    assert margin["suppression"] == "none"  # parts are blanked before totals
    # published values are untouched
    keep = out["suppression"] == "none"
    assert out.loc[keep, "ind"].tolist() == plain.loc[keep, "ind"].tolist()


def test_complementary_mask_prefers_smallest_part_and_handles_single_part():
    # total 0 with parts 1, 2, 3; part 1 is blank -> the smaller remaining part (2) is blanked
    m = complementary_mask(np.array([False, True, False, False]), np.array([100, 10, 40, 50]), [(0, [1, 2, 3])])
    assert m.tolist() == [False, True, True, False]
    # a total with a single part is the same cell: blanking one blanks the other
    assert complementary_mask(np.array([False, True]), np.array([40, 40]), [(0, [1])]).tolist() == [True, True]


def test_bad_relation_is_rejected():
    df, y = toy(n=50)
    d = Design(df["EST_DIS"], df["UPM_DIS"], df["w"])
    dims = {"g": {"all": np.ones(50, bool), "x": (df["g"] == "x").to_numpy()}}
    with pytest.raises(ValueError, match="not an exact partition"):
        estimate_cells(df, d, dims, {"ind": y}, relations={"g": [("all", ["x"])]})


def test_wilson_ci():
    # matches the closed form on the design-effect-adjusted n
    p, se = 0.2, 0.04
    lo, hi = wilson_ci(p, se)
    n = p * (1 - p) / se**2  # 100
    z = 1.959964
    c = (p + z * z / (2 * n)) / (1 + z * z / n)
    h = z * np.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / (1 + z * z / n)
    assert (lo, hi) == pytest.approx((c - h, c + h))
    assert lo > 0 and hi - p > p - lo  # asymmetric towards the middle, unlike Wald
    lo2, hi2 = wilson_ci(0.01, 0.02)  # Wald would go below 0
    assert lo2 >= 0 and hi2 < 1
    assert np.isnan(wilson_ci(0.0, 0.0)[0]) and np.isnan(wilson_ci(1.0, 0.0)[1]) and np.isnan(wilson_ci(0.5, 0.0)[0])
    big = wilson_ci(0.5, 0.001)  # large n_eff: close to Wald
    assert big == pytest.approx((0.5 - 1.96 * 0.001, 0.5 + 1.96 * 0.001), abs=1e-5)
