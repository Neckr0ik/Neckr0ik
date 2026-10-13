import pytest

from llm_survey_bias_kit import (
    FORWARD,
    REVERSED,
    assign_directions,
    build_option_orders,
    estimate_order_effect,
)

OPTS = ["agree", "neutral", "disagree"]


def test_build_reverse_alternates():
    plans = build_option_orders(OPTS, 4)
    assert [p.direction for p in plans] == [FORWARD, REVERSED, FORWARD, REVERSED]
    assert plans[0].order == tuple(OPTS)
    assert plans[1].order == tuple(reversed(OPTS))


def test_build_rotate_cycles():
    plans = build_option_orders(OPTS, 4, scheme="rotate")
    assert plans[1].order == ("neutral", "disagree", "agree")
    assert plans[3].order == tuple(OPTS)
    assert plans[2].direction == "rotation-2"


@pytest.mark.parametrize("bad", [["a"], ["a", "a"]])
def test_build_rejects_bad_options(bad):
    with pytest.raises(ValueError):
        build_option_orders(bad, 2)


def test_build_rejects_bad_scheme():
    with pytest.raises(ValueError):
        build_option_orders(OPTS, 2, scheme="shuffle")


def test_assign_directions_balanced_and_reproducible():
    ids = list(range(11))
    a = assign_directions(ids, seed=1)
    b = assign_directions(ids, seed=1)
    assert a == b
    n_fwd = sum(v == FORWARD for v in a.values())
    assert n_fwd in (5, 6)


def _resp(direction, choice, n):
    return [{"direction": direction, "choice": choice}] * n


def test_pure_primacy_model():
    # A model that always picks whatever is displayed first.
    data = _resp("forward", "agree", 50) + _resp("reversed", "disagree", 50)
    r = estimate_order_effect(data, OPTS, n_boot=200, n_perm=200)
    assert r.share_forward == {"agree": 1.0, "neutral": 0.0, "disagree": 0.0}
    assert r.share_reversed == {"agree": 0.0, "neutral": 0.0, "disagree": 1.0}
    assert r.tvd == pytest.approx(1.0)
    assert r.primacy_index == pytest.approx(1.0)
    assert r.balanced_share == {"agree": 0.5, "neutral": 0.0, "disagree": 0.5}
    assert r.flagged and r.p_value < 0.01


def test_pure_recency_model():
    data = _resp("forward", "disagree", 40) + _resp("reversed", "agree", 40)
    r = estimate_order_effect(data, OPTS, n_boot=100, n_perm=100)
    assert r.primacy_index == pytest.approx(-1.0)


def test_no_order_effect():
    block = _resp("x", "agree", 0)
    data = []
    for d in ("forward", "reversed"):
        data += _resp(d, "agree", 30) + _resp(d, "neutral", 20) + _resp(d, "disagree", 10)
    r = estimate_order_effect(data, OPTS, n_boot=200, n_perm=500)
    assert block == []
    assert r.tvd == pytest.approx(0.0)
    assert r.primacy_index == pytest.approx(0.0)
    assert r.p_value == pytest.approx(1.0)
    assert not r.flagged
    assert r.shift_ci["agree"][0] <= 0 <= r.shift_ci["agree"][1]


def test_partial_effect_known_shift():
    data = (
        _resp("forward", "agree", 60) + _resp("forward", "disagree", 40)
        + _resp("reversed", "agree", 40) + _resp("reversed", "disagree", 60)
    )
    r = estimate_order_effect(data, OPTS, n_boot=200, n_perm=200)
    assert r.shift["agree"] == pytest.approx(0.2)
    assert r.tvd == pytest.approx(0.2)
    assert r.primacy_index == pytest.approx(0.2)


def test_direction_case_insensitive_and_errors():
    data = _resp("FORWARD", "agree", 3) + _resp("Reversed", "agree", 3)
    r = estimate_order_effect(data, OPTS, n_boot=10, n_perm=10)
    assert r.n_forward == 3 and any("fewer than 30" in n for n in r.notes)
    with pytest.raises(ValueError):
        estimate_order_effect(_resp("forward", "agree", 3), OPTS)
    with pytest.raises(ValueError):
        estimate_order_effect(_resp("forward", "maybe", 3) + _resp("reversed", "agree", 3), OPTS)
    with pytest.raises(ValueError):
        estimate_order_effect(_resp("sideways", "agree", 3), OPTS)


def test_order_effect_reproducible():
    data = _resp("forward", "agree", 20) + _resp("forward", "neutral", 5) + _resp("reversed", "agree", 15) + _resp("reversed", "neutral", 10)
    a = estimate_order_effect(data, OPTS, seed=3)
    b = estimate_order_effect(data, OPTS, seed=3)
    assert a.to_dict() == b.to_dict()
