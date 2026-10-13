import pytest

from silicon_sample_validation import (
    MockLLM,
    ProbeTarget,
    build_probe_prompt,
    parse_numeric_answer,
    run_memorization_probe,
)

T = [
    ProbeTarget("a", "poverty rate", "Synthetic-1", "synthetic survey", "2026", 40.0, unit="%"),
    ProbeTarget("b", "poverty rate", "Synthetic-2", "synthetic survey", "2026", 20.0, unit="%", naive_guess=20.2),
    ProbeTarget("c", "poverty rate", "Synthetic-3", "synthetic survey", "2026", 30.0),
]


def test_prompt_has_no_persona_and_all_fields():
    p = build_probe_prompt(T[0])
    assert "Do not role-play" in p and "Synthetic-1" in p and "synthetic survey" in p and "(in %)" in p
    es = build_probe_prompt(T[0], "es")
    assert "No interpretes" in es and "DESCONOCIDO" in es
    with pytest.raises(ValueError):
        build_probe_prompt(T[0], "fr")


@pytest.mark.parametrize(
    "text,value",
    [
        ("42", 42.0),
        ("45.3%", 45.3),
        ("45,3 %", 45.3),
        ("1,234.5", 1234.5),
        ("1.234,5", 1234.5),
        ("12,345", 12345.0),
        ("-3.5", -3.5),
        ("About 31.4 percent.", 31.4),
        ("UNKNOWN", None),
        ("DESCONOCIDO", None),
        ("", None),
        (None, None),
        ("I don't know", None),
    ],
)
def test_parse_numeric_answer(text, value):
    assert parse_numeric_answer(text) == value


def test_memorizing_mock_is_flagged():
    mock = MockLLM.memorizing(T, ids=["a"])
    s = run_memorization_probe(mock, T)
    assert s.flagged_ids == ["a"]
    assert s.n_answered == 1 and s.n_targets == 3
    r = {x.target_id: x for x in s.results}
    assert r["a"].status.startswith("too close") and r["a"].abs_error == 0
    assert r["b"].status == "declined"
    assert len(mock.calls) == 3


def test_tolerance_rel_and_abs():
    mock = MockLLM.memorizing(T, offset=0.7)  # every answer off by 0.7
    s = run_memorization_probe(mock, T, rel_tol=0.02)
    # tolerances: 0.8, 0.4, 0.6 -> only "a" is within
    assert s.flagged_ids == ["a"]
    s2 = run_memorization_probe(mock, T, rel_tol=0.0, abs_tol=1.0)
    assert s2.n_flagged == 3


def test_ambiguous_when_naive_guess_equally_close():
    mock = MockLLM.memorizing(T, ids=["b"])
    s = run_memorization_probe(mock, T)
    r = {x.target_id: x for x in s.results}
    assert r["b"].flagged and r["b"].ambiguous and s.n_ambiguous == 1


def test_median_of_samples():
    answers = iter(["10", "40", "41", "UNKNOWN", "39"])
    mock = MockLLM(lambda p: next(answers))
    s = run_memorization_probe(mock, T[:1], n_samples=5)
    assert s.results[0].values == [10.0, 40.0, 41.0, 39.0]
    assert s.results[0].probe_value == pytest.approx(39.5)
    with pytest.raises(ValueError):
        run_memorization_probe(mock, T, n_samples=0)


def test_mock_default_and_mapping():
    m = MockLLM({"hi": "1"}, default="nope")
    assert m("hi") == "1" and m("x") == "nope" and m.calls == ["hi", "x"]
