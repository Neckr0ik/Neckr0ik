"""Memorization probe.

Before crediting a silicon sample for matching an official figure, ask the same
model for the figure directly - with no persona, no simulated respondents, no
anchoring data. If the bare model already "knows" the number, agreement of the
simulation with the official value is not evidence for the method.

The interface is provider-agnostic: an LLM is any callable ``prompt -> text``.
"""

from __future__ import annotations

import math
import re
from dataclasses import dataclass, field
from typing import Callable, Iterable, Mapping, Sequence

LLM = Callable[[str], str]

PROMPTS = {
    "en": (
        "This is a factual recall question. Do not role-play or simulate any person.\n"
        "What is the official value of the indicator below, as published by the source?\n"
        "Indicator: {indicator}\n"
        "Geography: {geography}\n"
        "Source: {source}\n"
        "Reference period: {period}\n"
        "Answer with a single number{unit_hint} and nothing else. "
        "If you do not know it, answer UNKNOWN."
    ),
    "es": (
        "Esta es una pregunta de memoria factual. No interpretes ni simules a ninguna persona.\n"
        "¿Cuál es el valor oficial del indicador siguiente, tal como lo publicó la fuente?\n"
        "Indicador: {indicator}\n"
        "Geografía: {geography}\n"
        "Fuente: {source}\n"
        "Periodo de referencia: {period}\n"
        "Responde sólo con un número{unit_hint} y nada más. "
        "Si no lo sabes, responde DESCONOCIDO."
    ),
}

_DECLINE = re.compile(r"\b(unknown|desconocido|no s[eé]|don't know|do not know|n/?a)\b", re.I)
_NUM = re.compile(r"[-+]?\d[\d.,\s]*")


@dataclass(frozen=True)
class ProbeTarget:
    target_id: str
    indicator: str
    geography: str
    source: str
    period: str
    official_value: float
    unit: str = ""
    naive_guess: float | None = None  # e.g. the national mean; used to spot lucky guesses


def build_probe_prompt(target: ProbeTarget, language: str = "en") -> str:
    """Persona-free prompt asking the model for the official figure itself."""
    if language not in PROMPTS:
        raise ValueError(f"language must be one of {sorted(PROMPTS)}")
    hint = ""
    if target.unit:
        hint = f" (in {target.unit})" if language == "en" else f" (en {target.unit})"
    return PROMPTS[language].format(
        indicator=target.indicator,
        geography=target.geography,
        source=target.source,
        period=target.period,
        unit_hint=hint,
    )


def _to_float(tok: str) -> float | None:
    t = tok.strip().replace(" ", "")
    t = t.rstrip(".,")
    if not t or not re.search(r"\d", t):
        return None
    if "," in t and "." in t:
        # the right-most separator is the decimal mark
        if t.rfind(",") > t.rfind("."):
            t = t.replace(".", "").replace(",", ".")
        else:
            t = t.replace(",", "")
    elif "," in t:
        parts = t.split(",")
        if len(parts) == 2 and len(parts[1]) != 3:
            t = t.replace(",", ".")  # decimal comma: 45,3
        else:
            t = t.replace(",", "")  # thousands: 1,234
    try:
        v = float(t)
    except ValueError:
        return None
    return v if math.isfinite(v) else None


def parse_numeric_answer(text: str | None) -> float | None:
    """First number in the answer, or None if the model declined / gave none.

    Handles ``45.3``, ``45,3`` (decimal comma), ``1,234.5``, ``1.234,5`` and a
    trailing ``%``.
    """
    if text is None:
        return None
    s = str(text).strip()
    if not s or _DECLINE.search(s) and not re.search(r"\d", s):
        return None
    m = _NUM.search(s)
    return _to_float(m.group(0)) if m else None


@dataclass
class ProbeResult:
    target_id: str
    prompt: str
    answers: list[str]
    values: list[float]
    probe_value: float | None
    official_value: float
    abs_error: float | None
    rel_error: float | None
    tolerance: float
    flagged: bool
    ambiguous: bool
    status: str


@dataclass
class ProbeSummary:
    n_targets: int
    n_answered: int
    n_flagged: int
    n_ambiguous: int
    flagged_ids: list[str]
    results: list[ProbeResult] = field(default_factory=list)

    @property
    def share_flagged(self) -> float:
        return self.n_flagged / self.n_targets if self.n_targets else 0.0


def run_memorization_probe(
    llm: LLM,
    targets: Iterable[ProbeTarget],
    rel_tol: float = 0.02,
    abs_tol: float = 0.0,
    n_samples: int = 1,
    language: str = "en",
) -> ProbeSummary:
    """Ask the bare model for each figure and flag answers that are too close.

    A target is ``flagged`` when the median parsed answer is within
    ``max(abs_tol, rel_tol·|official|)`` of the official value. If the target's
    ``naive_guess`` is also within tolerance, the flag is marked ``ambiguous``
    (the bare model may simply have guessed the obvious number). Flagged targets
    should be excluded from headline scores or reported separately.
    """
    if n_samples < 1:
        raise ValueError("n_samples must be >= 1")
    results: list[ProbeResult] = []
    for t in targets:
        prompt = build_probe_prompt(t, language)
        answers = [str(llm(prompt)) for _ in range(n_samples)]
        vals = [v for v in (parse_numeric_answer(a) for a in answers) if v is not None]
        tol = max(abs_tol, rel_tol * abs(t.official_value))
        if not vals:
            results.append(ProbeResult(t.target_id, prompt, answers, [], None, t.official_value,
                                       None, None, tol, False, False, "declined"))
            continue
        vals_sorted = sorted(vals)
        mid = len(vals_sorted) // 2
        pv = vals_sorted[mid] if len(vals_sorted) % 2 else 0.5 * (vals_sorted[mid - 1] + vals_sorted[mid])
        ae = abs(pv - t.official_value)
        re_ = ae / abs(t.official_value) if t.official_value != 0 else None
        flagged = ae <= tol
        ambiguous = bool(flagged and t.naive_guess is not None and abs(t.naive_guess - t.official_value) <= tol)
        status = "too close (possible memorization)" if flagged else "not close"
        if ambiguous:
            status = "too close, but a naive guess is equally close (ambiguous)"
        results.append(ProbeResult(t.target_id, prompt, answers, vals, pv, t.official_value,
                                   ae, re_, tol, flagged, ambiguous, status))
    flagged_ids = [r.target_id for r in results if r.flagged]
    return ProbeSummary(
        n_targets=len(results),
        n_answered=sum(r.probe_value is not None for r in results),
        n_flagged=len(flagged_ids),
        n_ambiguous=sum(r.ambiguous for r in results),
        flagged_ids=flagged_ids,
        results=results,
    )


class MockLLM:
    """Deterministic stand-in for an LLM (no network).

    ``MockLLM({"exact prompt": "42.0"}, default="UNKNOWN")`` or
    ``MockLLM(lambda prompt: "...")``. Every prompt is recorded in ``calls``.
    """

    def __init__(self, responses: Mapping[str, str] | Callable[[str], str] | None = None,
                 default: str = "UNKNOWN"):
        self._responses = responses
        self.default = default
        self.calls: list[str] = []

    def __call__(self, prompt: str) -> str:
        self.calls.append(prompt)
        if callable(self._responses):
            return str(self._responses(prompt))
        if self._responses and prompt in self._responses:
            return str(self._responses[prompt])
        return self.default

    @classmethod
    def memorizing(cls, targets: Sequence[ProbeTarget], ids: Sequence[str] | None = None,
                   offset: float = 0.0, language: str = "en") -> "MockLLM":
        """A mock that 'knows' the official value of the given targets (all by default)."""
        chosen = set(ids) if ids is not None else {t.target_id for t in targets}
        table = {
            build_probe_prompt(t, language): f"{t.official_value + offset:g}"
            for t in targets if t.target_id in chosen
        }
        return cls(table)
