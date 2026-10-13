# silicon-sample-validation

> **Resumen.** Arnés abierto para validar muestras sintéticas generadas con modelos de lenguaje («silicon samples») contra encuestas oficiales por estado o ciudad. Registra los pronósticos antes de que salga la cifra oficial, en un archivo encadenado con SHA-256. Sólo califica cifras publicadas después del corte de entrenamiento del modelo y exige superar referencias simples que no usan IA. Incluye una sonda de memorización y un análisis de dónde falla el método. Los datos de ejemplo son **sintéticos** y no son resultados.

An open harness for checking LLM-based silicon samples against official statistics, written so the analysis can be pre-registered. The method being tested produces estimates per state or city, for example the share of the population with some characteristic. This package decides whether those estimates count as evidence.

## Research questions

The harness is built around four questions:

1. **Closeness.** How close are the simulated estimates to official survey figures, by state and by city (MAE, RMSE, bias, correlation, interval coverage)?
2. **Baselines.** Does the method beat simple baselines that need no LLM: the last published value, the national mean, and a demographics-only regression? A method that doesn't beat all of them doesn't count.
3. **Anchoring.** Does anchoring simulated respondents in real interviews beat demographics-only prompting, in a paired comparison over the same units?
4. **Failure.** Where does it fail: by region, urbanization, presence of indigenous-language speakers, or dispersion of the simulated answers?

## Safeguards

| Risk | Safeguard | API |
|---|---|---|
| Forecasts adjusted after seeing the answer | Append-only JSONL registry with SHA-256 hash chaining and UTC timestamps. Publish the head hash and entry count before the release. | `ForecastRegistry` |
| The model saw the answer during training | Only targets published **after** the declared training cutoff are scored (optional margin; optional rule that the reference period also ends after the cutoff). The guard fails closed. | `filter_post_cutoff` |
| The model just *remembers* the figure | Memorization probe: ask the bare model, with no persona, for the official number, and flag answers within tolerance | `run_memorization_probe` |
| "Good" numbers that a naive rule also gets | Mandatory baselines. A paired bootstrap of the MAE difference must exclude 0 for every one. | `compare_to_baselines` |
| Selective reporting | Verdicts are explicit ("does not beat: … (report as a negative result)"). Every bootstrap is seeded. The code is open. | |

Negative results should be reported with the same detail as positive ones, with code and seeds.

## Install

```bash
pip install -e ".[test]"               # numpy only
pip install -e ".[test,anthropic]"     # + optional Claude adapter
pytest                                 # offline; the live API test is skipped
```

Python ≥ 3.11.

## Usage

```python
from silicon_sample_validation import (
    ForecastRegistry, filter_post_cutoff, build_baselines, compare_to_baselines,
    compare_two, error_breakdown, ProbeTarget, run_memorization_probe, MockLLM,
)

# 1. Before the release: register forecasts, then publish the head hash and entry count
#    (reg.head(), reg.verify().n_entries) somewhere public.
reg = ForecastRegistry("forecasts.jsonl")
reg.append("survey-2027:unit-07:indicator-x", 31.4, lower=27.0, upper=35.8,
           model="claude-haiku-5-5", method="anchored", seed=2027)

# 2. After the release: verify against what was published, keep only pre-registered, post-cutoff targets.
assert reg.verify(expected_head=published_head, expected_n=published_n).ok
pre = reg.preregistered({t["target_id"]: t["published_at"] for t in targets})
eligible = filter_post_cutoff(targets, training_cutoff="2026-06-30").eligible

# 3. Score against baselines (previous wave + demographics only use pre-release information).
base = build_baselines(previous_values, covariates=census_shares)
report = compare_to_baselines(official, estimates, base, lower, upper, method="anchored")
print(report.table()); print(report.verdict)

# 4. Anchored vs demographics-only, paired over the same units.
print(compare_two(official, anchored, demographic_only, "anchored", "demographics-only"))

# 5. Where it fails (columns supplied by you).
error_breakdown(records, by=["region", "urbanization", "indigenous_language", "dispersion"])

# 6. Memorization probe: any callable prompt -> text works.
summary = run_memorization_probe(MockLLM(), [ProbeTarget(...)], rel_tol=0.02)
```

Command line:

```bash
ssv head   forecasts.jsonl --count                # head hash and entry count to publish before the release
ssv verify forecasts.jsonl                        # exit 1 if a line was edited, reordered or deleted (except at the end)
ssv verify forecasts.jsonl --head HASH --count N  # also exit 1 if entries were removed from the end or the file was replaced
ssv demo                       # end-to-end run on SYNTHETIC data
```

### Optional Claude adapter

```python
from silicon_sample_validation.adapters.anthropic_adapter import AnthropicLLM, anthropic_available
if anthropic_available():                  # `anthropic` installed and ANTHROPIC_API_KEY set
    llm = AnthropicLLM()                   # default model "claude-haiku-5-5", effort "low"
    run_memorization_probe(llm, targets)
```

The core package never imports `anthropic`. Refusals come back as an empty answer, and the probe counts them as "declined". You can plug any other provider in as a plain function.

## Synthetic demo

```bash
python examples/demo_synthetic.py      # or: ssv demo
```

The demo builds 32 **synthetic** units (`SYNTHETIC-UNIT-01…`) from a random-number generator, seed 2027. It registers forecasts with a fixed clock, applies the cutoff and pre-registration guards, scores against baselines, compares anchored vs. demographics-only, breaks errors down and runs the probe with a mock that has "memorized" two figures. Finally it edits one past forecast to show that verification catches the change. The fake data contain a planted failure mode, larger errors where `indigenous_language == "yes"`, so the breakdown has something to find. **None of these numbers is a result about any real method, model or place.** Excerpt:

```
  SYNTHETIC DEMO DATA - not real, not results
[2] Training cutoff 2026-06-30: 28 eligible, 4 excluded
[3] Synthetic method vs naive baselines
    vs last_published           dMAE=+0.460 95% CI [-0.301, +1.253] skill=-0.26
    verdict on SYNTHETIC data: does not beat: last_published, demographic_regression (report as a negative result)
[7] Editing one past forecast breaks the chain:
    ok=False; first error: line 4: hash mismatch (entry was modified)
```

## Method details

* **Registry.** Each line holds exactly `{schema, seq, timestamp, prev_hash, record, hash}`, where `hash = SHA-256(canonical JSON of the other fields)` (sorted keys, no whitespace, NaN rejected). `verify()` recomputes every hash and checks the chain links, the sequence numbers and that timestamps never go backwards. It also rejects lines with duplicate keys, with fields outside that set, or that aren't byte-for-byte the canonical JSON of their entry, so no reader can be shown a value the hash doesn't cover. Deleting or editing a line breaks the chain, *except* deleting lines at the end (truncation): what remains is still a valid chain. Truncation, or replacing the whole file with another valid chain, is detected only by `verify(expected_head=..., expected_n=...)` (`ssv verify --head HASH --count N`) against a head and count published earlier. Entries appended after publication are allowed. `append()` refuses to write onto a chain that fails verification, and it holds an exclusive `fcntl.flock` on the file from verification to write, so concurrent appends from several processes stay chained. Windows has no lock: append from one process at a time there. For each target, the forecast that gets scored is the **last one registered strictly before** the official release.
* **Metrics.** MAE, RMSE, bias (estimate − official), Pearson and Spearman correlation, interval coverage vs. nominal, mean width, and interval score (Gneiting & Raftery 2007).
* **Beating baselines.** For each baseline, units are resampled with a paired bootstrap of `MAE_method − MAE_baseline`. The method beats the baseline only if the whole 95% CI is below 0. `skill = 1 − MAE_method/MAE_baseline`. With fewer than 10 units, the verdict is `not evaluable (too few units)`. It is `not evaluable (bootstrap has zero spread)` when every unit's error difference is identical, so the CI collapses to a point.
* **Baselines.** `last_published` is the previous official value. `national_mean` is the previous-wave national figure, or the weighted mean of the previous values. `demographic_regression` is OLS on the previous wave applied to current demographics. `demographic_regression_loo` is an optional, stronger benchmark labelled *not pre-release*, because it uses other units' current official values.
* **Probe.** The prompt contains no persona, in English or Spanish, and asks for a single number or UNKNOWN. The parser handles decimal commas (including `0,125`) and thousands separators. When an answer contains several numbers, it takes the one next to `%`, "percent" / "por ciento" or the target's unit. Failing that, it skips four-digit years (1900–2100) if another number is present. Otherwise it takes the first number. A target is flagged when the median answer falls within `max(abs_tol, rel_tol·|official|)` (default 2% relative). If a naive guess, such as the national mean, is just as close, the flag is marked *ambiguous*.

## Limitations

* The hash chain proves internal consistency, not wall-clock time. The machine's clock is trusted. Timing becomes auditable only once the head hash and entry count are published somewhere independent: an OSF pre-registration, a public commit, an RFC 3161 timestamp, or an e-mail to the editor. Without them, dropping the most recent forecasts goes undetected.
* A declared training cutoff is the provider's claim. Post-cutoff targets can still leak through earlier releases about the same period, such as preliminary figures or press coverage. Use `period_end_key` and a margin.
* The probe can only flag recall that the model *produces*. A model that knows a figure but answers UNKNOWN goes undetected. Close answers may also be lucky guesses, which is why naive guesses are checked too.
* With 32 states, or a few dozen cities, the CIs are wide. A failure to beat a baseline may mean the comparison lacks power, not that the method is worse. Report the CIs.
* The failure breakdown is marginal: one column at a time, with no interactions. Groups with fewer than 5 units are marked as small.
* Official survey estimates have their own sampling error. The harness treats them as truth, so a small MAE can fall within the survey's own margin.

## References


* Argyle, L. P., Busby, E. C., Fulda, N., Gubler, J. R., Rytting, C., & Wingate, D. (2023). Out of one, many: Using language models to simulate human samples. *Political Analysis*, 31(3), 337–351.
* Ashokkumar, A., Hewitt, L., Ghezae, I., & Willer, R. (2026). Large language models can predict the results of social science experiments. *Nature*.
* Bisbee, J., Clinton, J. D., Dorff, C., Kenkel, B., & Larson, J. M. (2024). Synthetic replacements for human survey data? The perils of large language models. *Political Analysis*, 32(4), 401–416.
* Gneiting, T., & Raftery, A. E. (2007). Strictly proper scoring rules, prediction, and estimation. *Journal of the American Statistical Association*, 102(477), 359–378.
* Hullman, J., Broska, D., Sun, H., & Shaw, A. (2026). This human study did not involve human subjects: Validating LLM simulations as behavioral evidence. Preprint, arXiv.
* Kozlowski, A. C., & Evans, J. (2025). Simulating subjects: The promise and peril of artificial intelligence stand-ins for social agents and interactions. *Sociological Methods & Research*, 54, 1017–1073.

## License

MIT © 2026 Giovanni Oliveira. See [LICENSE](LICENSE).

---

Part of the Hybrid Intelligence open lab — https://github.com/Neckr0ik
