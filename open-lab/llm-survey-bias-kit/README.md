# llm-survey-bias-kit

> **Resumen.** Herramientas abiertas para revisar respuestas simuladas por modelos de lenguaje (encuestas y pruebas de mensajes): sesgo por orden de las opciones, comparación A/B pareada con réplicas e intervalos de confianza, prueba A/A para medir el ruido, homogeneidad frente a una referencia humana, subgrupos con muy pocas unidades y tamaño efectivo de Kish. Son diagnósticos de una simulación. No miden la opinión pública.

Diagnostics for answers produced by LLM "silicon samples" in survey-style questions and message tests. The kit doesn't generate anything. It checks whether a set of simulated answers can support the comparison you want to make.

| Problem | Function | What it tells you |
|---|---|---|
| LLMs prefer options by **position** | `build_option_orders`, `assign_directions`, `estimate_order_effect` | Forward vs. reversed shares, TVD with permutation p-value, primacy index, order-balanced distribution |
| Is message A really different from B? | `paired_ab`, `paired_ab_from_records` | Paired difference, 95% CI (t and bootstrap), MDE, verdict |
| How big is the pipeline's own noise? | `aa_test`, `aa_split_replicates` | A/A difference and a **noise floor** you can pass to `paired_ab` |
| Simulated answers are **too homogeneous** | `categorical_dispersion`, `numeric_dispersion` | Entropy / SD ratio vs. a human reference, with bootstrap CI |
| Subgroup cuts that are too thin | `subgroup_sizes` | Distinct units per cell, flags cells below 12 units (configurable) |
| Unequal design weights | `kish_effective_n`, `kish_by_group` | Kish effective n, design effect |

Python ≥ 3.11. Its only dependency is NumPy. If SciPy is installed, it computes the t quantiles. Otherwise a built-in implementation does, and it matches SciPy to better than 1e-6 (tested both ways).

## Install

```bash
pip install -e ".[test]"        # from this folder
pytest                          # offline, deterministic
```

## Usage

### Python

```python
import numpy as np
from llm_survey_bias_kit import paired_ab, aa_test, estimate_order_effect, build_option_orders

# scores_a / scores_b: shape (n_units, n_replicates), rows = the same simulated units
aa = aa_test(run_1_of_A, run_2_of_A)                    # same message twice
res = paired_ab(scores_a, scores_b, noise_floor=aa.noise_floor)
print(res.diff, res.ci_t, res.ci_boot, res.mde, res.verdict)

plans = build_option_orders(["agree", "neutral", "disagree"], n_batches=10)  # forward/reversed
effect = estimate_order_effect(responses, ["agree", "neutral", "disagree"])  # [{"direction", "choice"}, ...]
print(effect.tvd, effect.p_value, effect.primacy_index, effect.balanced_share)
```

### Command line

The CLI reads one CSV (delimiter auto-detected among `, ; tab |`). Add `--json` to any command for machine-readable output.

```bash
python examples/make_synthetic_csvs.py /tmp/demo     # SYNTHETIC example files

llm-bias-kit paired      /tmp/demo/paired.csv --a msg_A --b msg_B [--noise-floor 0.2]
llm-bias-kit aa          /tmp/demo/paired.csv --a msg_A --b msg_A_rerun
llm-bias-kit aa          /tmp/demo/paired.csv --split msg_B        # needs >= 4 replicates
llm-bias-kit order       /tmp/demo/order.csv --options agree,neutral,disagree
llm-bias-kit homogeneity /tmp/demo/sim_choices.csv --reference /tmp/demo/reference.csv
llm-bias-kit homogeneity scores.csv --numeric --value-col score --reference-sd 2.4
llm-bias-kit subgroups   /tmp/demo/paired.csv --by region [--min-units 12] [--strict]
llm-bias-kit kish        /tmp/demo/weights.csv --by region
```

Expected columns, with defaults that you can change through flags: long format `unit_id, message, score` (one row per replicate) for `paired`/`aa`, `direction, choice` for `order`, `category, share` for the reference table, and `weight` for `kish`.

Excerpt from the synthetic example (random data, not a finding):

```
msg_A vs msg_B: units=120 replicates=3
  paired diff=0.2576  95% CI t=[0.1323, 0.3829]  bootstrap=[0.1342, 0.3833]
  MDE (80% power)=0.1787  within-unit replicate SD=0.8185
  verdict: DISTINGUISHABLE
```

## Method

**Answer order.** Dominguez-Olmedo et al. (2024) showed that LLM survey answers depend heavily on the order and labelling of options. The kit counterbalances the order: alternate batches see the options forward and reversed (`scheme="rotate"` cycles through every rotation). It then compares the two halves:

* per-option shift `share_forward − share_reversed`, with a bootstrap CI;
* total-variation distance (TVD) between the two distributions, with a permutation p-value (direction labels shuffled);
* primacy index `½[(f_first − r_first) + (r_last − f_last)]`. It is +1 for a model that always picks the first displayed option, −1 for pure recency, and 0 when order has no effect;
* the order-balanced distribution `½(forward + reversed)`, which is what you should report.

**Paired A/B.** Every simulated unit answers both messages, R times each. Replicates are averaged within each unit, and the paired difference is analysed across units:

* CI from the t distribution (`df = n − 1`) and a unit-level percentile bootstrap;
* `MDE = (t₁₋α/₂ + t_power) · SD_diff / √n`, the smallest true effect detectable with 80% power. `required_units()` inverts it;
* verdict: **not evaluable** with fewer than 2 replicates per unit (or fewer than 2 units), because one LLM call per unit can't separate the model's sampling noise from a message effect. **Distinguishable** when both CIs exclude 0 and |diff| exceeds the A/A noise floor, if one was given. **Indistinguishable** otherwise. "Indistinguishable" doesn't mean the messages are equal. Read it against the MDE.

**A/A.** The same message is simulated twice, either as two runs or by splitting each unit's replicates in half. The noise floor is the largest absolute bound of the A/A 95% CI. An A/A test that comes out "distinguishable" is a red flag: replicates may not be independent, or the pipeline may be caching or drifting.

**Homogeneity.** Bisbee et al. (2024) found that LLM-simulated answers have much less variance than human answers. For categorical items the kit compares normalised Shannon entropy (`H/log k`), the Gini–Simpson index, modal share and TVD against a human reference (raw answers or published proportions). It flags the items as too homogeneous when `H_sim/H_ref < 0.8`. For numeric scales it compares SDs. The 0.8 threshold is a convention and you can change it.

**Thin subgroups.** `subgroup_sizes` counts **distinct units**, not rows, because replicates of one simulated person add nothing about the subgroup. Cells with fewer than 12 units are marked not reportable.

**Kish effective n.** `n_eff = (Σw)²/Σw²` and `deff = n/n_eff = 1 + CV²(w)` (Kish 1965).

## Limitations

* These are diagnostics of a **simulation**. None of the outputs is a measure of public opinion or of voting intention.
* Reversal separates primacy from recency, but it doesn't separate either one from effects at specific positions in the middle of the list. Use `scheme="rotate"` for that. Order effects can also interact with option labels (A/B/C vs. 1/2/3), and this kit doesn't model that.
* The bootstrap CI for TVD is biased upwards near 0, because TVD ≥ 0. Use the permutation p-value to test for an effect.
* The paired analysis treats simulated units as exchangeable draws. If units come from a weighted design, apply weights before aggregating and check the Kish effective n. The CIs here are unweighted.
* The homogeneity thresholds and the 12-unit minimum are conventions, not statistical laws.
* The CLI loads the whole CSV into memory. It is meant for files of up to a few million rows.

## References

* Argyle, L. P., Busby, E. C., Fulda, N., Gubler, J. R., Rytting, C., & Wingate, D. (2023). Out of one, many: Using language models to simulate human samples. *Political Analysis*, 31(3), 337–351.
* Bisbee, J., Clinton, J. D., Dorff, C., Kenkel, B., & Larson, J. M. (2024). Synthetic replacements for human survey data? The perils of large language models. *Political Analysis*, 32(4), 401–416.
* Dominguez-Olmedo, R., Hardt, M., & Mendler-Dünner, C. (2024). Questioning the survey responses of large language models. *Advances in Neural Information Processing Systems (NeurIPS)*.
* Kish, L. (1965). *Survey Sampling*. New York: Wiley.

## License

MIT © 2026 Giovanni Oliveira. See [LICENSE](LICENSE).

---

Part of the Hybrid Intelligence open lab — https://github.com/Neckr0ik
