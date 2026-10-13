# Hybrid Intelligence · Method & Build Log

*Impulse Labs*

**Hybrid Intelligence** is the shared core behind Impulse Labs' products. It combines three things that are rarely in the same room: **official census data**, **real face-to-face interviews by INRA**, and **large language models**. The result is a *silicon sample*: a population of simulated people, each one anchored in a real Mexican profile, that reacts to a message before it goes public.

It is built to **anticipate objections, compare wordings and generate hypotheses**. It is not a poll, does not estimate voting intention and does not forecast sales; every product says so on screen.

---

## How a reading is built

```mermaid
flowchart LR
    A[Census 2020<br/>INEGI ITER] -->|probability sampling<br/>design weights| B[Simulated profile]
    C[INRA face-to-face<br/>interviews] -->|donor imputation<br/>k-anonymity| B
    D[Today's context<br/>news · speech text] --> E
    B --> E[LLM reaction<br/>stance · sentiment ·<br/>credibility · objection]
    E --> F[Optional influence rounds]
    E --> G[Paired A/B with 95% CI<br/>and minimum detectable effect]
```

| Step | What happens | Grounded in |
|:---|:---|:---|
| Census sampling | Municipalities drawn proportional to adult population; traits from Census 2020 cells; design weights and effective sample size reported | Kish (1965) |
| A real person behind each profile | Life and media context taken from an INRA interview with the same profile | Hot-deck imputation (Andridge & Little, 2010) · Argyle et al. (2023) · k-anonymity (Sweeney, 2002) |
| Context of the moment | Profiles react with the day's information | Social impact theory (Latané, 1981) |
| Reaction | The model answers *as that person*, within the limits of their data; answer order reversed in half the batches to cancel position bias | Algorithmic fidelity (Argyle et al., 2023) · Dominguez-Olmedo et al. (2024) |
| Influence rounds | Profiles see each other's stances and may change; who moved whom is logged | Latané (1981) · Moscovici et al. (1969) · Centola (2010) · Sunstein (2002) |
| A/B comparison | Paired per profile, replicated, order alternated; "indistinguishable" unless it beats the minimum detectable effect; A/A control | Ashokkumar et al. (2026) |

## Known limits, stated up front

Each of the three core products ships a **Scientific Basis** tab that lists what the literature says this method *cannot* do and how the tool handles it: simulated answers that are too homogeneous (Bisbee et al., 2024; Wang et al., 2025), models that represent the US and highly educated profiles better than others (Santurkar et al., 2023; Durmus et al., 2023; Atari et al., 2023), memorization of published polls (Kozlowski & Evans, 2025), inflated effect sizes (Ashokkumar et al., 2026) and the gap between a realistic simulation and a calibrated estimator (Hullman et al., 2026).

## Validation study · planned

The method's fidelity with the **Mexican population has not been measured yet**. A study in preparation, to be submitted for peer review, will test it against official INEGI surveys:

1. How close do simulated people get to the perception official surveys measure, by state and city?
2. Do they beat simple baselines that need no language model?
3. Does anchoring each person in a real interview beat describing them with demographics alone?
4. Where does it fail: region, urbanization, indigenous-language presence, opinion dispersion?

Safeguards: compare only against figures published after the model's training cutoff, register forecasts before the official release, run a memorization probe, and report negative results with open code and seeds. The harness is already open: [silicon-sample-validation](../open-lab/silicon-sample-validation).

---

## Products on the core

**ZÓKALO** · **MOSAIK** · **KALEIDO** — built on the Hybrid Intelligence Core.
**SKED** · **Ethea** — sister products from Impulse Labs.

All are private and in active development.

---

## Build log

| Date | Milestone |
|:---|:---|
| 2026-10-13 | **Public portfolio upgraded**: Spanish & Portuguese sentiment, message-framing comparison, bug fixes, offline tests and CI across all five repos |
| 2026-10-13 | **Open Lab** published: census sampler, ENDUTIH 2025 media profiles, LLM survey bias kit, validation harness and LLM gateway with metering — public data only, 227 tests, 224 of them offline in CI ([open-lab](../open-lab/README.md)) |
| 2026-10-12 | **Ethea**: new release |
| 2026-10-11 | Shared **Scientific Basis** module shipped in all three core products: method, evidence, limits and academic and official references, written once and rendered per brand |
| 2026-10-10 | **Core under version control**: one engine, three products, byte-identical reproducible builds (verified by fingerprint) and golden-hash regression tests for the sampler (fixed seed) |
| 2026-10-10 | **Core server v0**: run the products as a web app outside the chat interface, with accounts, a shared monthly quota per organization, per-user metering, run history in PostgreSQL and a switchable LLM provider (Anthropic API / Amazon Bedrock) |
| 2026-10-10 | **SKED** under version control |
| Next | One-command deploy with backup and rollback · split the shared engine into modules · validation study fieldwork |

## References

<sub>The same list the products' Scientific Basis tab cites.</sub>

- Andridge, R. R., & Little, R. J. A. (2010). A review of hot deck imputation for survey non-response. *International Statistical Review*, 78(1), 40–64.
- Argyle, L. P., et al. (2023). Out of one, many: Using language models to simulate human samples. *Political Analysis*, 31(3), 337–351.
- Ashokkumar, A., Hewitt, L., Ghezae, I., & Willer, R. (2026). Large language models can predict the results of social science experiments. *Nature*. (Earlier circulated as a working paper by Hewitt, Ashokkumar, Ghezae & Willer, 2024.)
- Atari, M., Xue, M. J., Park, P. S., Blasi, D. E., & Henrich, J. (2023). Which humans? Preprint.
- Bisbee, J., Clinton, J. D., Dorff, C., Kenkel, B., & Larson, J. M. (2024). Synthetic replacements for human survey data? The perils of large language models. *Political Analysis*, 32(4), 401–416.
- Centola, D. (2010). The spread of behavior in an online social network experiment. *Science*, 329, 1194–1197.
- Dominguez-Olmedo, R., Hardt, M., & Mendler-Dünner, C. (2024). Questioning the survey responses of large language models. *NeurIPS*, 37.
- Durmus, E., et al. (2023). Towards measuring the representation of subjective global opinions in language models. Preprint.
- Hullman, J., Broska, D., Sun, H., & Shaw, A. (2026). This human study did not involve human subjects: Validating LLM simulations as behavioral evidence. Preprint.
- INEGI. Censo de Población y Vivienda 2020 (ITER) · ENDUTIH 2025.
- Kish, L. (1965). *Survey Sampling*. Wiley.
- Kozlowski, A. C., & Evans, J. (2025). Simulating subjects: The promise and peril of artificial intelligence stand-ins for social agents and interactions. *Sociological Methods & Research*, 54, 1017–1073.
- Latané, B. (1981). The psychology of social impact. *American Psychologist*, 36, 343–356.
- Moscovici, S., Lage, E., & Naffrechoux, M. (1969). Influence of a consistent minority on the responses of a majority in a color perception task. *Sociometry*, 32(4), 365–380.
- Santurkar, S., et al. (2023). Whose opinions do language models reflect? *ICML*, PMLR 202, 29971–30004.
- Sunstein, C. R. (2002). The law of group polarization. *Journal of Political Philosophy*, 10(2), 175–195.
- Sweeney, L. (2002). k-anonymity: A model for protecting privacy. *International Journal of Uncertainty, Fuzziness and Knowledge-Based Systems*, 10(5), 557–570.
- Wang, A., Morgenstern, J., & Dickerson, J. P. (2025). Large language models that replace human participants can harmfully misportray and flatten identity groups. *Nature Machine Intelligence*, 7, 400–411.

<sub>Log entries describe engineering milestones only. Client data, interview content and product internals stay private.</sub>
