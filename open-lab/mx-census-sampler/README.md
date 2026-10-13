# mx-census-sampler

> **Resumen.** Muestreo reproducible con probabilidad proporcional al tamaño (PPS) de los 2,469 municipios de México según su población adulta (18+), con datos públicos del Censo de Población y Vivienda 2020 del INEGI (ITER). Asigna a cada persona simulada sexo, edad y escolaridad a partir de los conteos censales de su municipio, con pesos de diseño y tamaño efectivo de muestra de Kish.

`mx-census-sampler` draws seeded, reproducible **PPS samples of Mexican
municipalities** (measure of size = population 18+) from INEGI's 2020 Census,
and gives every selected respondent a **sex × age band × schooling profile**
drawn from that municipality's own census counts. It reports design weights,
Kish's effective sample size and a sample-vs-census summary.

It is a public building block of the Hybrid Intelligence approach: anchoring
LLM "silicon samples" in where Mexicans actually live and who they are, using
only public INEGI data. It is one of the open foundations behind Impulse Labs
products (ZÓKALO · MOSAIK · KALEIDO); it contains no product code and no
partner data.

## Data provenance

* **Source:** INEGI, *Censo de Población y Vivienda 2020 — Principales
  resultados por localidad (ITER)*, national CSV
  (`iter_00_cpv2020_csv.zip`, data file last modified by INEGI 2022-05-19).
* **What is committed:** `data/municipios_cpv2020.csv` — 2,469 rows (one per
  municipality), 33 columns, ~420 KB — plus `data/PROVENANCE.md` with the
  download URL, date, SHA-256 of the zip and the column mapping.
* **What is not committed:** the raw zip/CSV (~37 MB / 150 MB). `raw/` and
  `*.zip` are gitignored.
* **How it is derived:** ITER rows with `LOC == "0000"` and `MUN != "000"`
  (*Total del Municipio*). The build checks there are exactly 2,469 and that
  they add up to the national row in the same file (POBTOT 126,014,024; P_18YMAS
  87,492,680). Non-numeric (suppressed) values make the build fail rather than
  being imputed.
* **License:** INEGI *Términos de libre uso de la información*
  (<https://www.inegi.org.mx/inegi/terminos.html>). Attribution:
  *Fuente: INEGI. Censo de Población y Vivienda 2020.* This is a derived
  table; INEGI does not endorse it.

ITER columns used:

| Purpose | ITER mnemonics |
|---|---|
| Measure of size, totals | `POBTOT`, `POBFEM`, `POBMAS`, `P_18YMAS`, `P_18YMAS_F`, `P_18YMAS_M` |
| Sex × age band (18–24, 25–34, 35–44, 45–54, 55–64, 65+) | `P_18A24_F/_M`, `P_25A29…P_60A64_F/_M`, `P_65A69…P_85YMAS_F/_M` |
| Schooling | `P18YM_PB`, `P18YM_PB_F`, `P18YM_PB_M` (18+ with *posbásica*); `P_15YMAS`, `P15YM_SE`, `P15PRI_IN`, `P15PRI_CO`, `P15SEC_IN`, `P15SEC_CO` (15+); `GRAPROES` |
| Context only | `TVIVPARHAB`, `VPH_INTER` |

## Method

**Selection.** Municipalities are the units; the measure of size is `P_18YMAS`.

* `--method systematic` (default): systematic PPS. Units are ordered by CVEGEO
  (which gives implicit geographic stratification), cumulated by size and hit
  by `r + k·I`, `I = X_h / n_h`, `r ~ U(0, I)`. A municipality larger than the
  interval (e.g. Iztapalapa, Tijuana) can be hit more than once; each hit is a
  separate draw. The number of hits is always `⌊n·p_i⌋` or `⌈n·p_i⌉`.
* `--method wr`: PPS with replacement (Hansen–Hurwitz), `n_h` independent
  draws with per-draw probability `p_i = X_i / X_h`.

**Stratification (optional).** `--stratify state` with `--allocation`
`proportional` (default), `equal` or `sqrt`; integers by largest remainder.

**Weights.** Every draw yields `--per-unit m` respondents, each with design
weight `X_h / (n_h · m)`. Weights sum exactly to the adult population of the
(filtered) frame. Unstratified or proportional designs are self-weighting;
`equal`/`sqrt` allocations oversample small states and produce unequal weights.

**Kish effective sample size.** `ESS = (Σw)² / Σw²`, and
`deff_w = n / ESS = 1 + CV²(w)` (Kish, L. 1965, *Survey Sampling*, Wiley).
Example: 320 draws × 5, stratified by state with equal allocation → 1,600
respondents, ESS ≈ 936, deff_w ≈ 1.71.

**Profiles.** For each respondent, from the municipality's own counts:

1. sex × age band jointly, from the 12 census cells (an exact joint
   distribution; people with unspecified age are left out of the denominator);
2. schooling given sex: `P(post_basic | sex) = P18YM_PB_<sex> / P_18YMAS_<sex>`;
   the rest is split into `none` / `primary` / `secondary` using the
   municipality's 15+ proportions of `P15YM_SE : P15PRI_* : P15SEC_*`.

**Reproducibility.** One `numpy.random.Generator(PCG64(seed))` stream is used.
The code consumes only `random()` doubles and does its own inverse-CDF lookups,
so the output does not depend on how NumPy implements `choice`. A golden-hash
test (`tests/test_golden.py`) pins SHA-256 fingerprints of the output CSV for
fixed seeds, on the fixture and on the committed national frame. If a
fingerprint changes, the sampler's behaviour changed. Update the hash only
for an intentional change, and explain it in the commit.

## Usage

```bash
pip install -e ".[test]"        # Python 3.11+, numpy + pandas

mx-census-sampler info                                   # frame by size band
mx-census-sampler sample -n 400 --seed 2027 --out sample.csv
mx-census-sampler sample -n 320 --per-unit 5 --stratify state --allocation equal \
    --summary-json summary.json --out sample.csv
mx-census-sampler sample -n 50 --state 20 --size-band micro,small --method wr
mx-census-sampler prepare        # re-download ITER and rebuild data/ (optional)
```

Size bands (on POBTOT): `micro` <5k, `small` 5k–20k, `medium` 20k–100k,
`large` 100k–500k, `metro` ≥500k.

Real output (`sample -n 400 --seed 2027`):

```
  sample      : 400 respondents in 292 distinct municipalities (55 hit more than once)
  weights     : sum=87,492,680  min=218,731.7  max=218,731.7
  Kish ESS    : 400.0  (deff_w = 1.000)
  sex         : F 51.0% (census 52.0%)  M 49.0% (census 48.0%)
  schooling   : none 4.8% (census 5.2%)  primary 23.8% (census 21.5%)  secondary 26.2% (census 27.6%)  post_basic 45.2% (census 45.7%)
```

```csv
respondent_id,draw_id,person_in_draw,stratum,cvegeo,cve_ent,nom_ent,nom_mun,size_band,p_18ymas,p_draw,expected_hits,sex,age_band,schooling,weight
4,4,1,all,01002,01,Aguascalientes,Asientos,medium,32032,0.0003661106278,0.1464442511,M,25-34,secondary,218731.7
5,5,1,all,01007,01,Aguascalientes,Rincón de Romos,medium,36034,0.0004118515972,0.1647406389,F,18-24,none,218731.7
```

Python:

```python
from mx_census_sampler import load_frame, filter_frame, sample
frame = filter_frame(load_frame(), states=["09", "15"])
res = sample(frame, n=200, seed=7, per_unit=2)
res.respondents.head(); res.ess; print(res.summary_text())
```

Tests (`pytest`) run offline. They use a 12-municipality subset of the real
frame (`tests/fixtures/`) and a synthetic miniature ITER file for `prepare`.

## Limitations

* **Simulation, not a survey.** Profiles are draws from census marginals for
  research design and synthetic-respondent work. No output here measures
  opinion or voting intention.
* **Schooling is independent of age** within sex and municipality, because ITER
  does not cross schooling by age. This understates schooling for young adults
  and overstates it for older ones. The none/primary/secondary split comes from
  15+, not 18+.
* **Census 2020 snapshot.** Population has changed since March 2020. The
  frame is municipal (2,469 units as of the census; municipalities created
  later are not included).
* **Kish ESS covers unequal weighting only.** It does not include the
  clustering effect of putting several respondents in one municipality
  (`--per-unit > 1`), which also inflates variance.
* Systematic PPS has no unbiased variance estimator; treat it as
  with-replacement for variance approximations.

## License

MIT — see `LICENSE`. Census data: INEGI, under its free-use terms.

---

Part of the Hybrid Intelligence open lab — <https://github.com/Neckr0ik>
