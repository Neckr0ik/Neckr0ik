# endutih-media-profiles

> **Resumen.** Perfiles de uso de medios y tecnología en México (internet, celular, computadora, redes sociales, streaming, radio y TV abierta) por entidad, sexo, edad y ámbito urbano/rural. Se calculan con los microdatos públicos de la ENDUTIH 2025 del INEGI y sus factores de expansión. Cada celda trae su *n* sin ponderar y error estándar de diseño; las celdas con n < 30 se suprimen.

`endutih-media-profiles` turns INEGI's public **ENDUTIH 2025** microdata into
small, queryable tables of weighted media and technology use shares, with
**unweighted n per cell** and **design-based standard errors**. A library and
CLI return the profile for any state × sex × age band × urban/rural cell.

It is a public building block of the Hybrid Intelligence approach: giving
LLM "silicon samples" realistic media diets anchored in official survey data,
using only public INEGI data. It is one of the open foundations behind
Impulse Labs products (ZÓKALO · MOSAIK · KALEIDO); it contains no product code
and no partner data.

## Data provenance

* **Source:** INEGI, *Encuesta Nacional sobre Disponibilidad y Uso de
  Tecnologías de la Información en los Hogares (ENDUTIH) 2025*, open-data
  CSV microdata, published 16 June 2026:
  `https://www.inegi.org.mx/contenidos/programas/endutih/2025/datosabiertos/conjunto_de_datos_endutih_2025_csv.zip`
* **Tables used:** `tr_endutih_usuarios_anual_2025` + `tr_endutih_usuarios2_anual_2025`
  (the selected person aged 6+ in each household, joined 1:1; 57,810 records,
  weight `FAC_PER`, Σ = 121.9 M) and `tr_endutih_hogares_anual_2025`
  (57,810 households, weight `FAC_HOG`, Σ = 39.7 M). Design variables:
  `EST_DIS` (strata, 425) and `UPM_DIS` (PSUs, 8,607).
* **What is committed** (`data/`, ~780 KB total):
  * `endutih2025_persons.csv`: 2,371 non-empty cells of state (32 + all) ×
    sex × age (`6-11`, `12-17`, `18-29`, `30-44`, `45-59`, `60+`, `18+`, all) ×
    area (urban, rural, all). 22 indicators, each with share and SE.
  * `endutih2025_households.csv`: 99 cells of state × area, 8 household
    indicators.
  * `indicators.csv`: each key → ENDUTIH variable(s), universe gates, EN/ES
    labels.
  * `PROVENANCE.md`: URL, download date, SHA-256 of the zip, file layout.
* **Not committed:** the raw microdata (`raw/`, `*.zip` are gitignored).
* **License:** INEGI *Términos de libre uso de la información*
  (<https://www.inegi.org.mx/inegi/terminos.html>). Attribution:
  *Fuente: INEGI. ENDUTIH 2025.* These are our own estimates from the public
  microdata. They are not official INEGI tabulations, and INEGI does not
  endorse them.

**Validation.** Computed independently from the microdata, the tables match
INEGI's published 2025 headline results (results report, 16 June 2026):
internet users 86.1% of people 6+ (104.9 M), 88.9% urban, 75.2% rural. A test
(`tests/test_committed_data.py`) checks this against the committed tables.

## Indicators

Persons (share of **all people 6+ in the cell**): `internet_user`,
`computer_user`, `cellphone_user`, `owns_cellphone`,
`internet_via_smartphone`, `internet_via_smart_tv`, `social_media_user`,
`facebook`, `whatsapp`, `youtube`, `instagram`, `tiktok`, `x_twitter`,
`paid_video_streaming`, `free_online_video`, `free_music_streaming`,
`online_radio`, `online_tv`, `online_reading`, `online_shopping_12m`,
`radio_last_week`, `open_tv_last_week`.

Households: `hh_internet`, `hh_computer`, `hh_radio`, `hh_flat_tv`,
`hh_smart_tv`, `hh_pay_tv`, `hh_streaming_service`, `hh_fixed_phone`.

Run `endutih-profiles --list` for labels, and see `data/indicators.csv` for
the exact variables. Recall periods follow the questionnaire: internet, device
and online-activity items cover the last 3 months, online shopping the last
12 months, and radio and open TV the previous week.

## Method

* **Coding.** `1` → 1 and `2` → 0. Items asked only of a sub-population are
  set to 0 for people outside it, so every person share has the same
  denominator. Examples: the online items (only internet users) and the
  social networks (only social-media users). Other blanks or codes such as
  `9` (*no sabe*) count as missing, and those people are left out of that
  indicator's denominator. Where that happens, an `<indicator>_n` column gives
  the valid count.
* **Estimates.** Weighted ratio `Σ w·y / Σ w` with the ENDUTIH expansion
  factors.
* **Standard errors.** Taylor linearisation, ultimate-cluster variance with
  PSUs (`UPM_DIS`) nested in strata (`EST_DIS`), first stage treated as with
  replacement. This is the same approach as R
  `survey::svydesign(ids=~UPM_DIS, strata=~EST_DIS, weights=~FAC_PER)`. The
  tests check the vectorised estimator against a loop-based reference. 95%
  CIs are Wald intervals clipped to [0, 1].
* **Suppression.** If a cell has **fewer than 30 unweighted respondents**,
  its shares, SEs and weighted total are blanked and `suppressed=True`. Its
  `n` is still shown. The same rule applies per indicator to the valid-answer
  count. This removes 280 of 2,371 person cells. n ≥ 30 is a floor, not a
  quality guarantee: check the SE.

## Usage

```bash
pip install -e ".[test]"         # Python 3.11+, numpy + pandas

endutih-profiles --state 09 --age 18-29
endutih-profiles --sex female --age 60+ --area rural --indicators internet_user,radio_last_week,open_tv_last_week
endutih-profiles --households --state 20 --format json
endutih-profiles-prepare          # re-download ENDUTIH 2025 and rebuild data/ (optional)
```

Real output (`endutih-profiles --state 09 --age 18-29`, excerpt):

```
ENDUTIH 2025 · persons · state=09 (Ciudad de México) · sex=all · age=18-29 · area=all
unweighted n = 259 · weighted = 1,498,056

indicator                 share          95% CI      n national
---------------------------------------------------------------
computer_user             72.4%     66.2– 78.5%    259    56.6%
instagram                 72.2%     65.6– 78.8%    259    61.5%
tiktok                    62.6%     55.7– 69.5%    259    49.1%
paid_video_streaming      79.9%     74.8– 85.1%    259    61.5%
radio_last_week           19.7%     13.8– 25.5%    259    23.2%
open_tv_last_week         53.0%     46.1– 60.0%    259    39.5%
```

Python:

```python
from endutih_media_profiles import profile, load_table
profile(state="09", age="18-29")          # DataFrame: indicator, share, se, ci95_*, n, national_share
cube = load_table("persons")              # the full aggregated table
```

Tests (`pytest`) run offline. They build a **synthetic** ENDUTIH-shaped zip
(`tests/synthetic.py`) with random values. It is not INEGI data and only
mimics the file layout and skip patterns.

## Limitations

* **Survey estimates, not a census.** State-level cells, and especially
  state × sex × age × area cells, rest on small samples, so read the SE and
  `n`. Breakdowns finer than state × area go beyond what ENDUTIH is designed
  to publish.
* **Selected-person universe.** Person indicators describe the one person
  aged 6+ selected per household, as ENDUTIH does. They cover use (any
  device), not frequency or intensity, except the recall periods noted above.
* **Social networks** are those the respondent named under question 7.16.
  WhatsApp and YouTube count only when mentioned *as social networks*, so the
  shares are lower than "uses the app" would be.
* **Edition.** Only the 2025 layout was verified. `--edition 2024` should
  download the 2024 file, but it fails loudly if column names differ. Never
  compare editions without checking question wording.
* **Media use is not opinion.** These shares describe exposure and
  technology access. They do not measure audiences of specific outlets or any
  attitude.

## License

MIT — see `LICENSE`. ENDUTIH data: INEGI, under its free-use terms.

---

Part of the Hybrid Intelligence open lab — <https://github.com/Neckr0ik>
