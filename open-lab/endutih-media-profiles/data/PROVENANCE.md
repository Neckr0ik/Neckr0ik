# Provenance — ENDUTIH 2025 aggregated tables

| | |
|---|---|
| Source | INEGI, *Encuesta Nacional sobre Disponibilidad y Uso de Tecnologías de la Información en los Hogares* (**ENDUTIH**) **2025**, open-data microdata (CSV) |
| URL | https://www.inegi.org.mx/contenidos/programas/endutih/2025/datosabiertos/conjunto_de_datos_endutih_2025_csv.zip |
| Downloaded | 2026-10-13 (UTC) |
| Zip SHA-256 | `65d219261b3890ee12eaf95cdd1185f6b7d52eefd7e698ffd335b604364fd508` |
| Tables used | `conjunto_de_datos/tr_endutih_usuarios_anual_2025.csv`, `conjunto_de_datos/tr_endutih_usuarios2_anual_2025.csv` (persons, joined 1:1 on UPM, VIV_SEL, HOGAR, NUM_REN); `conjunto_de_datos/tr_endutih_hogares_anual_2025.csv` (households) |
| Weights | `FAC_PER` (persons), `FAC_HOG` (households) |
| Design | strata `EST_DIS`, PSUs `UPM_DIS` (for standard errors) |
| License | INEGI *Términos de libre uso de la información* — https://www.inegi.org.mx/inegi/terminos.html |
| Records | 57,810 selected persons aged 6+ (Σ FAC_PER = 121,906,757); 57,810 households (Σ FAC_HOG = 39,677,498) |
| Suppression | cells with unweighted n < 30 have shares, SEs and weighted totals blanked (`suppression=primary`); further cells are blanked (`suppression=complementary`) so that no blank can be recovered by subtracting published cells from a published total along any dimension; the same is done per indicator for indicator-level blanks |

Required attribution (per INEGI's terms): *Fuente: INEGI. Encuesta Nacional
sobre Disponibilidad y Uso de Tecnologías de la Información en los Hogares
(ENDUTIH) 2025.* These tables are estimates computed by the
endutih-media-profiles authors from the public microdata; they are not
official INEGI figures and may differ slightly from INEGI's published
tabulations. INEGI does not endorse them.

## Files

* `endutih2025_persons.csv` — one row per cell of
  state (32 + `all`) × sex (`male`, `female`, `all`) × age
  (`6-11`, `12-17`, `18-29`, `30-44`, `45-59`, `60+`, `18+`, `all`) ×
  area (`urban`, `rural`, `all`). `18+` overlaps the adult bands.
* `endutih2025_households.csv` — state × area for household indicators.
* `indicators.csv` — every indicator key, the ENDUTIH variable(s), universe
  gates and labels (EN/ES).

Columns: `n` = unweighted respondents in the cell (always shown);
`suppressed` / `suppression` (`none`, `primary`, `complementary`); `pop` = weighted
persons/households; `<indicator>` = weighted share (0–1); `<indicator>_se` =
linearised standard error; `<indicator>_n` (only where answers can be missing)
= respondents with a valid answer. `area` follows ENDUTIH `DOMINIO`
(U = localities of 2,500+ inhabitants, R = smaller).

Rebuild with `endutih-profiles-prepare --edition 2025`.
