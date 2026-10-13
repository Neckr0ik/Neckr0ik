# Provenance — `municipios_cpv2020.csv`

| | |
|---|---|
| Source | INEGI, *Censo de Población y Vivienda 2020*, **Principales resultados por localidad (ITER)**, national file |
| URL | https://www.inegi.org.mx/contenidos/programas/ccpv/2020/datosabiertos/iter/iter_00_cpv2020_csv.zip |
| Downloaded | 2026-10-13 (UTC) |
| Zip SHA-256 | `9342fdbd45bda5897f2b827a12904843b6f8fb85d4e72da299e09e4d2422ab60` |
| File read | `iter_00_cpv2020/conjunto_de_datos/conjunto_de_datos_iter_00CSV20.csv` |
| License | INEGI *Términos de libre uso de la información* — https://www.inegi.org.mx/inegi/terminos.html |
| Rows | 2469 municipalities (ITER rows with `LOC == "0000"` and `MUN != "000"`) |
| Total population (POBTOT) | 126,014,024 |
| Population 18+ (P_18YMAS) | 87,492,680 |

Required attribution (per INEGI's terms): *Fuente: INEGI. Censo de Población y
Vivienda 2020. Principales resultados por localidad (ITER).* This derived table
is an aggregation/selection made by the mx-census-sampler authors; INEGI does
not endorse it.

## Columns

| Derived column | ITER mnemonic(s) (summed) |
|---|---|
| `cvegeo` | `ENTIDAD` + `MUN` (5-digit INEGI geostatistical key) |
| `cve_ent`, `nom_ent` | `ENTIDAD`, `NOM_ENT` |
| `cve_mun`, `nom_mun` | `MUN`, `NOM_MUN` |
| `pobtot` | `POBTOT` |
| `pobfem` | `POBFEM` |
| `pobmas` | `POBMAS` |
| `p_18ymas` | `P_18YMAS` |
| `p_18ymas_f` | `P_18YMAS_F` |
| `p_18ymas_m` | `P_18YMAS_M` |
| `f_18_24` | `P_18A24_F` |
| `f_25_34` | `P_25A29_F` + `P_30A34_F` |
| `f_35_44` | `P_35A39_F` + `P_40A44_F` |
| `f_45_54` | `P_45A49_F` + `P_50A54_F` |
| `f_55_64` | `P_55A59_F` + `P_60A64_F` |
| `f_65_plus` | `P_65A69_F` + `P_70A74_F` + `P_75A79_F` + `P_80A84_F` + `P_85YMAS_F` |
| `m_18_24` | `P_18A24_M` |
| `m_25_34` | `P_25A29_M` + `P_30A34_M` |
| `m_35_44` | `P_35A39_M` + `P_40A44_M` |
| `m_45_54` | `P_45A49_M` + `P_50A54_M` |
| `m_55_64` | `P_55A59_M` + `P_60A64_M` |
| `m_65_plus` | `P_65A69_M` + `P_70A74_M` + `P_75A79_M` + `P_80A84_M` + `P_85YMAS_M` |
| `p18ym_pb` | `P18YM_PB` |
| `p18ym_pb_f` | `P18YM_PB_F` |
| `p18ym_pb_m` | `P18YM_PB_M` |
| `p_15ymas` | `P_15YMAS` |
| `p15ym_se` | `P15YM_SE` |
| `p15_pri` | `P15PRI_IN` + `P15PRI_CO` |
| `p15_sec` | `P15SEC_IN` + `P15SEC_CO` |
| `graproes` | `GRAPROES` |
| `tvivparhab` | `TVIVPARHAB` |
| `vph_inter` | `VPH_INTER` |

Notes

* `f_*` / `m_*` are women / men by age band built from the quinquennial
  ITER groups (`P_25A29_F` + `P_30A34_F`, …). People with unspecified age
  are in `p_18ymas` but in no age band, so the 12 bands sum to slightly less
  than `p_18ymas`.
* `p18ym_pb*` = population 18+ with *educación posbásica* (any grade of
  upper-secondary/bachillerato, technical studies with secondary, *normal*,
  or higher education).
* `p15ym_se`, `p15_pri`, `p15_sec` are for the population **15+** (ITER does
  not publish these levels for 18+): no schooling, primary (incomplete +
  complete), secondary (incomplete + complete).
* `graproes` = average years of schooling, population 15+.
* `tvivparhab` / `vph_inter` = inhabited private dwellings / those with
  Internet (context only; not used by the sampler).
* Rebuild with `mx-census-sampler prepare`; the build re-checks that the
  municipal rows add up to the national total row of the same file.
