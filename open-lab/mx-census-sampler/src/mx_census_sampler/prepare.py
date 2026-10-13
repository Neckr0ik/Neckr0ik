"""Download INEGI ITER 2020 and derive the municipal frame.

The ITER file ("Principales resultados por localidad") has one row per
locality plus summary rows. Municipal totals are the rows with ``LOC == "0000"``
and ``MUN != "000"`` (``NOM_LOC == "Total del Municipio"``). We keep only those
2,469 rows and a handful of columns, so no locality-level information is
carried forward.
"""

from __future__ import annotations

import datetime as _dt
import hashlib
import io
import shutil
import sys
import urllib.request
import zipfile
from pathlib import Path

import numpy as np
import pandas as pd

ITER_URL = (
    "https://www.inegi.org.mx/contenidos/programas/ccpv/2020/datosabiertos/"
    "iter/iter_00_cpv2020_csv.zip"
)
ITER_MEMBER = "iter_00_cpv2020/conjunto_de_datos/conjunto_de_datos_iter_00CSV20.csv"
LICENSE_URL = "https://www.inegi.org.mx/inegi/terminos.html"
EXPECTED_MUNICIPALITIES = 2469

# Derived column -> ITER mnemonic(s) summed. All are person counts except
# GRAPROES (average years of schooling, 15+) and the two dwelling counts.
_AGE_PARTS = {
    "18_24": ["P_18A24"],
    "25_34": ["P_25A29", "P_30A34"],
    "35_44": ["P_35A39", "P_40A44"],
    "45_54": ["P_45A49", "P_50A54"],
    "55_64": ["P_55A59", "P_60A64"],
    "65_plus": ["P_65A69", "P_70A74", "P_75A79", "P_80A84", "P_85YMAS"],
}
COLUMN_MAP: dict[str, list[str]] = {
    "pobtot": ["POBTOT"],
    "pobfem": ["POBFEM"],
    "pobmas": ["POBMAS"],
    "p_18ymas": ["P_18YMAS"],
    "p_18ymas_f": ["P_18YMAS_F"],
    "p_18ymas_m": ["P_18YMAS_M"],
    **{f"f_{k}": [f"{c}_F" for c in v] for k, v in _AGE_PARTS.items()},
    **{f"m_{k}": [f"{c}_M" for c in v] for k, v in _AGE_PARTS.items()},
    "p18ym_pb": ["P18YM_PB"],
    "p18ym_pb_f": ["P18YM_PB_F"],
    "p18ym_pb_m": ["P18YM_PB_M"],
    "p_15ymas": ["P_15YMAS"],
    "p15ym_se": ["P15YM_SE"],
    "p15_pri": ["P15PRI_IN", "P15PRI_CO"],
    "p15_sec": ["P15SEC_IN", "P15SEC_CO"],
    "graproes": ["GRAPROES"],
    "tvivparhab": ["TVIVPARHAB"],
    "vph_inter": ["VPH_INTER"],
}
ID_COLUMNS = ["ENTIDAD", "NOM_ENT", "MUN", "NOM_MUN", "LOC", "NOM_LOC"]


def iter_columns() -> list[str]:
    cols = list(ID_COLUMNS)
    for parts in COLUMN_MAP.values():
        cols.extend(p for p in parts if p not in cols)
    return cols


def download(url: str, dest: Path, timeout: int = 300) -> Path:
    dest.parent.mkdir(parents=True, exist_ok=True)
    tmp = dest.with_suffix(dest.suffix + ".part")
    req = urllib.request.Request(url, headers={"User-Agent": "mx-census-sampler/0.1"})
    with urllib.request.urlopen(req, timeout=timeout) as resp, open(tmp, "wb") as fh:
        shutil.copyfileobj(resp, fh)
    if not zipfile.is_zipfile(tmp):
        tmp.unlink(missing_ok=True)
        raise RuntimeError(f"Download from {url} is not a zip file (INEGI page moved?).")
    tmp.replace(dest)
    return dest


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def read_iter(source: Path | io.IOBase, member: str = ITER_MEMBER) -> pd.DataFrame:
    """Read the ITER CSV (from the zip or a plain CSV) as strings."""
    kw = dict(dtype=str, encoding="utf-8-sig", usecols=lambda c: c in set(iter_columns()))
    if isinstance(source, Path) and zipfile.is_zipfile(source):
        with zipfile.ZipFile(source) as zf:
            with zf.open(member) as fh:
                return pd.read_csv(fh, **kw)
    return pd.read_csv(source, **kw)


def _numeric(s: pd.Series, name: str) -> pd.Series:
    out = pd.to_numeric(s.str.strip(), errors="coerce")
    bad = out.isna()
    if bad.any():
        raise ValueError(
            f"Column {name} has {int(bad.sum())} non-numeric municipal values "
            f"(e.g. {s[bad].iloc[0]!r}); refusing to impute."
        )
    return out


def aggregate_municipalities(raw: pd.DataFrame, expected: int | None = EXPECTED_MUNICIPALITIES) -> pd.DataFrame:
    """Keep municipal total rows and map ITER columns to the derived schema."""
    missing = [c for c in iter_columns() if c not in raw.columns]
    if missing:
        raise ValueError(f"ITER input lacks columns: {missing}")
    mun = raw[(raw["LOC"] == "0000") & (raw["MUN"] != "000")].copy()
    if expected is not None and len(mun) != expected:
        raise ValueError(f"Expected {expected} municipal total rows, found {len(mun)}.")
    out = pd.DataFrame(
        {
            "cvegeo": mun["ENTIDAD"] + mun["MUN"],
            "cve_ent": mun["ENTIDAD"],
            "nom_ent": mun["NOM_ENT"],
            "cve_mun": mun["MUN"],
            "nom_mun": mun["NOM_MUN"],
        }
    )
    for new, parts in COLUMN_MAP.items():
        total = sum(_numeric(mun[p], p) for p in parts)
        out[new] = total
    int_cols = [c for c in COLUMN_MAP if c != "graproes"]
    out[int_cols] = out[int_cols].astype(np.int64)
    out = out.sort_values("cvegeo", kind="mergesort").reset_index(drop=True)

    # Consistency checks against the national total row of the same file.
    nat = raw[(raw["ENTIDAD"] == "00") & (raw["MUN"] == "000") & (raw["LOC"] == "0000")]
    if len(nat) == 1:
        for col, iter_col in (("pobtot", "POBTOT"), ("p_18ymas", "P_18YMAS")):
            nat_val = int(nat[iter_col].iloc[0])
            if int(out[col].sum()) != nat_val:
                raise ValueError(f"Sum of municipal {col} != national {iter_col} ({nat_val}).")
    if (out["p_18ymas_f"] + out["p_18ymas_m"] != out["p_18ymas"]).any():
        raise ValueError("P_18YMAS_F + P_18YMAS_M != P_18YMAS for some municipality.")
    return out


PROVENANCE_TEMPLATE = """# Provenance — `municipios_cpv2020.csv`

| | |
|---|---|
| Source | INEGI, *Censo de Población y Vivienda 2020*, **Principales resultados por localidad (ITER)**, national file |
| URL | {url} |
| Downloaded | {date} (UTC) |
| Zip SHA-256 | `{sha}` |
| File read | `{member}` |
| License | INEGI *Términos de libre uso de la información* — {license_url} |
| Rows | {rows} municipalities (ITER rows with `LOC == "0000"` and `MUN != "000"`) |
| Total population (POBTOT) | {pobtot:,} |
| Population 18+ (P_18YMAS) | {p18:,} |

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
{rows_md}

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
"""


def write_provenance(path: Path, *, url: str, zip_path: Path, frame: pd.DataFrame) -> None:
    rows_md = "\n".join(f"| `{k}` | {' + '.join(f'`{p}`' for p in v)} |" for k, v in COLUMN_MAP.items())
    text = PROVENANCE_TEMPLATE.format(
        url=url,
        date=_dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%d"),
        sha=sha256(zip_path),
        member=ITER_MEMBER,
        license_url=LICENSE_URL,
        rows=len(frame),
        pobtot=int(frame["pobtot"].sum()),
        p18=int(frame["p_18ymas"].sum()),
        rows_md=rows_md,
    )
    path.write_text(text, encoding="utf-8")


def run(
    out_csv: Path,
    raw_dir: Path,
    url: str = ITER_URL,
    zip_path: Path | None = None,
    force_download: bool = False,
) -> pd.DataFrame:
    """Full pipeline: download (if needed) → aggregate → write CSV + provenance."""
    if zip_path is None:
        zip_path = raw_dir / Path(url).name
        if force_download or not zip_path.is_file():
            print(f"Downloading {url} …", file=sys.stderr)
            try:
                download(url, zip_path)
            except Exception as exc:  # noqa: BLE001 — report and stop, never fabricate
                raise SystemExit(
                    f"ERROR: could not download ITER from {url}: {exc}\n"
                    "No data was written. Download the zip manually and pass --zip."
                ) from exc
    raw = read_iter(zip_path)
    frame = aggregate_municipalities(raw)
    out_csv.parent.mkdir(parents=True, exist_ok=True)
    frame.to_csv(out_csv, index=False, encoding="utf-8", lineterminator="\n")
    write_provenance(out_csv.parent / "PROVENANCE.md", url=url, zip_path=zip_path, frame=frame)
    return frame
