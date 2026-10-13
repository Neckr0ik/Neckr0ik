"""Download ENDUTIH open microdata and build the aggregated profile tables.

Only aggregated tables are written. Raw microdata stays in ``raw/``
(gitignored).
"""

from __future__ import annotations

import datetime as _dt
import hashlib
import shutil
import sys
import urllib.request
import zipfile
from pathlib import Path

import numpy as np
import pandas as pd

from .estimate import ALL, MIN_N_DEFAULT, Design, estimate_cells
from .indicators import HOUSEHOLD_INDICATORS, PERSON_INDICATORS, Indicator
from .states import STATE_NAMES

DEFAULT_EDITION = 2025
URL_TEMPLATE = (
    "https://www.inegi.org.mx/contenidos/programas/endutih/{edition}/datosabiertos/"
    "conjunto_de_datos_endutih_{edition}_csv.zip"
)
LICENSE_URL = "https://www.inegi.org.mx/inegi/terminos.html"
KEYS = ["UPM", "VIV_SEL", "HOGAR", "NUM_REN"]

AGE_BANDS = {
    "6-11": (6, 11),
    "12-17": (12, 17),
    "18-29": (18, 29),
    "30-44": (30, 44),
    "45-59": (45, 59),
    "60+": (60, 200),
    "18+": (18, 200),  # overlapping convenience band for adult-only work
}
SEXES = {"male": "1", "female": "2"}
AREAS = {"urban": "U", "rural": "R"}


def member(edition: int, table: str) -> str:
    return f"conjunto_de_datos/tr_endutih_{table}_anual_{edition}.csv"


def download(url: str, dest: Path, timeout: int = 300) -> Path:
    dest.parent.mkdir(parents=True, exist_ok=True)
    tmp = dest.with_suffix(dest.suffix + ".part")
    req = urllib.request.Request(url, headers={"User-Agent": "endutih-media-profiles/0.1"})
    with urllib.request.urlopen(req, timeout=timeout) as resp, open(tmp, "wb") as fh:
        shutil.copyfileobj(resp, fh)
    if not zipfile.is_zipfile(tmp):
        tmp.unlink(missing_ok=True)
        raise RuntimeError(f"Download from {url} is not a zip file (edition not published?).")
    tmp.replace(dest)
    return dest


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def read_table(zf: zipfile.ZipFile, name: str) -> pd.DataFrame:
    with zf.open(name) as fh:
        return pd.read_csv(fh, dtype=str, encoding="utf-8-sig", keep_default_na=False)


def load_persons(zip_path: Path, edition: int) -> pd.DataFrame:
    """Selected-respondent records: ``usuarios`` (modules 6–7) joined 1:1 with
    ``usuarios2`` (modules 8–11, carries FAC_PER and demographics)."""
    with zipfile.ZipFile(zip_path) as zf:
        u = read_table(zf, member(edition, "usuarios"))
        u2 = read_table(zf, member(edition, "usuarios2"))
    shared = [c for c in u.columns if c in u2.columns and c not in KEYS]
    p = u.drop(columns=shared).merge(u2, on=KEYS, how="inner", validate="1:1")
    if len(p) != len(u) or len(p) != len(u2):
        raise ValueError("usuarios and usuarios2 do not match one-to-one.")
    return p


def load_households(zip_path: Path, edition: int) -> pd.DataFrame:
    with zipfile.ZipFile(zip_path) as zf:
        h = read_table(zf, member(edition, "hogares"))
    flat, smart = h["P4_1_4"], pd.to_numeric(h["P4_1_4_2"].replace("", np.nan), errors="coerce")
    derived = np.where(flat == "2", "2", np.where((smart >= 1) & (smart < 99), "1", np.where(smart == 0, "2", "")))
    h["SMART_TV"] = derived
    return h


def code_indicator(df: pd.DataFrame, ind: Indicator) -> np.ndarray:
    """1 / 0 / NaN array following the gate rules in :mod:`indicators`."""
    missing = [v for v in (*ind.variables, *(g for g, _ in ind.gates)) if v not in df.columns]
    if missing:
        raise ValueError(f"Indicator {ind.key}: columns {missing} not in microdata.")
    vals = [df[v].str.strip() for v in ind.variables]
    yes = np.zeros(len(df), dtype=bool)
    no = np.ones(len(df), dtype=bool)
    for v in vals:
        yes |= (v == "1").to_numpy()
        no &= (v == "2").to_numpy()
    y = np.full(len(df), np.nan)
    y[no] = 0.0
    y[yes] = 1.0
    out_of_universe = np.zeros(len(df), dtype=bool)
    for var, code in ind.gates:
        g = df[var].str.strip()
        out_of_universe |= ((g != code) & (g != "")).to_numpy()
    y[out_of_universe] = 0.0
    return y


def _levels(series: pd.Series, mapping: dict[str, str]) -> dict[str, np.ndarray]:
    lv = {ALL: np.ones(len(series), dtype=bool)}
    for label, code in mapping.items():
        lv[label] = (series == code).to_numpy()
    return lv


def state_levels(cve_ent: pd.Series) -> dict[str, np.ndarray]:
    return _levels(cve_ent.str.zfill(2), {c: c for c in sorted(STATE_NAMES)})


def age_levels(edad: pd.Series) -> dict[str, np.ndarray]:
    a = pd.to_numeric(edad, errors="coerce")
    lv = {ALL: np.ones(len(a), dtype=bool)}
    for label, (lo, hi) in AGE_BANDS.items():
        lv[label] = ((a >= lo) & (a <= hi)).to_numpy()
    return lv


def build_person_table(p: pd.DataFrame, edition: int, min_n: int = MIN_N_DEFAULT) -> pd.DataFrame:
    design = Design(p["EST_DIS"], p["UPM_DIS"], pd.to_numeric(p["FAC_PER"]))
    dims = {
        "state": state_levels(p["CVE_ENT"]),
        "sex": _levels(p["SEXO"].str.strip(), SEXES),
        "age": age_levels(p["EDAD"]),
        "area": _levels(p["DOMINIO"].str.strip(), AREAS),
    }
    inds = {i.key: code_indicator(p, i) for i in PERSON_INDICATORS}
    out = estimate_cells(p, design, dims, inds, min_n=min_n)
    return _finish(out, edition)


def build_household_table(h: pd.DataFrame, edition: int, min_n: int = MIN_N_DEFAULT) -> pd.DataFrame:
    design = Design(h["EST_DIS"], h["UPM_DIS"], pd.to_numeric(h["FAC_HOG"]))
    dims = {"state": state_levels(h["CVE_ENT"]), "area": _levels(h["DOMINIO"].str.strip(), AREAS)}
    inds = {i.key: code_indicator(h, i) for i in HOUSEHOLD_INDICATORS}
    out = estimate_cells(h, design, dims, inds, min_n=min_n)
    return _finish(out, edition)


def _finish(out: pd.DataFrame, edition: int) -> pd.DataFrame:
    out.insert(0, "edition", edition)
    out.insert(2, "state_name", out["state"].map(lambda s: "Estados Unidos Mexicanos" if s == ALL else STATE_NAMES[s]))
    return out


def indicator_dictionary() -> pd.DataFrame:
    rows = []
    for i in (*PERSON_INDICATORS, *HOUSEHOLD_INDICATORS):
        rows.append(
            {
                "key": i.key,
                "table": i.table,
                "endutih_variables": " OR ".join(i.variables),
                "universe_gates": " & ".join(f"{v}=={c}" for v, c in i.gates) or "(all)",
                "label_en": i.label_en,
                "label_es": i.label_es,
                "note": i.note,
            }
        )
    return pd.DataFrame(rows)


PROVENANCE = """# Provenance — ENDUTIH {edition} aggregated tables

| | |
|---|---|
| Source | INEGI, *Encuesta Nacional sobre Disponibilidad y Uso de Tecnologías de la Información en los Hogares* (**ENDUTIH**) **{edition}**, open-data microdata (CSV) |
| URL | {url} |
| Downloaded | {date} (UTC) |
| Zip SHA-256 | `{sha}` |
| Tables used | `{m_u}`, `{m_u2}` (persons, joined 1:1 on UPM, VIV_SEL, HOGAR, NUM_REN); `{m_h}` (households) |
| Weights | `FAC_PER` (persons), `FAC_HOG` (households) |
| Design | strata `EST_DIS`, PSUs `UPM_DIS` (for standard errors) |
| License | INEGI *Términos de libre uso de la información* — {license_url} |
| Records | {n_p:,} selected persons aged 6+ (Σ FAC_PER = {pop_p:,}); {n_h:,} households (Σ FAC_HOG = {pop_h:,}) |
| Suppression | cells with unweighted n < {min_n} have shares, SEs and weighted totals blanked |

Required attribution (per INEGI's terms): *Fuente: INEGI. Encuesta Nacional
sobre Disponibilidad y Uso de Tecnologías de la Información en los Hogares
(ENDUTIH) {edition}.* These tables are estimates computed by the
endutih-media-profiles authors from the public microdata; they are not
official INEGI figures and may differ slightly from INEGI's published
tabulations. INEGI does not endorse them.

## Files

* `endutih{edition}_persons.csv` — one row per cell of
  state (32 + `all`) × sex (`male`, `female`, `all`) × age
  (`6-11`, `12-17`, `18-29`, `30-44`, `45-59`, `60+`, `18+`, `all`) ×
  area (`urban`, `rural`, `all`). `18+` overlaps the adult bands.
* `endutih{edition}_households.csv` — state × area for household indicators.
* `indicators.csv` — every indicator key, the ENDUTIH variable(s), universe
  gates and labels (EN/ES).

Columns: `n` = unweighted respondents in the cell; `pop` = weighted
persons/households; `<indicator>` = weighted share (0–1); `<indicator>_se` =
linearised standard error; `<indicator>_n` (only where answers can be missing)
= respondents with a valid answer. `area` follows ENDUTIH `DOMINIO`
(U = localities of 2,500+ inhabitants, R = smaller).

Rebuild with `endutih-profiles-prepare --edition {edition}`.
"""


def write_provenance(path: Path, *, edition, url, zip_path, persons, households, min_n) -> None:
    text = PROVENANCE.format(
        edition=edition,
        url=url,
        date=_dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%d"),
        sha=sha256(zip_path),
        m_u=member(edition, "usuarios"),
        m_u2=member(edition, "usuarios2"),
        m_h=member(edition, "hogares"),
        license_url=LICENSE_URL,
        n_p=len(persons),
        pop_p=round(pd.to_numeric(persons["FAC_PER"]).sum()),
        n_h=len(households),
        pop_h=round(pd.to_numeric(households["FAC_HOG"]).sum()),
        min_n=min_n,
    )
    path.write_text(text, encoding="utf-8")


def run(
    out_dir: Path,
    raw_dir: Path,
    edition: int = DEFAULT_EDITION,
    url: str | None = None,
    zip_path: Path | None = None,
    min_n: int = MIN_N_DEFAULT,
    force_download: bool = False,
) -> dict[str, Path]:
    url = url or URL_TEMPLATE.format(edition=edition)
    if zip_path is None:
        zip_path = raw_dir / Path(url).name
        if force_download or not zip_path.is_file():
            print(f"Downloading {url} …", file=sys.stderr)
            try:
                download(url, zip_path)
            except Exception as exc:  # noqa: BLE001 — report and stop, never fabricate
                raise SystemExit(
                    f"ERROR: could not download ENDUTIH {edition} from {url}: {exc}\n"
                    "No tables were written. Find the CSV zip at "
                    "https://www.inegi.org.mx/programas/endutih/ and pass --zip."
                ) from exc
    persons = load_persons(zip_path, edition)
    households = load_households(zip_path, edition)
    out_dir.mkdir(parents=True, exist_ok=True)
    paths = {
        "persons": out_dir / f"endutih{edition}_persons.csv",
        "households": out_dir / f"endutih{edition}_households.csv",
        "indicators": out_dir / "indicators.csv",
    }
    kw = dict(index=False, lineterminator="\n", encoding="utf-8")
    build_person_table(persons, edition, min_n).to_csv(paths["persons"], **kw)
    build_household_table(households, edition, min_n).to_csv(paths["households"], **kw)
    indicator_dictionary().to_csv(paths["indicators"], **kw)
    write_provenance(
        out_dir / "PROVENANCE.md", edition=edition, url=url, zip_path=zip_path,
        persons=persons, households=households, min_n=min_n,
    )
    return paths
