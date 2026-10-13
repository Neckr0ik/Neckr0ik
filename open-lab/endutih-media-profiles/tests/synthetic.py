"""SYNTHETIC ENDUTIH-shaped microdata for offline tests.

!!! Every value here is randomly generated. It is NOT INEGI data and must
never be used for analysis. It only mimics the file layout (table names,
column names, codes, skip patterns) of the ENDUTIH 2025 open-data zip.
"""

from __future__ import annotations

import io
import zipfile

import numpy as np
import pandas as pd

EDITION = 2025
SOCIAL = ["P7_16_1", "P7_16_2", "P7_16_3", "P7_16_6", "P7_16_7", "P7_16_10"]
ONLINE = ["P7_6_4", "P7_6_5", "P7_13_1", "P7_13_2", "P7_13_3", "P7_13_4", "P7_13_6", "P7_13_7", "P7_21"]


def _yn(rng, n, p):
    return np.where(rng.random(n) < p, "1", "2")


def make_frames(seed: int = 7, n: int = 480):
    rng = np.random.default_rng(seed)
    state = np.where(np.arange(n) < n // 2, "01", "09")
    est = np.array([f"{s}{(i // 60) % 2}" for i, s in enumerate(state)])  # 4 strata
    upm = np.array([f"{i // 30:05d}" for i in range(n)])  # 16 PSUs of 30
    keys = pd.DataFrame({
        "UPM": [f"S{i:06d}" for i in range(n)], "VIV_SEL": "01", "HOGAR": "01", "NUM_REN": "01",
    })
    design = pd.DataFrame({
        "UPM_DIS": upm, "EST_DIS": est,
        "DOMINIO": np.where(rng.random(n) < 0.75, "U", "R"),
        "CVE_ENT": state, "ESTATUS": "SYNTHETIC",
    })
    edad = rng.integers(6, 90, n).astype(str)
    sexo = np.where(rng.random(n) < 0.5, "1", "2")
    fac = rng.integers(100, 900, n).astype(str)
    internet = _yn(rng, n, 0.8)
    u = pd.concat([keys, pd.DataFrame({"EDAD": edad, "P6_1": _yn(rng, n, 0.4), "P7_1": internet})], axis=1)
    social = np.where(internet == "1", _yn(rng, n, 0.85), "")
    u["P7_15"] = social
    for c in ONLINE:
        u[c] = np.where(internet == "1", _yn(rng, n, 0.5), "")
    for c in SOCIAL:
        u[c] = np.where(social == "1", _yn(rng, n, 0.6), "")
    u["P7_13_6"] = np.where((internet == "1") & (rng.random(n) < 0.05), "9", u["P7_13_6"])  # some 'no sabe'
    u = pd.concat([u, pd.DataFrame({"FAC_PER": fac, "SEXO": sexo}), design], axis=1)
    u2 = pd.concat([keys, pd.DataFrame({
        "EDAD": edad, "P8_1": _yn(rng, n, 0.85), "P8_3": _yn(rng, n, 0.9),
        "P10_1": _yn(rng, n, 0.3), "P10_7": _yn(rng, n, 0.5), "FAC_PER": fac, "SEXO": sexo,
    }), design], axis=1)
    flat = _yn(rng, n, 0.85)
    smart = np.where(flat == "1", rng.choice(["0", "1", "2", "99"], n), "")
    h = pd.concat([keys.drop(columns="NUM_REN"), pd.DataFrame({
        "P4_1_1": _yn(rng, n, 0.35), "P4_1_4": flat, "P4_1_4_2": smart,
        "P4_2_1": _yn(rng, n, 0.1), "P4_2_2": _yn(rng, n, 0.3), "P4_2_3": _yn(rng, n, 0.2),
        "P4_4": _yn(rng, n, 0.78), "P5_1": _yn(rng, n, 0.3), "P5_5": _yn(rng, n, 0.3),
        "P5_6": _yn(rng, n, 0.35), "FAC_HOG": rng.integers(50, 300, n).astype(str),
    }), design], axis=1)
    return u, u2, h


def write_zip(path, seed: int = 7) -> None:
    u, u2, h = make_frames(seed)
    with zipfile.ZipFile(path, "w") as zf:
        for name, df in (("usuarios", u), ("usuarios2", u2), ("hogares", h)):
            zf.writestr(f"conjunto_de_datos/tr_endutih_{name}_anual_{EDITION}.csv", df.to_csv(index=False))
        zf.writestr("SYNTHETIC_README.txt", "Randomly generated test data. NOT INEGI data.\n")
