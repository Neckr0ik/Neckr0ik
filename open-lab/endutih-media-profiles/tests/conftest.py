from pathlib import Path

import pytest

from endutih_media_profiles.prepare import run

from .synthetic import EDITION, write_zip

REAL_DATA = Path(__file__).resolve().parents[1] / "data"


@pytest.fixture(scope="session")
def synthetic_zip(tmp_path_factory):
    """SYNTHETIC ENDUTIH-shaped zip (random values, not INEGI data)."""
    p = tmp_path_factory.mktemp("raw") / "synthetic_endutih.zip"
    write_zip(p)
    return p


@pytest.fixture(scope="session")
def synthetic_tables(synthetic_zip, tmp_path_factory):
    out = tmp_path_factory.mktemp("tables")
    run(out, out / "raw", edition=EDITION, zip_path=synthetic_zip)
    return out
