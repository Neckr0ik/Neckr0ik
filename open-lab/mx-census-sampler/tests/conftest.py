from pathlib import Path

import pytest

from mx_census_sampler import load_frame

FIXTURE = Path(__file__).parent / "fixtures" / "municipios_fixture.csv"
REAL = Path(__file__).resolve().parents[1] / "data" / "municipios_cpv2020.csv"


@pytest.fixture(scope="session")
def frame():
    """12 real municipalities copied from data/municipios_cpv2020.csv (3 states)."""
    return load_frame(FIXTURE)
