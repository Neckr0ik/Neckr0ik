"""Golden-hash regression tests.

These fingerprints are SHA-256 hashes of the canonical respondent CSV for
fixed seeds. If one fails, the sampler's output changed: either a bug, or an
intentional change — in which case update the hash *and explain why in the
commit message*. Regenerate with:

    GOLDEN_PRINT=1 pytest tests/test_golden.py -s
"""

import os

import pytest

from mx_census_sampler import load_frame, sample

from .conftest import REAL

CASES = {
    "systematic_n40": dict(n=40, seed=2027, method="systematic"),
    "wr_n40_m3": dict(n=40, seed=2027, method="wr", per_unit=3),
    "state_equal_n30": dict(n=30, seed=2027, stratify="state", allocation="equal"),
}

GOLDEN_FIXTURE = {
    "systematic_n40": "61996e043ebb825a3240004baa7d8a265018233dce6c6a9f6c4f3d0d53dcbee5",
    "wr_n40_m3": "6f4dd424e4dc4da0046a5679ed938985f79aac96721aa9afc37b3da230596abd",
    "state_equal_n30": "90cf0905ca5c2565e8d8dbb3a5bd18737d9d38cfb5343d8274383143435b7ead",
}

# Full committed national frame (data/municipios_cpv2020.csv). This one also
# changes if the data file is rebuilt with different content.
GOLDEN_REAL = {
    "systematic_n400": ("90a045293ec6e8ce93e0efcdaf446abf4a60bd17c28c13702cad75f1758cde01", dict(n=400, seed=2027)),
}


@pytest.mark.parametrize("name", sorted(CASES))
def test_golden_fixture(frame, name):
    fp = sample(frame, **CASES[name]).fingerprint()
    if os.environ.get("GOLDEN_PRINT"):
        print(f'    "{name}": "{fp}",')
    assert fp == GOLDEN_FIXTURE[name]


@pytest.mark.skipif(not REAL.is_file(), reason="committed national frame not present")
@pytest.mark.parametrize("name", sorted(GOLDEN_REAL))
def test_golden_real_frame(name):
    expected, kw = GOLDEN_REAL[name]
    fp = sample(load_frame(REAL), **kw).fingerprint()
    if os.environ.get("GOLDEN_PRINT"):
        print(f'    "{name}": "{fp}",')
    assert fp == expected
