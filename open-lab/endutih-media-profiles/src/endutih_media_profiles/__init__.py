"""endutih-media-profiles — media & technology use profiles for Mexico from
INEGI ENDUTIH public microdata (weighted, with design-based SEs).

    from endutih_media_profiles import profile
    profile(state="09", age="18-29")
"""

from .indicators import ALL_INDICATORS, HOUSEHOLD_INDICATORS, PERSON_INDICATORS
from .query import load_table, profile

__version__ = "0.1.0"
__all__ = ["ALL_INDICATORS", "HOUSEHOLD_INDICATORS", "PERSON_INDICATORS", "load_table", "profile"]
