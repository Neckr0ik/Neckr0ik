"""llm-survey-bias-kit: diagnostics for LLM-simulated survey and message-test answers."""

from .homogeneity import (
    DEFAULT_MIN_UNITS,
    CategoricalDispersion,
    NumericDispersion,
    SubgroupCell,
    categorical_dispersion,
    numeric_dispersion,
    subgroup_sizes,
)
from .kish import KishResult, kish_by_group, kish_effective_n
from .order import (
    FORWARD,
    REVERSED,
    OrderEffect,
    OrderPlan,
    assign_directions,
    build_option_orders,
    estimate_order_effect,
)
from .paired import (
    DISTINGUISHABLE,
    INDISTINGUISHABLE,
    NOT_EVALUABLE,
    AAResult,
    PairedResult,
    aa_split_replicates,
    aa_test,
    matrices_from_records,
    minimum_detectable_effect,
    paired_ab,
    paired_ab_from_records,
    required_units,
)

__version__ = "0.1.0"

__all__ = [
    "AAResult",
    "CategoricalDispersion",
    "DEFAULT_MIN_UNITS",
    "DISTINGUISHABLE",
    "FORWARD",
    "INDISTINGUISHABLE",
    "KishResult",
    "NOT_EVALUABLE",
    "NumericDispersion",
    "OrderEffect",
    "OrderPlan",
    "PairedResult",
    "REVERSED",
    "SubgroupCell",
    "aa_split_replicates",
    "aa_test",
    "assign_directions",
    "build_option_orders",
    "categorical_dispersion",
    "estimate_order_effect",
    "kish_by_group",
    "kish_effective_n",
    "matrices_from_records",
    "minimum_detectable_effect",
    "numeric_dispersion",
    "paired_ab",
    "paired_ab_from_records",
    "required_units",
    "subgroup_sizes",
]
