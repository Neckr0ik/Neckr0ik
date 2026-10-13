"""silicon-sample-validation: an open harness for validating LLM silicon samples
against official surveys (pre-registered forecasts, post-cutoff targets,
baselines, memorization probe, failure analysis)."""

from .baselines import (
    build_baselines,
    demographic_regression,
    demographic_regression_loo,
    last_published,
    national_mean,
)
from .compare import ComparisonReport, PairwiseComparison, compare_to_baselines, compare_two
from .cutoff import CutoffResult, filter_post_cutoff
from .failure import GroupError, error_breakdown, format_breakdown, worst_units
from .metrics import bias, coverage, interval_score, mae, pearson, rmse, score, spearman
from .probe import (
    MockLLM,
    ProbeResult,
    ProbeSummary,
    ProbeTarget,
    build_probe_prompt,
    parse_numeric_answer,
    run_memorization_probe,
)
from .registry import GENESIS_HASH, ForecastRegistry, RegistryError, VerificationReport
from .synthetic import SYNTHETIC_LABEL, make_synthetic_dataset

__version__ = "0.1.0"

__all__ = [
    "ComparisonReport", "CutoffResult", "ForecastRegistry", "GENESIS_HASH", "GroupError",
    "MockLLM", "PairwiseComparison", "ProbeResult", "ProbeSummary", "ProbeTarget",
    "RegistryError", "SYNTHETIC_LABEL", "VerificationReport", "bias", "build_baselines",
    "build_probe_prompt", "compare_to_baselines", "compare_two", "coverage",
    "demographic_regression", "demographic_regression_loo", "error_breakdown",
    "filter_post_cutoff", "format_breakdown", "interval_score", "last_published", "mae",
    "make_synthetic_dataset", "national_mean", "parse_numeric_answer", "pearson", "rmse",
    "run_memorization_probe", "score", "spearman", "worst_units",
]
