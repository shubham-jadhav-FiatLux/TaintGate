"""Agent evaluation harness and comparative defense baselines."""

from eval.baselines import (
    BaseDefense,
    NoDefense,
    StaticToolFilter,
    NaiveHITL,
    DualLLMInspector,
    TaintGateDefense,
)
from eval.runner import run_benchmark, evaluate_defense

__all__ = [
    "BaseDefense",
    "NoDefense",
    "StaticToolFilter",
    "NaiveHITL",
    "DualLLMInspector",
    "TaintGateDefense",
    "run_benchmark",
    "evaluate_defense",
]
