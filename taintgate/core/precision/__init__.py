"""Tier 2 Precision Features for TaintGate."""

from taintgate.core.precision.field_sensitive import FieldSensitiveLabeler
from taintgate.core.precision.extractors import (
    QuarantinedExtractor,
    RegexExtractor,
    AllowlistExtractor,
    NumericExtractor,
    ExtractorRegistry,
    ExtractionError,
)
from taintgate.core.precision.provenance_tracker import ExactProvenanceResolver
from taintgate.core.precision.subagents import CleanContextSubAgent, CleanContextCoordinator

__all__ = [
    "FieldSensitiveLabeler",
    "QuarantinedExtractor",
    "RegexExtractor",
    "AllowlistExtractor",
    "NumericExtractor",
    "ExtractorRegistry",
    "ExtractionError",
    "ExactProvenanceResolver",
    "CleanContextSubAgent",
    "CleanContextCoordinator",
]
