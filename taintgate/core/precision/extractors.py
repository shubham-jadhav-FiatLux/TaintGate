"""Tier 2 Precision: Typed Quarantined Extractors.

Provides isolated, schema-validated extractors that can safely endorse
untrusted data without allowing arbitrary prompt injection payloads to pass through.
"""

from __future__ import annotations

import abc
import re
from typing import Any, Callable, Dict, List, Optional, Set, Tuple

from taintgate.core.lattice import Label, IntegrityLevel, ConfidentialityLevel
from taintgate.core.labels import LABEL_ENDORSED_PUBLIC, LABEL_TRUSTED_PUBLIC
from taintgate.core.sanitizer import FrontierDataSanitizer


class ExtractionError(ValueError):
    """Raised when data fails validation under a quarantined extractor."""
    pass


class QuarantinedExtractor(abc.ABC):
    """Abstract base class for pure, isolated data extractors and validators."""

    def __init__(self, name: str, target_label: Optional[Label] = None):
        self.name = name
        self.target_label = target_label or LABEL_ENDORSED_PUBLIC

    @abc.abstractmethod
    def extract(self, raw_input: Any) -> Any:
        """Validates and extracts typed data from raw input. Raises ExtractionError on failure."""
        pass

    def endorse(self, raw_input: Any, input_label: Optional[Label] = None) -> Tuple[Any, Label]:
        """Runs extraction in quarantine.
        
        If valid, returns (extracted_value, label).
        Soundness invariant: Endorsement upgrades integrity to ENDORSED, but
        NEVER declassifies confidentiality (preserves max confidentiality).
        """
        val = self.extract(raw_input)
        final_conf = self.target_label.confidentiality
        if input_label is not None:
            final_conf = max(final_conf, input_label.confidentiality)
        
        final_label = Label(
            integrity=self.target_label.integrity,
            confidentiality=final_conf,
        )
        return val, final_label


class RegexExtractor(QuarantinedExtractor):
    """Extracts data strictly matching a regular expression via fullmatch."""

    def __init__(self, name: str, pattern: str, target_label: Optional[Label] = None):
        super().__init__(name, target_label)
        self.regex = re.compile(pattern)

    def extract(self, raw_input: Any) -> str:
        raw_text = str(raw_input).strip()
        report = FrontierDataSanitizer.sanitize(raw_text)
        text = report.clean_text

        # Anomaly check: flag unexpectedly high entropy in parameters
        if report.is_high_entropy_anomaly and len(text) > 32 and not self.name.lower().startswith("sha"):
            raise ExtractionError(
                f"Steganographic anomaly: parameter has excessive Shannon entropy ({report.shannon_entropy:.2f} bits/byte)"
            )

        match = self.regex.fullmatch(text)
        if not match:
            raise ExtractionError(f"Input does not strictly match pattern for extractor '{self.name}': {text[:50]}")
        return match.group(0)


class AllowlistExtractor(QuarantinedExtractor):
    """Ensures input belongs to a predetermined set of trusted values (e.g., approved contacts)."""

    def __init__(self, name: str, allowed_values: Set[Any], target_label: Optional[Label] = None):
        super().__init__(name, target_label)
        self.allowed_values = {v.strip().lower() if isinstance(v, str) else v for v in allowed_values}

    def extract(self, raw_input: Any) -> Any:
        clean = raw_input.strip() if isinstance(raw_input, str) else raw_input
        cmp_val = clean.lower() if isinstance(clean, str) else clean
        if cmp_val not in self.allowed_values:
            raise ExtractionError(f"Value '{clean}' not in allowlist for extractor '{self.name}'")
        return clean


class NumericExtractor(QuarantinedExtractor):
    """Extracts clean integers or floating point numbers, stripping arbitrary text."""

    def __init__(self, name: str, is_float: bool = False, min_val: Optional[float] = None, max_val: Optional[float] = None):
        super().__init__(name, LABEL_ENDORSED_PUBLIC)
        self.is_float = is_float
        self.min_val = min_val
        self.max_val = max_val

    def extract(self, raw_input: Any) -> Any:
        try:
            val = float(raw_input) if self.is_float else int(raw_input)
        except (ValueError, TypeError) as e:
            raise ExtractionError(f"Failed numeric conversion for extractor '{self.name}': {raw_input}") from e

        if self.min_val is not None and val < self.min_val:
            raise ExtractionError(f"Value {val} below minimum {self.min_val}")
        if self.max_val is not None and val > self.max_val:
            raise ExtractionError(f"Value {val} above maximum {self.max_val}")
        return val


class ExtractorRegistry:
    """Registry of registered quarantined extractors."""

    def __init__(self):
        self._extractors: Dict[str, QuarantinedExtractor] = {}
        # Pre-register common standard extractors with strict fullmatch patterns
        self.register(
            RegexExtractor(
                name="email",
                pattern=r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$",
                target_label=Label(integrity=IntegrityLevel.ENDORSED, confidentiality=ConfidentialityLevel.PUBLIC),
            )
        )
        self.register(
            RegexExtractor(
                name="url_slug",
                pattern=r"^[a-zA-Z0-9_\-]+$",
                target_label=Label(integrity=IntegrityLevel.ENDORSED, confidentiality=ConfidentialityLevel.PUBLIC),
            )
        )
        self.register(NumericExtractor(name="integer", is_float=False))
        self.register(NumericExtractor(name="float", is_float=True))

    def register(self, extractor: QuarantinedExtractor) -> None:
        self._extractors[extractor.name] = extractor

    def get(self, name: str) -> Optional[QuarantinedExtractor]:
        return self._extractors.get(name)

    def extract_and_endorse(self, extractor_name: str, raw_input: Any, input_label: Optional[Label] = None) -> Tuple[Any, Label]:
        extractor = self.get(extractor_name)
        if not extractor:
            raise KeyError(f"Extractor '{extractor_name}' not registered")
        return extractor.endorse(raw_input, input_label=input_label)
