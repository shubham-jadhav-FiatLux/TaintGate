"""Frontier Data Sanitizer: Steganography, Homoglyph Normalization, and Entropy Defense.

Protects LLM agent pipelines against linguistic steganography, Unicode homoglyph spoofing,
invisible zero-width instruction smuggling, and anomalous high-entropy covert channels.
"""

from __future__ import annotations

from dataclasses import dataclass
import math
import re
from typing import Any, Dict, List, Optional, Tuple, Union
import unicodedata

# Invisible characters: zero-width spaces, joiners, BOM, and bidi overrides
INVISIBLE_CHARS_RE = re.compile(
    r"[\u200B-\u200D\u200E\u200F\u202A-\u202E\u2060-\u2064\u2066-\u2069\uFEFF]"
)


@dataclass
class SanitizationReport:
    """Telemetry report of sanitization transformations and entropy metrics."""
    original_text: str
    clean_text: str
    invisible_stripped_count: int
    homoglyphs_normalized: bool
    shannon_entropy: float
    is_high_entropy_anomaly: bool

    @property
    def was_modified(self) -> bool:
        return self.invisible_stripped_count > 0 or self.homoglyphs_normalized


class FrontierDataSanitizer:
    """Launders untrusted text to prevent linguistic steganography and homoglyph smuggling."""

    @staticmethod
    def normalize_unicode(text: str) -> Tuple[str, bool]:
        """Normalizes Unicode using NFKC, collapsing homoglyphs and compatibility variants."""
        normalized = unicodedata.normalize("NFKC", text)
        was_modified = normalized != text
        return normalized, was_modified

    @staticmethod
    def strip_invisible(text: str) -> Tuple[str, int]:
        """Strips zero-width spaces, directional overrides, joiners, and hidden marks."""
        matches = len(INVISIBLE_CHARS_RE.findall(text))
        cleaned = INVISIBLE_CHARS_RE.sub("", text)
        return cleaned, matches

    @staticmethod
    def compute_shannon_entropy(data: Union[str, bytes]) -> float:
        """Computes the Shannon entropy in bits per character/byte.

        H(X) = - sum(p_i * log2(p_i))
        """
        if not data:
            return 0.0

        raw_bytes = data.encode("utf-8") if isinstance(data, str) else data
        length = len(raw_bytes)
        if length == 0:
            return 0.0

        frequency: Dict[int, int] = {}
        for b in raw_bytes:
            frequency[b] = frequency.get(b, 0) + 1

        entropy = 0.0
        for count in frequency.values():
            p = count / length
            entropy -= p * math.log2(p)

        return round(entropy, 4)

    @classmethod
    def is_anomalous_entropy(
        cls,
        text: str,
        threshold: float = 4.85,
        min_length: int = 24,
    ) -> bool:
        """Identifies text with anomalously high entropy resembling encrypted/steganographic payloads.

        Standard natural language and code identifiers have entropy between 2.5 and 4.2.
        Random keys, encrypted ciphertext, or packed payloads typically exceed 4.8 bits/char.
        """
        if len(text) < min_length:
            return False
        entropy = cls.compute_shannon_entropy(text)
        return entropy >= threshold

    @classmethod
    def sanitize(
        cls,
        text: str,
        entropy_threshold: float = 4.85,
    ) -> SanitizationReport:
        """Executes the complete sanitization pipeline on input text."""
        if not text:
            return SanitizationReport(
                original_text="",
                clean_text="",
                invisible_stripped_count=0,
                homoglyphs_normalized=False,
                shannon_entropy=0.0,
                is_high_entropy_anomaly=False,
            )

        # 1. Strip invisible control and zero-width characters
        stripped, invisible_count = cls.strip_invisible(text)

        # 2. Normalize Unicode (NFKC)
        normalized, homoglyphs_modified = cls.normalize_unicode(stripped)

        # 3. Compute Shannon entropy
        entropy = cls.compute_shannon_entropy(normalized)
        is_anomaly = cls.is_anomalous_entropy(normalized, threshold=entropy_threshold)

        return SanitizationReport(
            original_text=text,
            clean_text=normalized,
            invisible_stripped_count=invisible_count,
            homoglyphs_normalized=homoglyphs_modified,
            shannon_entropy=entropy,
            is_high_entropy_anomaly=is_anomaly,
        )
