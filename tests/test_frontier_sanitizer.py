"""Unit tests for FrontierDataSanitizer.

Verifies Unicode NFKC homoglyph normalization, zero-width steganographic stripping,
Shannon entropy calculation, and anomalous payload gating.
"""

import os
import pytest

from taintgate.core.sanitizer import FrontierDataSanitizer, SanitizationReport
from taintgate.core.precision.extractors import RegexExtractor, ExtractionError


def test_strip_invisible_characters():
    # Hidden zero-width spaces, joiners, directional overrides, and BOM
    smuggled = "rm\u200B -rf\u200D /\uFEFF\u202E"
    clean, count = FrontierDataSanitizer.strip_invisible(smuggled)
    assert clean == "rm -rf /"
    assert count == 4

    clean_text, zero_count = FrontierDataSanitizer.strip_invisible("safe_identifier_123")
    assert clean_text == "safe_identifier_123"
    assert zero_count == 0


def test_normalize_unicode_homoglyphs():
    # Fullwidth latin characters and compatibility ligatures
    # Fullwidth 'a' (\uFF41), 'b' (\uFF42), ligature 'fi' (\uFB01)
    fullwidth = "\uFF41\uFF42\uFB01le"
    normalized, modified = FrontierDataSanitizer.normalize_unicode(fullwidth)
    assert normalized == "abfile"
    assert modified is True

    pure_ascii = "standard_filename.txt"
    norm_ascii, modified_ascii = FrontierDataSanitizer.normalize_unicode(pure_ascii)
    assert norm_ascii == pure_ascii
    assert modified_ascii is False


def test_shannon_entropy_calculation():
    # Empty string or bytes
    assert FrontierDataSanitizer.compute_shannon_entropy("") == 0.0
    assert FrontierDataSanitizer.compute_shannon_entropy(b"") == 0.0

    # Low entropy: repeated characters
    assert FrontierDataSanitizer.compute_shannon_entropy("AAAAAAAAAA") == 0.0

    # Natural language: typical English entropy is ~3.0 - 4.2
    nat_lang = "The quick brown fox jumps over the lazy dog in the sunny afternoon."
    h_nat = FrontierDataSanitizer.compute_shannon_entropy(nat_lang)
    assert 3.0 < h_nat < 4.5

    # High entropy: 256 random bytes uniformly distributed should approach 8.0 bits/byte
    random_bytes = bytes([i % 256 for i in range(1024)])
    h_uniform = FrontierDataSanitizer.compute_shannon_entropy(random_bytes)
    assert h_uniform >= 7.9


def test_is_anomalous_entropy():
    # Short string should not trigger anomaly even if high entropy
    assert FrontierDataSanitizer.is_anomalous_entropy("x$9#a@", min_length=24) is False

    # Normal code / SQL snippet
    sql = "SELECT id, username, email FROM system_accounts WHERE status = 'active'"
    assert FrontierDataSanitizer.is_anomalous_entropy(sql) is False

    # Anomalous packed / encrypted payload (e.g. 64 pseudorandom bytes hex encoded or high-entropy raw)
    random_payload = bytes(range(128)).decode("latin-1")
    assert FrontierDataSanitizer.is_anomalous_entropy(random_payload, threshold=4.85) is True


def test_sanitize_full_pipeline():
    dirty = "user\u200B_\uFF4Eame"  # contains zero-width and fullwidth 'n'
    report = FrontierDataSanitizer.sanitize(dirty)
    assert isinstance(report, SanitizationReport)
    assert report.clean_text == "user_name"
    assert report.invisible_stripped_count == 1
    assert report.homoglyphs_normalized is True
    assert report.was_modified is True
    assert report.shannon_entropy > 0.0

    # Empty string handling
    empty_report = FrontierDataSanitizer.sanitize("")
    assert empty_report.clean_text == ""
    assert empty_report.invisible_stripped_count == 0
    assert empty_report.was_modified is False


def test_regex_extractor_with_sanitization():
    extractor = RegexExtractor("safe_id", r"^[a-zA-Z0-9_]+$")
    
    # Input with smuggled zero-width characters that would otherwise fail regex or smuggle tokens
    raw_with_zw = "clean\u200B_token\uFEFF_42"
    extracted = extractor.extract(raw_with_zw)
    assert extracted == "clean_token_42"

    # Input with excessive entropy representing covert steganography
    high_entropy_secret = bytes(range(64)).decode("latin-1")
    with pytest.raises(ExtractionError, match="Steganographic anomaly"):
        extractor.extract(high_entropy_secret)
