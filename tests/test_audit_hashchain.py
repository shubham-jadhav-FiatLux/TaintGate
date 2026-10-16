"""Tests for tamper-evident hash-chained audit logging."""

import json
from pathlib import Path
from taintgate.core.events import ProvenanceEvent, ProvenanceEventType
from taintgate.core.labels import LABEL_TRUSTED_PUBLIC, LABEL_UNTRUSTED_SECRET
from taintgate.audit.log import HashChainLog


def test_hash_chain_creation_and_verification(tmp_path: Path):
    log_file = tmp_path / "audit.jsonl"
    logger = HashChainLog(log_file)

    ev1 = ProvenanceEvent(
        session_id="s1",
        event_type=ProvenanceEventType.CONTEXT_ADDITION,
        label=LABEL_TRUSTED_PUBLIC,
        details={"info": "first event"},
    )
    ev2 = ProvenanceEvent(
        session_id="s1",
        event_type=ProvenanceEventType.TOOL_RESULT,
        label=LABEL_UNTRUSTED_SECRET,
        details={"info": "second event"},
    )

    h1 = logger.append(ev1)
    h2 = logger.append(ev2)

    assert h1 != h2
    valid, failed_idx = logger.verify()
    assert valid is True
    assert failed_idx is None


def test_tamper_detection_modified_payload(tmp_path: Path):
    log_file = tmp_path / "audit_tampered.jsonl"
    logger = HashChainLog(log_file)

    ev1 = ProvenanceEvent(
        session_id="s1",
        event_type=ProvenanceEventType.CONTEXT_ADDITION,
        label=LABEL_TRUSTED_PUBLIC,
        details={"step": 1},
    )
    ev2 = ProvenanceEvent(
        session_id="s1",
        event_type=ProvenanceEventType.TOOL_RESULT,
        label=LABEL_TRUSTED_PUBLIC,
        details={"step": 2},
    )

    logger.append(ev1)
    logger.append(ev2)

    # Corrupt line 0 payload
    lines = log_file.read_text(encoding="utf-8").splitlines()
    rec0 = json.loads(lines[0])
    rec0["event"]["details"]["step"] = 999  # Attacker modified details
    lines[0] = json.dumps(rec0)
    log_file.write_text("\n".join(lines) + "\n", encoding="utf-8")

    # Verifier must detect tampering
    verifier = HashChainLog(log_file)
    valid, failing_line = verifier.verify()
    assert valid is False
    assert failing_line == 0


def test_tamper_detection_broken_chain(tmp_path: Path):
    log_file = tmp_path / "audit_broken.jsonl"
    logger = HashChainLog(log_file)

    for i in range(3):
        logger.append(
            ProvenanceEvent(
                session_id="s1",
                event_type=ProvenanceEventType.CONTEXT_ADDITION,
                label=LABEL_TRUSTED_PUBLIC,
                details={"i": i},
            )
        )

    # Delete middle record
    lines = log_file.read_text(encoding="utf-8").splitlines()
    del lines[1]
    log_file.write_text("\n".join(lines) + "\n", encoding="utf-8")

    verifier = HashChainLog(log_file)
    valid, failing_line = verifier.verify()
    assert valid is False
    assert failing_line == 1


def test_missing_log_verify_fails(tmp_path: Path):
    nonexistent = tmp_path / "does_not_exist.jsonl"
    logger = HashChainLog(nonexistent)
    valid, failing_line = logger.verify()
    assert valid is False


def test_truncation_detection_via_tip(tmp_path: Path):
    log_file = tmp_path / "audit_truncated.jsonl"
    logger = HashChainLog(log_file)

    for i in range(5):
        logger.append(
            ProvenanceEvent(
                session_id="s1",
                event_type=ProvenanceEventType.CONTEXT_ADDITION,
                label=LABEL_TRUSTED_PUBLIC,
                details={"step": i},
            )
        )

    # Valid before truncation
    valid, _ = logger.verify()
    assert valid is True

    # Attacker truncates the last 2 records from the jsonl file
    lines = log_file.read_text(encoding="utf-8").splitlines()
    truncated_lines = lines[:3]
    log_file.write_text("\n".join(truncated_lines) + "\n", encoding="utf-8")

    # Verifier checks tip anchor and detects truncation
    verifier = HashChainLog(log_file)
    valid, failing_line = verifier.verify()
    assert valid is False


def test_hmac_tip_tamper_detection(tmp_path: Path):
    log_file = tmp_path / "audit_hmac.jsonl"
    key = b"secret-key-32-bytes-long-123456"
    logger = HashChainLog(log_file, hmac_key=key)

    logger.append(
        ProvenanceEvent(
            session_id="s1",
            event_type=ProvenanceEventType.CONTEXT_ADDITION,
            label=LABEL_TRUSTED_PUBLIC,
            details={"step": 1},
        )
    )

    verifier = HashChainLog(log_file, hmac_key=key)
    valid, _ = verifier.verify()
    assert valid is True

    # Tamper with the tip MAC
    tip_file = log_file.with_suffix(".tip")
    tip_data = json.loads(tip_file.read_text(encoding="utf-8"))
    tip_data["mac"] = "bad" * 16
    tip_file.write_text(json.dumps(tip_data), encoding="utf-8")

    valid, _ = verifier.verify()
    assert valid is False
