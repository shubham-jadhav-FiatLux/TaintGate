"""Tamper-Evident Hash-Chained Audit Logger.

Integrity is a hash chain over records. Tamper-*evidence against a motivated attacker*
(who can rewrite the file) additionally requires an **authenticated tip anchor**: after
each append the logger writes ``<log>.tip`` holding ``(seq, tip_hash, mac)`` where ``mac``
is ``HMAC-SHA256(key, "seq:tip_hash")``. Verification then detects:

* content/linkage tampering of any record (hash chain), and
* **truncation** (seq mismatch) and **tip deletion** — but only when a key is configured.

The key must be held outside the log directory (e.g. ``$TAINTGATE_AUDIT_KEY``); if it sat
next to the log, an attacker could truncate and re-sign. Without a key the tip is an
*unkeyed* checksum: it catches accidental truncation but not a deliberate rewrite, and
``verify`` reports ``ok_integrity_only`` rather than ``ok_authenticated``.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from taintgate.core.events import ProvenanceEvent

GENESIS_HASH = "0" * 64


def audit_key_from_env() -> Optional[bytes]:
    """Reads the tip-authentication key from ``$TAINTGATE_AUDIT_KEY`` (hex or raw), or None."""
    raw = os.environ.get("TAINTGATE_AUDIT_KEY")
    if not raw:
        return None
    try:
        return bytes.fromhex(raw)
    except ValueError:
        return raw.encode("utf-8")


class HashChainLog:
    """Append-only, tamper-evident audit log with SHA-256 hash chaining and anchored tips."""

    def __init__(self, log_path: Path, hmac_key: Optional[bytes] = None):
        self.log_path = Path(log_path)
        self.tip_path = self.log_path.with_suffix(".tip")
        # Fall back to the ambient key so a keyed configuration is the easy default.
        self.hmac_key = hmac_key if hmac_key is not None else audit_key_from_env()
        self.last_hash = GENESIS_HASH
        self.seq = 0

        if self.log_path.exists():
            # Recover last hash from existing file
            lines = [l.strip() for l in self.log_path.read_text(encoding="utf-8").splitlines() if l.strip()]
            self.seq = len(lines)
            if lines:
                try:
                    last_record = json.loads(lines[-1])
                    self.last_hash = last_record.get("hash", GENESIS_HASH)
                except Exception:
                    self.last_hash = GENESIS_HASH

    def _compute_tip_mac(self, seq: int, tip_hash: str) -> str:
        payload = f"{seq}:{tip_hash}".encode("utf-8")
        if self.hmac_key:
            return hmac.new(self.hmac_key, payload, hashlib.sha256).hexdigest()
        return hashlib.sha256(payload).hexdigest()

    @property
    def is_authenticated(self) -> bool:
        """True when a tip-authentication key is configured (unforgeable truncation evidence)."""
        return self.hmac_key is not None

    def append(self, event: ProvenanceEvent) -> str:
        """Appends a new event record with cryptographic linkage to the preceding record."""
        payload = {
            "prev_hash": self.last_hash,
            "event": event.to_dict(),
        }
        canonical_str = json.dumps(payload, sort_keys=True)
        record_hash = hashlib.sha256(canonical_str.encode("utf-8")).hexdigest()

        record = {
            "hash": record_hash,
            "prev_hash": self.last_hash,
            "event": event.to_dict(),
        }

        self.log_path.parent.mkdir(parents=True, exist_ok=True)
        with open(self.log_path, "a", encoding="utf-8") as f:
            f.write(json.dumps(record, sort_keys=True) + "\n")

        self.last_hash = record_hash
        self.seq += 1

        # Write anchored tip
        tip_data = {
            "seq": self.seq,
            "tip_hash": self.last_hash,
            "mac": self._compute_tip_mac(self.seq, self.last_hash),
        }
        self.tip_path.write_text(json.dumps(tip_data, sort_keys=True) + "\n", encoding="utf-8")

        return record_hash

    def verify(self) -> Tuple[bool, Optional[int]]:
        """Verifies hash-chain integrity and the tip anchor. Returns (valid, failing_index)."""
        valid, idx, _ = self.verify_detailed()
        return valid, idx

    def verify_detailed(self) -> Tuple[bool, Optional[int], str]:
        """Verifies the log and returns ``(valid, failing_index, status)``.

        ``status`` is one of ``"ok_authenticated"`` (chain + keyed tip verified; truncation
        and tip deletion are detectable), ``"ok_integrity_only"`` (chain verified but no key
        configured, so a deliberate rewrite is *not* detectable), or ``"fail"``.
        A missing or empty log fails. When a key is configured, a missing tip is treated as
        deletion and fails.
        """
        if not self.log_path.exists():
            return False, None, "fail"

        lines = [l.strip() for l in self.log_path.read_text(encoding="utf-8").splitlines() if l.strip()]
        if not lines:
            return False, None, "fail"

        expected_prev = GENESIS_HASH

        for idx, line in enumerate(lines):
            try:
                record = json.loads(line)
            except Exception:
                return False, idx, "fail"

            rec_hash = record.get("hash")
            rec_prev = record.get("prev_hash")
            rec_event = record.get("event")

            if rec_prev != expected_prev:
                return False, idx, "fail"

            payload = {
                "prev_hash": rec_prev,
                "event": rec_event,
            }
            canonical_str = json.dumps(payload, sort_keys=True)
            computed_hash = hashlib.sha256(canonical_str.encode("utf-8")).hexdigest()

            if computed_hash != rec_hash:
                return False, idx, "fail"

            expected_prev = rec_hash

        # Tip anchor: detects truncation (seq mismatch) and, under a key, forgery and deletion.
        if self.tip_path.exists():
            try:
                tip = json.loads(self.tip_path.read_text(encoding="utf-8"))
                tip_seq = tip.get("seq")
                tip_hash = tip.get("tip_hash")
                tip_mac = tip.get("mac")
            except Exception:
                return False, None, "fail"

            # Authenticate the tip FIRST: without the key an attacker cannot have produced a
            # valid MAC for a truncated log, so a MAC mismatch is decisive.
            expected_mac = self._compute_tip_mac(tip_seq, tip_hash) if isinstance(tip_seq, int) and isinstance(tip_hash, str) else None
            if expected_mac is None or not hmac.compare_digest(str(tip_mac), expected_mac):
                return False, None, "fail"
            if tip_seq != len(lines):
                return False, len(lines), "fail"  # truncation
            if tip_hash != expected_prev:
                return False, len(lines) - 1, "fail"
            return True, None, ("ok_authenticated" if self.is_authenticated else "ok_integrity_only")

        # No tip present.
        if self.is_authenticated:
            # A key is configured, so every genuine record carries a tip; its absence on a
            # non-empty log is evidence of deletion/rollback.
            return False, None, "fail"
        return True, None, "ok_integrity_only"
