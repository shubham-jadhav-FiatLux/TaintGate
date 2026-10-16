"""Decision API and Capability Tokens.

Defines the decision request/response types for Policy Enforcement Points (PEPs)
and capability token minting/verification to close time-of-check to time-of-use (TOCTOU) gaps.
"""

from __future__ import annotations

from enum import Enum
import hashlib
import hmac
import json
import time
from typing import Any, Dict, List, Optional
from dataclasses import dataclass, field
import uuid

from taintgate.core.lattice import Label


class ActionEffect(str, Enum):
    """Declared side effect of a tool."""
    READ = "read"
    LOCAL_WRITE = "local_write"
    EXTERNAL = "external"
    IRREVERSIBLE = "irreversible"

    @classmethod
    def from_str(cls, val: str) -> "ActionEffect":
        key = val.strip().lower()
        for item in cls:
            if item.value == key:
                return item
        raise ValueError(f"Unknown action effect: {val}")


class DecisionType(str, Enum):
    """Verdict rendered by the Policy Decision Point."""
    ALLOW = "allow"
    DENY = "deny"
    APPROVE = "approve"
    REDACT = "redact"


@dataclass
class CapabilityToken:
    """Short-lived, scoped capability token for TOCTOU protection."""
    token_id: str
    tool_name: str
    scope_hash: str
    issued_at: float
    expires_at: float
    signature: str

    @classmethod
    def mint(
        cls,
        tool_name: str,
        arguments: Dict[str, Any],
        secret_key: bytes,
        ttl_seconds: float = 60.0,
    ) -> "CapabilityToken":
        token_id = str(uuid.uuid4())
        now = time.time()
        expires = now + ttl_seconds
        scope_str = json.dumps({"tool": tool_name, "args": arguments}, sort_keys=True, default=str)
        scope_hash = hashlib.sha256(scope_str.encode()).hexdigest()

        msg = f"{token_id}:{tool_name}:{scope_hash}:{now}:{expires}".encode()
        sig = hmac.new(secret_key, msg, hashlib.sha256).hexdigest()

        return cls(
            token_id=token_id,
            tool_name=tool_name,
            scope_hash=scope_hash,
            issued_at=now,
            expires_at=expires,
            signature=sig,
        )

    def verify(
        self,
        tool_name: str,
        arguments: Dict[str, Any],
        secret_key: bytes,
    ) -> bool:
        if time.time() > self.expires_at:
            return False
        if tool_name != self.tool_name:
            return False

        scope_str = json.dumps({"tool": tool_name, "args": arguments}, sort_keys=True, default=str)
        curr_scope_hash = hashlib.sha256(scope_str.encode()).hexdigest()
        if curr_scope_hash != self.scope_hash:
            return False

        msg = f"{self.token_id}:{self.tool_name}:{self.scope_hash}:{self.issued_at}:{self.expires_at}".encode()
        expected_sig = hmac.new(secret_key, msg, hashlib.sha256).hexdigest()
        return hmac.compare_digest(self.signature, expected_sig)


@dataclass
class DecisionRequest:
    """Canonical decision request presented to PDP."""
    tool_name: str
    arguments: Dict[str, Any]
    effect: ActionEffect
    session_id: str
    session_context_label: Label
    argument_labels: Dict[str, Label] = field(default_factory=dict)
    recipients: Optional[List[str]] = None
    provenance_node_id: Optional[str] = None


@dataclass
class Decision:
    """Verdict returned by PDP."""
    type: DecisionType
    reason: str
    rule_id: Optional[str] = None
    explanation: str = ""
    redacted_arguments: Optional[Dict[str, Any]] = None
    capability_token: Optional[CapabilityToken] = None

    @property
    def is_allowed(self) -> bool:
        return self.type == DecisionType.ALLOW

    @property
    def is_denied(self) -> bool:
        return self.type == DecisionType.DENY

    @property
    def requires_approval(self) -> bool:
        return self.type == DecisionType.APPROVE
