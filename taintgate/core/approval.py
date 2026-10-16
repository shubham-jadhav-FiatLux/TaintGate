"""Approval Protocol."""

from __future__ import annotations

from enum import Enum
import time
from typing import Any, Dict, Optional
from dataclasses import dataclass, field
import uuid


class GrantScope(str, Enum):
    ONCE = "once"
    SESSION = "session"
    FOREVER = "forever"


@dataclass
class ApprovalRequest:
    """Sent to the Trusted UI when a tool call requires human sign-off."""
    session_id: str
    tool_name: str
    arguments: Dict[str, Any]
    explanation: str
    flow_summary: str
    request_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: float = field(default_factory=time.time)


@dataclass
class ApprovalResponse:
    """Returned by the Trusted UI."""
    request_id: str
    approved: bool
    scope: GrantScope = GrantScope.ONCE
    approver: str = "human_operator"
    timestamp: float = field(default_factory=time.time)
