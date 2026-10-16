"""Shared Event and Audit Record Schemas."""

from __future__ import annotations

from enum import Enum
import json
import time
from typing import Any, Dict, Optional
from dataclasses import dataclass, field
import uuid

from taintgate.core.lattice import Label, IntegrityLevel, ConfidentialityLevel


class ProvenanceEventType(str, Enum):
    CONTEXT_ADDITION = "context_addition"
    TOOL_RESULT = "tool_result"
    FILE_READ = "file_read"
    DESTINATION_CONTACTED = "destination_contacted"
    DECISION_EVALUATED = "decision_evaluated"
    APPROVAL_PROMPTED = "approval_prompted"
    APPROVAL_RESOLVED = "approval_resolved"


@dataclass
class ProvenanceEvent:
    """Canonical boundary or provenance event."""
    session_id: str
    event_type: ProvenanceEventType
    label: Label
    details: Dict[str, Any] = field(default_factory=dict)
    event_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "event_id": self.event_id,
            "session_id": self.session_id,
            "timestamp": self.timestamp,
            "event_type": self.event_type.value,
            "label": self.label.to_dict(),
            "details": self.details,
        }

    def canonical_json(self) -> str:
        return json.dumps(self.to_dict(), sort_keys=True)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ProvenanceEvent":
        label = Label.from_dict(data["label"])

        return cls(
            event_id=data["event_id"],
            session_id=data["session_id"],
            timestamp=data["timestamp"],
            event_type=ProvenanceEventType(data["event_type"]),
            label=label,
            details=data.get("details", {}),
        )
