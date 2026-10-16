"""TaintGate: Deterministic Information-Flow Control for LLM Agents."""

from taintgate.core.lattice import Label, IntegrityLevel, ConfidentialityLevel
from taintgate.core.labels import (
    LabelledValue,
    LABEL_TRUSTED_PUBLIC,
    LABEL_TRUSTED_INTERNAL,
    LABEL_TRUSTED_SECRET,
    LABEL_UNTRUSTED_PUBLIC,
    LABEL_UNTRUSTED_INTERNAL,
    LABEL_UNTRUSTED_SECRET,
    LABEL_ENDORSED_INTERNAL,
)
from taintgate.core.provenance import ProvenanceGraph, NodeType
from taintgate.core.decisions import (
    ActionEffect,
    Decision,
    DecisionRequest,
    DecisionType,
    CapabilityToken,
)
from taintgate.core.events import ProvenanceEvent, ProvenanceEventType
from taintgate.core.approval import ApprovalRequest, ApprovalResponse, GrantScope
from taintgate.core.policy import TaintGateConfig, ToolConfig, parse_policy, PolicyEvaluator
from taintgate.session.context import SessionTracker


class Engine:
    """Convenience top-level wrapper around the TaintGate Reference Monitor."""

    def __init__(self, config: TaintGateConfig):
        self.config = config
        self.evaluator = PolicyEvaluator(config)

    @classmethod
    def from_config(cls, path_or_str) -> "Engine":
        config = parse_policy(path_or_str)
        return cls(config)

    def decide(self, request: DecisionRequest) -> Decision:
        return self.evaluator.evaluate(request)

    def create_session(self, session_id: str = None) -> SessionTracker:
        return SessionTracker(evaluator=self.evaluator, session_id=session_id)


__version__ = "0.2.0"

__all__ = [
    "Engine",
    "SessionTracker",
    "Label",
    "IntegrityLevel",
    "ConfidentialityLevel",
    "LabelledValue",
    "ActionEffect",
    "Decision",
    "DecisionRequest",
    "DecisionType",
    "CapabilityToken",
    "ProvenanceGraph",
    "NodeType",
    "ProvenanceEvent",
    "ProvenanceEventType",
    "ApprovalRequest",
    "ApprovalResponse",
    "GrantScope",
    "TaintGateConfig",
    "ToolConfig",
    "PolicyEvaluator",
    "parse_policy",
    "__version__",
]
