"""taintgate-core: the reference monitor engine.

This package contains the small, dependency-light reference monitor engine:
the label lattice, policy schema and evaluator, decision and capability-token types,
provenance graph, approval protocol, and audit event schemas.
"""

from taintgate.core.lattice import (
    Label,
    IntegrityLevel,
    ConfidentialityLevel,
)
from taintgate.core.labels import (
    LabelledValue,
    LABEL_TRUSTED_PUBLIC,
    LABEL_TRUSTED_INTERNAL,
    LABEL_TRUSTED_SECRET,
    LABEL_UNTRUSTED_PUBLIC,
    LABEL_UNTRUSTED_INTERNAL,
    LABEL_UNTRUSTED_SECRET,
    LABEL_ENDORSED_PUBLIC,
    LABEL_ENDORSED_INTERNAL,
)

from taintgate.core.provenance import (
    ProvenanceGraph,
    ProvenanceNode,
    ProvenanceEdge,
    NodeType,
)
from taintgate.core.decisions import (
    ActionEffect,
    Decision,
    DecisionRequest,
    DecisionType,
    CapabilityToken,
)
from taintgate.core.events import (
    ProvenanceEvent,
    ProvenanceEventType,
)
from taintgate.core.approval import (
    ApprovalRequest,
    ApprovalResponse,
    GrantScope,
)
from taintgate.core.policy import (
    TaintGateConfig,
    ToolConfig,
    PolicyEvaluator,
    parse_policy,
)

CONTRACT_VERSION = "1.0.0"

__all__ = [
    "CONTRACT_VERSION",
    # Labels and lattice
    "Label",
    "IntegrityLevel",
    "ConfidentialityLevel",
    "LabelledValue",
    "LABEL_TRUSTED_PUBLIC",
    "LABEL_TRUSTED_INTERNAL",
    "LABEL_TRUSTED_SECRET",
    "LABEL_UNTRUSTED_PUBLIC",
    "LABEL_UNTRUSTED_INTERNAL",
    "LABEL_UNTRUSTED_SECRET",
    "LABEL_ENDORSED_PUBLIC",
    "LABEL_ENDORSED_INTERNAL",

    # Policy configuration
    "TaintGateConfig",
    "ToolConfig",
    "parse_policy",
    # Decisions and evaluation
    "ActionEffect",
    "Decision",
    "DecisionRequest",
    "DecisionType",
    "PolicyEvaluator",
    # Provenance and events
    "ProvenanceGraph",
    "ProvenanceNode",
    "ProvenanceEdge",
    "NodeType",
    "ProvenanceEvent",
    # Approvals
    "ApprovalRequest",
    "ApprovalResponse",
    "GrantScope",
    # Capability tokens
    "CapabilityToken",
    # Audit events
    "ProvenanceEventType",
]
