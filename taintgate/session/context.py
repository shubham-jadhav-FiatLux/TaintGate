"""Session context tracking and sound information-flow propagation."""

from __future__ import annotations

import json
from typing import Any, Dict, List, Optional
import uuid

from taintgate.core.lattice import Label
from taintgate.core.labels import LABEL_TRUSTED_PUBLIC
from taintgate.core.provenance import ProvenanceGraph, NodeType, ProvenanceNode
from taintgate.core.decisions import (
    ActionEffect,
    Decision,
    DecisionRequest,
    DecisionType,
    CapabilityToken,
)
from taintgate.core.approval import GrantScope
from taintgate.core.policy.evaluator import PolicyEvaluator


def _canonical_grant_key(tool_name: str, arguments: Dict[str, Any]) -> str:
    """Builds a deterministic, order-independent key for scoped approval grants."""
    try:
        args_json = json.dumps(arguments, sort_keys=True, default=str)
    except Exception:
        args_json = str(sorted(str(k) + ":" + str(v) for k, v in arguments.items()))
    return f"{tool_name}:{args_json}"


class SessionTracker:
    """Manages multi-turn session taint tracking and provenance graphs."""

    def __init__(
        self,
        evaluator: PolicyEvaluator,
        session_id: Optional[str] = None,
        enable_exact_provenance: bool = False,
    ):
        self.session_id = session_id or str(uuid.uuid4())
        self.evaluator = evaluator
        self.enable_exact_provenance = enable_exact_provenance
        self.context_label = LABEL_TRUSTED_PUBLIC
        self.provenance_graph = ProvenanceGraph()
        self.turn = 0
        self.last_turn_node_id: Optional[str] = None
        self.scoped_grants: Dict[str, GrantScope] = {}

    def add_user_turn(self, content: str, label: Label = LABEL_TRUSTED_PUBLIC) -> ProvenanceNode:
        """Records a user input turn into the session."""
        self.turn += 1
        node = self.provenance_graph.add_node(
            node_type=NodeType.USER_INPUT,
            label=label,
            description=f"user turn: {content[:40]}...",
            turn=self.turn,
            metadata={"content": content, "raw_text": content},
        )
        if self.last_turn_node_id:
            self.provenance_graph.add_edge(self.last_turn_node_id, node.node_id, relation="turn_sequence")
        self.last_turn_node_id = node.node_id

        # Accumulate taint via lattice join
        self.context_label = self.context_label.join(label)
        return node

    def record_tool_result(self, tool_name: str, arguments: Dict[str, Any], output_label: Label) -> ProvenanceNode:
        """Records the arrival of observation/data from a tool output."""
        node = self.provenance_graph.add_node(
            node_type=NodeType.TOOL_RESULT,
            label=output_label,
            description=f"{tool_name}(...) output",
            turn=self.turn,
            metadata={"tool": tool_name, "arguments": arguments},
        )
        if self.last_turn_node_id:
            self.provenance_graph.add_edge(node.node_id, self.last_turn_node_id, relation="context_addition")

        # Accumulate taint into session context
        self.context_label = self.context_label.join(output_label)
        return node

    def evaluate_tool_call(self, tool_name: str, arguments: Dict[str, Any]) -> Decision:
        """Evaluates a proposed tool call against session context and active policy."""
        tool_cfg = self.evaluator.get_tool_config(tool_name)
        effect = ActionEffect.from_str(tool_cfg.effect)

        # Register tool call node in provenance graph
        call_node = self.provenance_graph.add_node(
            node_type=NodeType.TOOL_CALL,
            label=self.context_label,
            description=f"{tool_name}({arguments})",
            turn=self.turn,
            metadata={"tool": tool_name, "arguments": arguments},
        )
        if self.last_turn_node_id:
            self.provenance_graph.add_edge(self.last_turn_node_id, call_node.node_id, relation="steers_call")

        # Resolve argument labels (exact provenance if enabled, else context label)
        if self.enable_exact_provenance:
            from taintgate.core.precision.provenance_tracker import ExactProvenanceResolver
            resolver = ExactProvenanceResolver(self.provenance_graph)
            arg_labels = resolver.resolve_argument_labels(arguments, self.context_label)
        else:
            arg_labels = {k: self.context_label for k in arguments}

        req = DecisionRequest(
            tool_name=tool_name,
            arguments=arguments,
            effect=effect,
            session_id=self.session_id,
            session_context_label=self.context_label,
            argument_labels=arg_labels,
            provenance_node_id=call_node.node_id,
        )

        decision = self.evaluator.evaluate(req)

        # Check scoped grants: grants can ONLY upgrade APPROVE to ALLOW; they never override DENY!
        grant_key = _canonical_grant_key(tool_name, arguments)
        if decision.type == DecisionType.APPROVE and grant_key in self.scoped_grants:
            scope = self.scoped_grants[grant_key]
            if scope == GrantScope.ONCE:
                # Consume single-use grant
                del self.scoped_grants[grant_key]

            # Issue approval-backed ALLOW decision with valid capability token
            token = CapabilityToken.mint(
                tool_name=tool_name,
                arguments=arguments,
                secret_key=self.evaluator.token_secret,
            )
            decision = Decision(
                type=DecisionType.ALLOW,
                reason=f"Permitted via previous scoped human approval grant ({scope.value})",
                rule_id="scoped_grant",
                capability_token=token,
            )

        # If denied or requiring approval, attach flow slice explanation
        if decision.type in (DecisionType.DENY, DecisionType.APPROVE):
            flow_explanation = self.provenance_graph.format_flow_path(call_node.node_id)
            decision.explanation = flow_explanation

        return decision

    def grant_approval(self, tool_name: str, arguments: Dict[str, Any], scope: GrantScope = GrantScope.SESSION) -> None:
        """Records a human approval grant."""
        grant_key = _canonical_grant_key(tool_name, arguments)
        self.scoped_grants[grant_key] = scope
