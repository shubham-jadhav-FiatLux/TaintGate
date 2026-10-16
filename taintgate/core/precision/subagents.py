"""Tier 2 Precision: Clean-Context Sub-Agent Coordinator.

Enables architectural isolation where discrete sub-tasks execute in fresh, unpolluted
context windows, preventing accumulated session taint from paralyzing benign workflows
while soundly preserving parent taint invariants.
"""

from __future__ import annotations

from typing import Any, Callable, Dict, List, Optional, Tuple
import uuid

from taintgate.core.lattice import Label, IntegrityLevel, ConfidentialityLevel
from taintgate.core.labels import LABEL_TRUSTED_PUBLIC
from taintgate.core.provenance import NodeType
from taintgate.core.policy.evaluator import PolicyEvaluator
from taintgate.session.context import SessionTracker
from taintgate.core.precision.extractors import QuarantinedExtractor


class CleanContextSubAgent:
    """An isolated sub-agent operating with its own fresh context window.

    Soundness Invariant:
    A sub-agent inherits the parent session's integrity taint so it cannot be used
    by an untrusted parent as an unconstrained execution proxy.
    Its confidentiality window starts clean (PUBLIC) so that parent secrets do not
    unnecessarily leak into the subagent's queries.
    """

    def __init__(
        self,
        subagent_id: str,
        task_description: str,
        evaluator: PolicyEvaluator,
        parent_session_id: str,
        inherited_integrity: IntegrityLevel = IntegrityLevel.TRUSTED,
    ):
        self.subagent_id = subagent_id
        self.task_description = task_description
        self.evaluator = evaluator
        self.parent_session_id = parent_session_id
        self.inherited_integrity = inherited_integrity

        # Sub-agent session starts with inherited integrity and clean public confidentiality
        self.session = SessionTracker(evaluator=evaluator, session_id=subagent_id)
        start_label = Label(
            integrity=inherited_integrity,
            confidentiality=ConfidentialityLevel.PUBLIC,
        )
        self.session.context_label = start_label
        self.session.add_user_turn(task_description, label=start_label)

    def execute_tool_call(self, tool_name: str, arguments: Dict[str, Any]) -> Any:
        """Evaluates and executes tool call within the subagent's bounded context."""
        decision = self.session.evaluate_tool_call(tool_name, arguments)
        return decision


class CleanContextCoordinator:
    """Coordinates clean-context sub-agent delegation and safe result re-integration."""

    def __init__(self, evaluator: PolicyEvaluator):
        self.evaluator = evaluator
        self.active_subagents: Dict[str, CleanContextSubAgent] = {}

    def spawn_subagent(self, parent_session: SessionTracker, task: str) -> CleanContextSubAgent:
        """Spawns an isolated sub-agent inheriting the parent's integrity constraints."""
        sub_id = f"subagent_{uuid.uuid4().hex[:8]}"
        sub = CleanContextSubAgent(
            subagent_id=sub_id,
            task_description=task,
            evaluator=self.evaluator,
            parent_session_id=parent_session.session_id,
            inherited_integrity=parent_session.context_label.integrity,
        )
        self.active_subagents[sub_id] = sub

        # Record delegation in parent provenance graph with parent's integrity
        parent_session.provenance_graph.add_node(
            node_type=NodeType.EXTERNAL_SOURCE,
            label=Label(integrity=parent_session.context_label.integrity, confidentiality=ConfidentialityLevel.PUBLIC),
            description=f"Spawning subagent: {task[:40]}",
            turn=parent_session.turn,
            metadata={"subagent_id": sub_id},
        )
        return sub

    def return_result_to_parent(
        self,
        parent_session: SessionTracker,
        subagent_id: str,
        result_data: Any,
        extractor: Optional[QuarantinedExtractor] = None,
    ) -> Label:
        """Safely re-integrates sub-agent output into the parent session.

        Soundness Invariant:
        The result label retains the subagent's accumulated taint. An extractor can
        endorse integrity only if the extractor validates the result, but cannot
        declassify confidentiality.
        """
        sub = self.active_subagents.get(subagent_id)
        if not sub:
            raise KeyError(f"Unknown subagent: {subagent_id}")

        base_label = sub.session.context_label

        if extractor is not None:
            clean_val, final_label = extractor.endorse(result_data, input_label=base_label)
        else:
            final_label = base_label

        # Record tool result in parent
        parent_session.record_tool_result(
            tool_name=f"subagent_{subagent_id}",
            arguments={"task": sub.task_description},
            output_label=final_label,
        )

        return final_label
