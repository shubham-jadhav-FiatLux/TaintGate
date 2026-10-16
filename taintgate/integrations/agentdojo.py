"""AgentDojo benchmark pipeline element for evaluating agent defenses."""

from __future__ import annotations

from typing import Any, Dict, Optional, Tuple

from taintgate.core.decisions import Decision, DecisionType
from taintgate.core.policy.evaluator import PolicyEvaluator
from taintgate.session.context import SessionTracker


class TaintGateDojoPipelineElement:
    """Interception filter for the AgentDojo benchmark evaluation pipeline."""

    def __init__(self, evaluator: PolicyEvaluator):
        self.evaluator = evaluator
        self.session = SessionTracker(evaluator=evaluator)

    def filter_tool_call(self, tool_name: str, arguments: Dict[str, Any]) -> Tuple[bool, Optional[str], Optional[Decision]]:
        """Filters an AgentDojo tool invocation.

        Returns:
            (is_allowed, error_message_if_blocked, decision)
        """
        decision = self.session.evaluate_tool_call(tool_name, arguments)

        if decision.type == DecisionType.DENY:
            msg = f"Operation blocked by TaintGate: {decision.reason}\nTrace:\n{decision.explanation}"
            return False, msg, decision

        if decision.type == DecisionType.APPROVE:
            msg = f"Operation held for human approval: {decision.reason}"
            return False, msg, decision

        return True, None, decision

    def record_tool_result(self, tool_name: str, arguments: Dict[str, Any], result: Any) -> None:
        """Labels tool observation and propagates session taint."""
        output_label = self.evaluator.resolve_tool_output_label(tool_name, arguments)
        self.session.record_tool_result(tool_name, arguments, output_label)

    def reset_session(self) -> None:
        """Resets session context between benchmark tasks."""
        self.session = SessionTracker(evaluator=self.evaluator)
