"""OpenAI Agents SDK and ReAct agent loop interception hook."""

from __future__ import annotations

from typing import Any, Dict, Optional

from taintgate.core.decisions import Decision
from taintgate.session.context import SessionTracker


class TaintGateReActMediator:
    """Hooks into ReAct (Reason-Act-Observe) agent loops to enforce information-flow control."""

    def __init__(self, session: SessionTracker):
        self.session = session

    def intercept_tool_call(self, tool_name: str, arguments: Dict[str, Any]) -> Decision:
        """Evaluates a proposed tool call before the agent harness executes it."""
        return self.session.evaluate_tool_call(tool_name, arguments)

    def record_tool_observation(self, tool_name: str, arguments: Dict[str, Any], observation: Any) -> None:
        """Labels and records tool output when it returns to the agent context."""
        output_label = self.session.evaluator.resolve_tool_output_label(tool_name, arguments)
        self.session.record_tool_result(tool_name, arguments, output_label)
