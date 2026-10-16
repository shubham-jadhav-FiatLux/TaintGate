"""LangChain tool wrapping and reference monitor hooks."""

from __future__ import annotations

import functools
from typing import Any, Callable, Dict, Optional

from taintgate.core.decisions import Decision, DecisionType
from taintgate.session.context import SessionTracker


class TaintGateSecurityError(Exception):
    """Raised when a tool invocation is blocked by the TaintGate reference monitor."""

    def __init__(self, message: str, decision: Decision):
        super().__init__(message)
        self.decision = decision
        self.explanation = decision.explanation
        self.rule_id = decision.rule_id


class TaintGateToolWrapper:
    """Wraps callable functions or LangChain tools with TaintGate reference monitoring."""

    def __init__(
        self,
        func: Callable[..., Any],
        session: SessionTracker,
        tool_name: Optional[str] = None,
    ):
        self.func = func
        self.session = session
        self.tool_name = tool_name or getattr(func, "__name__", "unknown_tool")

    def __call__(self, *args: Any, **kwargs: Any) -> Any:
        # Convert positional arguments to kwargs if function has named parameters
        call_args: Dict[str, Any] = dict(kwargs)
        if args and hasattr(self.func, "__code__"):
            varnames = self.func.__code__.co_varnames
            for idx, arg_val in enumerate(args):
                if idx < len(varnames):
                    call_args[varnames[idx]] = arg_val

        # Step 1: Pre-execution policy check
        decision = self.session.evaluate_tool_call(self.tool_name, call_args)

        if decision.type == DecisionType.DENY:
            raise TaintGateSecurityError(
                f"[TaintGate] Tool '{self.tool_name}' BLOCKED: {decision.reason}",
                decision=decision,
            )

        if decision.type == DecisionType.APPROVE:
            raise TaintGateSecurityError(
                f"[TaintGate] Tool '{self.tool_name}' requires human approval: {decision.reason}",
                decision=decision,
            )

        # Step 2: Execute underlying tool
        result = self.func(*args, **kwargs)

        # Step 3: Post-execution observation labelling
        output_label = self.session.evaluator.resolve_tool_output_label(self.tool_name, call_args)
        self.session.record_tool_result(self.tool_name, call_args, output_label)

        return result


def wrap_tool(
    func_or_tool: Callable[..., Any],
    session: SessionTracker,
    tool_name: Optional[str] = None,
) -> TaintGateToolWrapper:
    """Convenience decorator or wrapper for functions and LangChain tools."""
    return TaintGateToolWrapper(func_or_tool, session=session, tool_name=tool_name)
