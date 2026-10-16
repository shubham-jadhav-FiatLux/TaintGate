"""Baseline defense implementations for comparative security evaluation."""

from __future__ import annotations

import re
from typing import Any, Dict, Optional, Tuple
from dataclasses import dataclass

from taintgate.core.policy.evaluator import PolicyEvaluator
from taintgate.session.context import SessionTracker


@dataclass
class DefenseResult:
    allowed: bool
    requires_approval: bool = False
    reason: str = ""
    explanation: str = ""


class BaseDefense:
    def evaluate_call(self, tool_name: str, arguments: Dict[str, Any]) -> DefenseResult:
        raise NotImplementedError

    def record_observation(self, tool_name: str, arguments: Dict[str, Any], observation: Any) -> None:
        pass

    def reset(self) -> None:
        pass


class NoDefense(BaseDefense):
    """Raw agent execution with no mediation barrier."""

    def evaluate_call(self, tool_name: str, arguments: Dict[str, Any]) -> DefenseResult:
        return DefenseResult(allowed=True, reason="No defense active")


class StaticToolFilter(BaseDefense):
    """Static allow/deny tool filter based on tool names."""

    def __init__(self, disallowed_tools: Optional[set] = None):
        self.disallowed_tools = disallowed_tools or {"email.send", "db.delete_table"}

    def evaluate_call(self, tool_name: str, arguments: Dict[str, Any]) -> DefenseResult:
        if tool_name in self.disallowed_tools:
            return DefenseResult(allowed=False, reason=f"Tool '{tool_name}' blocked by static filter")
        return DefenseResult(allowed=True, reason="Tool permitted by static filter")


class NaiveHITL(BaseDefense):
    """Naive Human-In-The-Loop requiring explicit approval for all non-read actions."""

    def __init__(self, side_effect_tools: Optional[set] = None):
        self.side_effect_tools = side_effect_tools or {"fs.write_file", "email.send", "db.delete_table"}

    def evaluate_call(self, tool_name: str, arguments: Dict[str, Any]) -> DefenseResult:
        if tool_name in self.side_effect_tools:
            # Requires human approval on every side-effecting call
            return DefenseResult(
                allowed=False,
                requires_approval=True,
                reason=f"Action '{tool_name}' held for human approval",
            )
        return DefenseResult(allowed=True, reason="Read action permitted")


class DualLLMInspector(BaseDefense):
    """Static keyword/pattern inspector — a deterministic *stand-in* for the cheap tier of a
    content-inspection defense (e.g. a dual-LLM inspector prompted to flag suspicious arguments).

    IMPORTANT (honesty of comparison): this is NOT a real LLM. It is a regex over tool arguments,
    included only to illustrate that *content-pattern* inspection is evadable by encoding the
    payload or using an innocuous-looking recipient. Results for this baseline must be read as
    "a keyword inspector", never generalized to "all dual-LLM inspectors": a real LLM inspector
    could catch some of these, and evaluating one requires a live model (see eval/agentdojo_runner.py).
    """

    def __init__(self):
        # A representative block-list an operator might hand a cheap inspector.
        self.exfil_patterns = [
            re.compile(r"attacker|evil|exfiltrat|leaked|stolen|credential|secret", re.IGNORECASE)
        ]

    def evaluate_call(self, tool_name: str, arguments: Dict[str, Any]) -> DefenseResult:
        arg_str = str(arguments)
        if tool_name in ("email.send", "http.post"):
            for pat in self.exfil_patterns:
                if pat.search(arg_str):
                    return DefenseResult(
                        allowed=False,
                        reason="Keyword inspector flagged an argument matching an exfiltration pattern",
                    )
        return DefenseResult(allowed=True, reason="Keyword inspector found no flagged pattern")


class TaintGateDefense(BaseDefense):
    """TaintGate deterministic reference monitor."""

    def __init__(self, evaluator: PolicyEvaluator):
        self.evaluator = evaluator
        self.session = SessionTracker(evaluator=evaluator)

    def evaluate_call(self, tool_name: str, arguments: Dict[str, Any]) -> DefenseResult:
        dec = self.session.evaluate_tool_call(tool_name, arguments)
        return DefenseResult(
            allowed=dec.is_allowed,
            requires_approval=dec.requires_approval,
            reason=dec.reason,
            explanation=dec.explanation,
        )

    def record_observation(self, tool_name: str, arguments: Dict[str, Any], observation: Any) -> None:
        lbl = self.evaluator.resolve_tool_output_label(tool_name, arguments)
        self.session.record_tool_result(tool_name, arguments, lbl)

    def reset(self) -> None:
        self.session = SessionTracker(evaluator=self.evaluator)
