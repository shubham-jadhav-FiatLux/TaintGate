"""Model Context Protocol (MCP) JSON-RPC Interceptor and Protocol Mediator."""

from __future__ import annotations

import logging
from typing import Any, Dict, Optional, Tuple

from taintgate.core.policy.evaluator import PolicyEvaluator
from taintgate.core.decisions import DecisionType
from taintgate.core.events import ProvenanceEvent, ProvenanceEventType
from taintgate.session.context import SessionTracker
from taintgate.proxy.pinning import ToolDescriptionPinner
from taintgate.audit.log import HashChainLog

logger = logging.getLogger(__name__)


class MCPInterceptor:
    """Mediates MCP JSON-RPC 2.0 messages between MCP clients and servers."""

    def __init__(
        self,
        evaluator: PolicyEvaluator,
        session: Optional[SessionTracker] = None,
        pinner: Optional[ToolDescriptionPinner] = None,
        audit_log: Optional[HashChainLog] = None,
        strict_pinning: bool = False,
    ):
        self.evaluator = evaluator
        self.session = session or SessionTracker(evaluator=evaluator)
        self.pinner = pinner or ToolDescriptionPinner()
        self.audit_log = audit_log
        self.strict_pinning = strict_pinning
        self.tampered_tools: set[str] = set()
        self._pending_calls: Dict[Any, Dict[str, Any]] = {}
        self._pending_list_id: Optional[Any] = None

    def handle_client_message(
        self,
        msg: Any,
    ) -> Tuple[Optional[Dict[str, Any]], Optional[Dict[str, Any]]]:
        """Processes an incoming JSON-RPC message from the client.

        Returns:
            (forward_to_server, immediate_client_response)
        """
        if not isinstance(msg, dict):
            return None, {
                "jsonrpc": "2.0",
                "id": None,
                "error": {"code": -32600, "message": "Invalid Request: expected JSON object"},
            }

        method = msg.get("method")
        msg_id = msg.get("id")

        if method == "tools/list":
            self._pending_list_id = msg_id
            return msg, None

        if method == "tools/call":
            params = msg.get("params", {})
            if not isinstance(params, dict):
                return None, {
                    "jsonrpc": "2.0",
                    "id": msg_id,
                    "error": {"code": -32602, "message": "Invalid params: expected object"},
                }
            tool_name = params.get("name", "")
            arguments = params.get("arguments", {})
            if not isinstance(arguments, dict):
                arguments = {}

            # Block execution of tampered tools
            if tool_name in self.tampered_tools:
                return None, {
                    "jsonrpc": "2.0",
                    "id": msg_id,
                    "error": {
                        "code": -32004,
                        "message": f"Tool '{tool_name}' is disabled due to tool description tampering",
                    },
                }

            # Strict pinning: reject calls to unpinned tools
            if self.strict_pinning and self.pinner.pinned_hashes and tool_name not in self.pinner.pinned_hashes:
                return None, {
                    "jsonrpc": "2.0",
                    "id": msg_id,
                    "error": {
                        "code": -32004,
                        "message": f"Strict pinning violation: tool '{tool_name}' has not been pinned",
                    },
                }

            # Evaluate against reference monitor policy
            decision = self.session.evaluate_tool_call(tool_name, arguments)

            # Record audit decision event
            if self.audit_log:
                ev = ProvenanceEvent(
                    session_id=self.session.session_id,
                    event_type=ProvenanceEventType.DECISION_EVALUATED,
                    label=self.session.context_label,
                    details={
                        "tool": tool_name,
                        "arguments": arguments,
                        "verdict": decision.type.value,
                        "reason": decision.reason,
                    },
                )
                self.audit_log.append(ev)

            if decision.type == DecisionType.DENY:
                logger.warning(f"[TaintGate Interceptor] BLOCKED {tool_name}: {decision.reason}")
                err_resp = {
                    "jsonrpc": "2.0",
                    "id": msg_id,
                    "error": {
                        "code": -32003,
                        "message": f"Blocked by TaintGate reference monitor: {decision.reason}",
                        "data": {
                            "tool": tool_name,
                            "explanation": decision.explanation,
                            "rule_id": decision.rule_id,
                        },
                    },
                }
                return None, err_resp

            if decision.type == DecisionType.APPROVE:
                err_resp = {
                    "jsonrpc": "2.0",
                    "id": msg_id,
                    "error": {
                        "code": -32002,
                        "message": f"Requires human approval: {decision.reason}",
                        "data": {
                            "tool": tool_name,
                            "explanation": decision.explanation,
                            "rule_id": decision.rule_id,
                        },
                    },
                }
                return None, err_resp

            # Handle REDACT: forward sanitized arguments to server
            forward_msg = msg
            effective_args = arguments
            if decision.type == DecisionType.REDACT and decision.redacted_arguments is not None:
                effective_args = decision.redacted_arguments
                forward_params = dict(params)
                forward_params["arguments"] = effective_args
                forward_msg = dict(msg)
                forward_msg["params"] = forward_params

            if msg_id is not None:
                self._pending_calls[msg_id] = {
                    "tool": tool_name,
                    "arguments": effective_args,
                    "decision": decision,
                }
            return forward_msg, None

        if method == "resources/read":
            params = msg.get("params", {})
            uri = params.get("uri", "") if isinstance(params, dict) else ""
            decision = self.session.evaluate_tool_call("resources.read", {"uri": uri})
            if decision.type == DecisionType.DENY:
                return None, {
                    "jsonrpc": "2.0",
                    "id": msg_id,
                    "error": {
                        "code": -32003,
                        "message": f"Blocked by TaintGate reference monitor: {decision.reason}",
                    },
                }
            if decision.type == DecisionType.APPROVE:
                return None, {
                    "jsonrpc": "2.0",
                    "id": msg_id,
                    "error": {
                        "code": -32002,
                        "message": f"Requires human approval: {decision.reason}",
                    },
                }
            if msg_id is not None:
                self._pending_calls[msg_id] = {
                    "tool": "resources.read",
                    "arguments": {"uri": uri},
                    "decision": decision,
                }
            return msg, None

        if method == "prompts/get":
            params = msg.get("params", {})
            name = params.get("name", "") if isinstance(params, dict) else ""
            args = params.get("arguments", {}) if (isinstance(params, dict) and isinstance(params.get("arguments"), dict)) else {}
            decision = self.session.evaluate_tool_call("prompts.get", {"name": name, **args})
            if decision.type == DecisionType.DENY:
                return None, {
                    "jsonrpc": "2.0",
                    "id": msg_id,
                    "error": {
                        "code": -32003,
                        "message": f"Blocked by TaintGate reference monitor: {decision.reason}",
                    },
                }
            if decision.type == DecisionType.APPROVE:
                return None, {
                    "jsonrpc": "2.0",
                    "id": msg_id,
                    "error": {
                        "code": -32002,
                        "message": f"Requires human approval: {decision.reason}",
                    },
                }
            if msg_id is not None:
                self._pending_calls[msg_id] = {
                    "tool": "prompts.get",
                    "arguments": {"name": name, **args},
                    "decision": decision,
                }
            return msg, None

        # Pass through all other messages (e.g. initialize, notifications)
        return msg, None

    def handle_server_message(self, msg: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Processes an incoming JSON-RPC response from the server.

        Returns:
            forward_to_client
        """
        msg_id = msg.get("id")

        # Intercept tools/list RESPONSE for description pinning. A JSON-RPC response has a
        # "result"/"error" and no "method"; a server->client *request* (e.g. roots/list,
        # sampling/createMessage) may legally reuse the client's id space. We must not mistake
        # such a request for the tools/list response, or a server could evade pinning by emitting
        # an id-colliding request just before the rug-pulled result (CVE-class id confusion).
        is_response = ("method" not in msg) and ("result" in msg or "error" in msg)
        if msg_id is not None and msg_id == self._pending_list_id and is_response:
            self._pending_list_id = None
            tools = msg.get("result", {}).get("tools", [])
            valid, mismatches = self.pinner.verify_tools(tools)
            if not valid:
                logger.error(f"[TaintGate Interceptor] Tool description tampering detected: {mismatches}")
                for mismatch in mismatches:
                    parts = mismatch.split(": ", 1)
                    if len(parts) == 2:
                        self.tampered_tools.add(parts[1].strip())
                return {
                    "jsonrpc": "2.0",
                    "id": msg_id,
                    "error": {
                        "code": -32004,
                        "message": "Tool description pinning violation: tool schema modified without authorization",
                        "data": {"mismatches": mismatches},
                    },
                }

        # Intercept tools/call response to label output and update session taint
        if msg_id is not None and msg_id in self._pending_calls:
            call_info = self._pending_calls.pop(msg_id)
            tool_name = call_info["tool"]
            arguments = call_info["arguments"]

            # Compute output label based on tool configuration and argument overrides
            output_label = self.evaluator.resolve_tool_output_label(tool_name, arguments)
            result_data = msg.get("result")

            self.session.record_tool_result(tool_name, arguments, output_label)

            if self.audit_log:
                ev = ProvenanceEvent(
                    session_id=self.session.session_id,
                    event_type=ProvenanceEventType.TOOL_RESULT,
                    label=output_label,
                    details={
                        "tool": tool_name,
                        "arguments": arguments,
                        "output_summary": str(result_data)[:200],
                    },
                )
                self.audit_log.append(ev)

        return msg
