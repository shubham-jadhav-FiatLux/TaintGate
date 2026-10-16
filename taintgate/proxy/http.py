"""Streamable HTTP / SSE Model Context Protocol (MCP) Proxy Handler (Experimental Stub).

NOTE: This module is an experimental stub for HTTP/SSE message mediation. Production deployments
must use the Unix domain socket PDP service (UnixSocketPDPServer) or stdio proxy (StdioMCPProxy).
Full HTTP/SSE streaming transport is not yet implemented.
"""

from __future__ import annotations

from typing import Any, Dict, Optional
from taintgate.core.policy.evaluator import PolicyEvaluator
from taintgate.proxy.interceptor import MCPInterceptor


class HttpMCPProxyHandler:
    """Experimental stub mediating HTTP/SSE-based MCP JSON-RPC requests."""

    def __init__(self, evaluator: PolicyEvaluator):
        self.evaluator = evaluator
        self.interceptor = MCPInterceptor(evaluator=evaluator)

    def process_request(self, request_json: Dict[str, Any]) -> Dict[str, Any]:
        """Processes an incoming JSON-RPC HTTP POST body."""
        forward, immediate_resp = self.interceptor.handle_client_message(request_json)
        if immediate_resp:
            return immediate_resp
        return {"forward": True, "payload": forward}
