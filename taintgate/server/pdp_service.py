"""Unix-Socket Policy Decision Point (PDP) Service Mode.

Enables out-of-process mediation by any Policy Enforcement Point (PEP) with identical
message formats between in-process Python and Unix domain socket RPC.
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Any, Dict, Optional
import os

from taintgate.core.lattice import Label, IntegrityLevel, ConfidentialityLevel
from taintgate.core.decisions import (
    ActionEffect,
    Decision,
    DecisionRequest,
    DecisionType,
    CapabilityToken,
)
from taintgate.core.policy.evaluator import PolicyEvaluator


def serialize_decision_request(req: DecisionRequest) -> Dict[str, Any]:
    return {
        "tool_name": req.tool_name,
        "arguments": req.arguments,
        "effect": req.effect.value,
        "session_id": req.session_id,
        "session_context_label": req.session_context_label.to_dict(),
        "argument_labels": {k: v.to_dict() for k, v in req.argument_labels.items()},
        "recipients": req.recipients,
        "provenance_node_id": req.provenance_node_id,
    }


def deserialize_decision_request(data: Dict[str, Any]) -> DecisionRequest:
    ctx_label = Label.from_dict(data["session_context_label"])
    arg_labels: Dict[str, Label] = {
        k: Label.from_dict(v) for k, v in data.get("argument_labels", {}).items()
    }
    arguments = data.get("arguments", {})
    if not isinstance(arguments, dict):
        raise ValueError("DecisionRequest.arguments must be a JSON object")

    return DecisionRequest(
        tool_name=data["tool_name"],
        arguments=arguments,
        effect=ActionEffect.from_str(data["effect"]),
        session_id=data["session_id"],
        session_context_label=ctx_label,
        argument_labels=arg_labels,
        recipients=data.get("recipients"),
        provenance_node_id=data.get("provenance_node_id"),
    )


def serialize_decision(dec: Decision) -> Dict[str, Any]:
    res: Dict[str, Any] = {
        "type": dec.type.value,
        "reason": dec.reason,
        "rule_id": dec.rule_id,
        "explanation": dec.explanation,
        "redacted_arguments": dec.redacted_arguments,
    }
    if dec.capability_token:
        res["capability_token"] = {
            "token_id": dec.capability_token.token_id,
            "tool_name": dec.capability_token.tool_name,
            "scope_hash": dec.capability_token.scope_hash,
            "issued_at": dec.capability_token.issued_at,
            "expires_at": dec.capability_token.expires_at,
            "signature": dec.capability_token.signature,
        }
    return res


def deserialize_decision(data: Dict[str, Any]) -> Decision:
    token = None
    tok_data = data.get("capability_token")
    if tok_data:
        token = CapabilityToken(
            token_id=tok_data["token_id"],
            tool_name=tok_data["tool_name"],
            scope_hash=tok_data["scope_hash"],
            issued_at=tok_data["issued_at"],
            expires_at=tok_data["expires_at"],
            signature=tok_data["signature"],
        )

    return Decision(
        type=DecisionType(data["type"]),
        reason=data["reason"],
        rule_id=data.get("rule_id"),
        explanation=data.get("explanation", ""),
        redacted_arguments=data.get("redacted_arguments"),
        capability_token=token,
    )


class UnixSocketPDPServer:
    """Out-of-process Policy Decision Point (PDP) daemon serving requests over a Unix socket."""

    def __init__(self, evaluator: PolicyEvaluator, socket_path: Path):
        self.evaluator = evaluator
        self.socket_path = Path(socket_path)
        self.server: Optional[asyncio.Server] = None

    async def start(self) -> None:
        if self.socket_path.exists():
            self.socket_path.unlink()

        self.socket_path.parent.mkdir(parents=True, exist_ok=True)
        self.server = await asyncio.start_unix_server(self._handle_client, path=str(self.socket_path))

    async def stop(self) -> None:
        if self.server:
            self.server.close()
            await self.server.wait_closed()
        if self.socket_path.exists():
            self.socket_path.unlink()

    async def _handle_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        while True:
            line = await reader.readline()
            if not line:
                break
            line_str = line.decode("utf-8").strip()
            if not line_str:
                continue

            try:
                req_data = json.loads(line_str)
                req = deserialize_decision_request(req_data)
                dec = self.evaluator.evaluate(req)
                resp_data = serialize_decision(dec)
                resp_str = json.dumps(resp_data, sort_keys=True) + "\n"
                writer.write(resp_str.encode("utf-8"))
                await writer.drain()
            except Exception as e:
                err_resp = {"type": "deny", "reason": f"PDP RPC Error: {str(e)}", "explanation": ""}
                writer.write((json.dumps(err_resp) + "\n").encode("utf-8"))
                await writer.drain()

        writer.close()
        await writer.wait_closed()


class UnixSocketPDPClient:
    """Client for querying the out-of-process UnixSocketPDPServer."""

    def __init__(self, socket_path: Path):
        self.socket_path = Path(socket_path)

    async def decide(self, request: DecisionRequest) -> Decision:
        reader, writer = await asyncio.open_unix_connection(path=str(self.socket_path))
        payload = serialize_decision_request(request)
        writer.write((json.dumps(payload) + "\n").encode("utf-8"))
        await writer.drain()

        line = await reader.readline()
        writer.close()
        await writer.wait_closed()

        resp_data = json.loads(line.decode("utf-8").strip())
        return deserialize_decision(resp_data)
