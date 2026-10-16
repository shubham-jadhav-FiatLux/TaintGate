"""Golden decision tests for policy engine and presets (M0 Milestone Requirement: 30+ tests)."""

import pytest
from taintgate.core.lattice import Label, IntegrityLevel, ConfidentialityLevel
from taintgate.core.labels import (
    LABEL_TRUSTED_PUBLIC,
    LABEL_TRUSTED_INTERNAL,
    LABEL_TRUSTED_SECRET,
    LABEL_UNTRUSTED_PUBLIC,
    LABEL_UNTRUSTED_INTERNAL,
    LABEL_UNTRUSTED_SECRET,
)
from taintgate.core.decisions import ActionEffect, DecisionRequest, DecisionType
from taintgate.core.policy.schema import (
    TaintGateConfig,
    ToolConfig,
    ToolOverride,
    ToolOutputAnnotation,
    RuleDefinition,
    PolicySection,
)
from taintgate.core.policy.evaluator import PolicyEvaluator
from taintgate.session.context import SessionTracker


@pytest.fixture
def base_policy_config() -> TaintGateConfig:
    return TaintGateConfig(
        tools={
            "fs.read_file": ToolConfig(
                effect="read",
                output=ToolOutputAnnotation(integrity="trusted", confidentiality="internal"),
                overrides=[
                    ToolOverride(path="~/company/secrets/**", confidentiality="secret"),
                    ToolOverride(path="**/resume.txt", integrity="untrusted"),
                ],
            ),
            "fs.write_file": ToolConfig(effect="local_write"),
            "email.send": ToolConfig(effect="external", recipients_arg="to"),
            "db.delete_table": ToolConfig(effect="irreversible"),
            "web.fetch": ToolConfig(
                effect="read",
                output=ToolOutputAnnotation(integrity="untrusted", confidentiality="public"),
            ),
            "fs.*": ToolConfig(effect="read"),
        },
        policy=PolicySection(
            preset="rule_of_two",
            contacts=["colleague@example.com", "boss@example.com"],
            rules=[
                RuleDefinition(
                    deny="external",
                    when="data.confidentiality >= internal and recipient not in contacts",
                ),
                RuleDefinition(
                    redact="external",
                    when="data.confidentiality >= secret and recipient in contacts",
                ),
            ],
        ),
    )


class TestGoldenPolicyDecisions:

    # 1. Benign read with trusted public context
    def test_01_benign_read_trusted_public(self, base_policy_config):
        evaluator = PolicyEvaluator(base_policy_config)
        req = DecisionRequest(
            tool_name="fs.read_file",
            arguments={"path": "notes.txt"},
            effect=ActionEffect.READ,
            session_id="s1",
            session_context_label=LABEL_TRUSTED_PUBLIC,
        )
        dec = evaluator.evaluate(req)
        assert dec.type == DecisionType.ALLOW

    # 2. Benign read with trusted internal context
    def test_02_benign_read_trusted_internal(self, base_policy_config):
        evaluator = PolicyEvaluator(base_policy_config)
        req = DecisionRequest(
            tool_name="fs.read_file",
            arguments={"path": "notes.txt"},
            effect=ActionEffect.READ,
            session_id="s1",
            session_context_label=LABEL_TRUSTED_INTERNAL,
        )
        dec = evaluator.evaluate(req)
        assert dec.type == DecisionType.ALLOW

    # 3. Benign local write with trusted public context
    def test_03_benign_write_trusted_public(self, base_policy_config):
        evaluator = PolicyEvaluator(base_policy_config)
        req = DecisionRequest(
            tool_name="fs.write_file",
            arguments={"path": "out.txt", "content": "hello"},
            effect=ActionEffect.LOCAL_WRITE,
            session_id="s1",
            session_context_label=LABEL_TRUSTED_PUBLIC,
        )
        dec = evaluator.evaluate(req)
        assert dec.type == DecisionType.ALLOW

    # 4. Benign local write with trusted internal context
    def test_04_benign_write_trusted_internal(self, base_policy_config):
        evaluator = PolicyEvaluator(base_policy_config)
        req = DecisionRequest(
            tool_name="fs.write_file",
            arguments={"path": "out.txt", "content": "hello"},
            effect=ActionEffect.LOCAL_WRITE,
            session_id="s1",
            session_context_label=LABEL_TRUSTED_INTERNAL,
        )
        dec = evaluator.evaluate(req)
        assert dec.type == DecisionType.ALLOW

    # 5. Untrusted context attempting read
    def test_05_untrusted_context_read(self, base_policy_config):
        evaluator = PolicyEvaluator(base_policy_config)
        req = DecisionRequest(
            tool_name="fs.read_file",
            arguments={"path": "public.txt"},
            effect=ActionEffect.READ,
            session_id="s1",
            session_context_label=LABEL_UNTRUSTED_PUBLIC,
        )
        dec = evaluator.evaluate(req)
        assert dec.type == DecisionType.ALLOW

    # 6. Untrusted context attempting local write (Rule of Two side effect -> APPROVE)
    def test_06_untrusted_context_local_write(self, base_policy_config):
        evaluator = PolicyEvaluator(base_policy_config)
        req = DecisionRequest(
            tool_name="fs.write_file",
            arguments={"path": "config.yaml", "content": "bad"},
            effect=ActionEffect.LOCAL_WRITE,
            session_id="s1",
            session_context_label=LABEL_UNTRUSTED_PUBLIC,
        )
        dec = evaluator.evaluate(req)
        assert dec.type == DecisionType.APPROVE

    # 7. Untrusted context attempting irreversible action (Rule of Two side effect -> APPROVE)
    def test_07_untrusted_context_irreversible_action(self, base_policy_config):
        evaluator = PolicyEvaluator(base_policy_config)
        req = DecisionRequest(
            tool_name="db.delete_table",
            arguments={"table": "temp_logs"},
            effect=ActionEffect.IRREVERSIBLE,
            session_id="s1",
            session_context_label=LABEL_UNTRUSTED_PUBLIC,
        )
        dec = evaluator.evaluate(req)
        assert dec.type == DecisionType.APPROVE

    # 8. Untrusted context + public data attempting external send (Rule of Two -> APPROVE)
    def test_08_untrusted_context_external_public(self, base_policy_config):
        evaluator = PolicyEvaluator(base_policy_config)
        req = DecisionRequest(
            tool_name="email.send",
            arguments={"to": "external@example.com", "body": "hi"},
            effect=ActionEffect.EXTERNAL,
            session_id="s1",
            session_context_label=LABEL_UNTRUSTED_PUBLIC,
        )
        dec = evaluator.evaluate(req)
        assert dec.type == DecisionType.APPROVE

    # 9. Untrusted context + internal confidentiality attempting external send (Rule of Two violation -> DENY)
    def test_09_untrusted_internal_external_denied(self, base_policy_config):
        evaluator = PolicyEvaluator(base_policy_config)
        req = DecisionRequest(
            tool_name="email.send",
            arguments={"to": "attacker@example.com", "body": "data"},
            effect=ActionEffect.EXTERNAL,
            session_id="s1",
            session_context_label=LABEL_UNTRUSTED_INTERNAL,
        )
        dec = evaluator.evaluate(req)
        assert dec.type == DecisionType.DENY

    # 10. Untrusted context + secret data attempting external send (Rule of Two violation -> DENY)
    def test_10_untrusted_secret_external_denied(self, base_policy_config):
        evaluator = PolicyEvaluator(base_policy_config)
        req = DecisionRequest(
            tool_name="email.send",
            arguments={"to": "attacker@example.com", "body": "secret"},
            effect=ActionEffect.EXTERNAL,
            session_id="s1",
            session_context_label=LABEL_UNTRUSTED_SECRET,
        )
        dec = evaluator.evaluate(req)
        assert dec.type == DecisionType.DENY

    # 11. Untrusted context + secret data attempting irreversible action (Rule of Two violation -> DENY)
    def test_11_untrusted_secret_irreversible_denied(self, base_policy_config):
        evaluator = PolicyEvaluator(base_policy_config)
        req = DecisionRequest(
            tool_name="db.delete_table",
            arguments={"table": "finance"},
            effect=ActionEffect.IRREVERSIBLE,
            session_id="s1",
            session_context_label=LABEL_UNTRUSTED_SECRET,
        )
        dec = evaluator.evaluate(req)
        assert dec.type == DecisionType.DENY

    # 12. Trusted context + internal data attempting external send to allowed contact (ALLOW)
    def test_12_trusted_internal_allowed_contact(self, base_policy_config):
        evaluator = PolicyEvaluator(base_policy_config)
        req = DecisionRequest(
            tool_name="email.send",
            arguments={"to": "colleague@example.com", "body": "report"},
            effect=ActionEffect.EXTERNAL,
            session_id="s1",
            session_context_label=LABEL_TRUSTED_INTERNAL,
        )
        dec = evaluator.evaluate(req)
        assert dec.type == DecisionType.ALLOW

    # 13. Trusted context + internal data attempting external send to non-contact (DENIED via rule)
    def test_13_trusted_internal_non_contact_denied(self, base_policy_config):
        evaluator = PolicyEvaluator(base_policy_config)
        req = DecisionRequest(
            tool_name="email.send",
            arguments={"to": "stranger@unknown.net", "body": "report"},
            effect=ActionEffect.EXTERNAL,
            session_id="s1",
            session_context_label=LABEL_TRUSTED_INTERNAL,
        )
        dec = evaluator.evaluate(req)
        assert dec.type == DecisionType.DENY

    # 14. Read-only preset: read of a KNOWN, non-egress read tool is allowed.
    #     (An *unknown* tool is denied under the fail-closed default, which tests 15-17 and
    #     the dedicated unknown-tool tests cover; here we exercise the preset itself.)
    def test_14_read_only_preset_read_allowed(self):
        cfg = TaintGateConfig(
            tools={"fs.read": ToolConfig(effect="read", egress=False)},
            policy=PolicySection(preset="read_only_browsing"),
        )
        evaluator = PolicyEvaluator(cfg)
        req = DecisionRequest(
            tool_name="fs.read",
            arguments={},
            effect=ActionEffect.READ,
            session_id="s",
            session_context_label=LABEL_TRUSTED_PUBLIC,
        )
        assert evaluator.evaluate(req).type == DecisionType.ALLOW

    # 15. Read-only preset: write denied
    def test_15_read_only_preset_write_denied(self):
        cfg = TaintGateConfig(policy=PolicySection(preset="read_only_browsing"))
        evaluator = PolicyEvaluator(cfg)
        req = DecisionRequest(
            tool_name="fs.write",
            arguments={},
            effect=ActionEffect.LOCAL_WRITE,
            session_id="s",
            session_context_label=LABEL_TRUSTED_PUBLIC,
        )
        assert evaluator.evaluate(req).type == DecisionType.DENY

    # 16. Read-only preset: external denied
    def test_16_read_only_preset_external_denied(self):
        cfg = TaintGateConfig(policy=PolicySection(preset="read_only_browsing"))
        evaluator = PolicyEvaluator(cfg)
        req = DecisionRequest(
            tool_name="http.post",
            arguments={},
            effect=ActionEffect.EXTERNAL,
            session_id="s",
            session_context_label=LABEL_TRUSTED_PUBLIC,
        )
        assert evaluator.evaluate(req).type == DecisionType.DENY

    # 17. Read-only preset: irreversible denied
    def test_17_read_only_preset_irreversible_denied(self):
        cfg = TaintGateConfig(policy=PolicySection(preset="read_only_browsing"))
        evaluator = PolicyEvaluator(cfg)
        req = DecisionRequest(
            tool_name="delete.all",
            arguments={},
            effect=ActionEffect.IRREVERSIBLE,
            session_id="s",
            session_context_label=LABEL_TRUSTED_PUBLIC,
        )
        assert evaluator.evaluate(req).type == DecisionType.DENY

    # 18. Strict exfiltration guard: public external allowed
    def test_18_strict_exfil_public_allowed(self):
        cfg = TaintGateConfig(policy=PolicySection(preset="strict_exfil_guard"))
        evaluator = PolicyEvaluator(cfg)
        req = DecisionRequest(
            tool_name="http.get",
            arguments={},
            effect=ActionEffect.EXTERNAL,
            session_id="s",
            session_context_label=LABEL_TRUSTED_PUBLIC,
        )
        assert evaluator.evaluate(req).type == DecisionType.ALLOW

    # 19. Strict exfiltration guard: internal external denied
    def test_19_strict_exfil_internal_denied(self):
        cfg = TaintGateConfig(policy=PolicySection(preset="strict_exfil_guard"))
        evaluator = PolicyEvaluator(cfg)
        req = DecisionRequest(
            tool_name="http.post",
            arguments={},
            effect=ActionEffect.EXTERNAL,
            session_id="s",
            session_context_label=LABEL_TRUSTED_INTERNAL,
        )
        assert evaluator.evaluate(req).type == DecisionType.DENY

    # 20. Strict exfiltration guard: secret external denied
    def test_20_strict_exfil_secret_denied(self):
        cfg = TaintGateConfig(policy=PolicySection(preset="strict_exfil_guard"))
        evaluator = PolicyEvaluator(cfg)
        req = DecisionRequest(
            tool_name="http.post",
            arguments={},
            effect=ActionEffect.EXTERNAL,
            session_id="s",
            session_context_label=LABEL_TRUSTED_SECRET,
        )
        assert evaluator.evaluate(req).type == DecisionType.DENY

    # 21. Path override: secrets folder marked SECRET
    def test_21_path_override_secrets(self, base_policy_config):
        evaluator = PolicyEvaluator(base_policy_config)
        lbl = evaluator.resolve_tool_output_label("fs.read_file", {"path": "~/company/secrets/q3.txt"})
        assert lbl.confidentiality == ConfidentialityLevel.SECRET

    # 22. Path override: resume marked UNTRUSTED
    def test_22_path_override_resume(self, base_policy_config):
        evaluator = PolicyEvaluator(base_policy_config)
        lbl = evaluator.resolve_tool_output_label("fs.read_file", {"path": "uploads/resume.txt"})
        assert lbl.integrity == IntegrityLevel.UNTRUSTED

    # 23. Path override wildcard matching
    def test_23_path_override_wildcard(self, base_policy_config):
        evaluator = PolicyEvaluator(base_policy_config)
        lbl = evaluator.resolve_tool_output_label("fs.read_file", {"path": "~/company/secrets/2026/plans.docx"})
        assert lbl.confidentiality == ConfidentialityLevel.SECRET

    # 24. Session-scoped grant allows second identical call
    def test_24_scoped_grant_session(self, base_policy_config):
        evaluator = PolicyEvaluator(base_policy_config)
        session = SessionTracker(evaluator=evaluator)
        session.add_user_turn("hello")
        session.record_tool_result("web.fetch", {}, LABEL_UNTRUSTED_PUBLIC)

        # Initial call requires approval
        dec1 = session.evaluate_tool_call("fs.write_file", {"path": "log.txt"})
        assert dec1.type == DecisionType.APPROVE

        # Human grants session-scoped approval
        from taintgate.core.approval import GrantScope
        session.grant_approval("fs.write_file", {"path": "log.txt"}, scope=GrantScope.SESSION)

        # Subsequent identical call is ALLOWED
        dec2 = session.evaluate_tool_call("fs.write_file", {"path": "log.txt"})
        assert dec2.type == DecisionType.ALLOW

    # 25. Scoped grant for tool A does not allow tool B
    def test_25_scoped_grant_isolation_tools(self, base_policy_config):
        evaluator = PolicyEvaluator(base_policy_config)
        session = SessionTracker(evaluator=evaluator)
        session.record_tool_result("web.fetch", {}, LABEL_UNTRUSTED_PUBLIC)
        session.grant_approval("fs.write_file", {"path": "log.txt"})

        dec = session.evaluate_tool_call("db.delete_table", {"table": "logs"})
        assert dec.type == DecisionType.APPROVE

    # 26. Scoped grant with different arguments requires approval
    def test_26_scoped_grant_isolation_args(self, base_policy_config):
        evaluator = PolicyEvaluator(base_policy_config)
        session = SessionTracker(evaluator=evaluator)
        session.record_tool_result("web.fetch", {}, LABEL_UNTRUSTED_PUBLIC)
        session.grant_approval("fs.write_file", {"path": "log.txt"})

        dec = session.evaluate_tool_call("fs.write_file", {"path": "other.txt"})
        assert dec.type == DecisionType.APPROVE

    # 27. Redact rule triggers REDACT verdict
    def test_27_redact_rule_verdict(self, base_policy_config):
        evaluator = PolicyEvaluator(base_policy_config)
        req = DecisionRequest(
            tool_name="email.send",
            arguments={"to": "colleague@example.com", "body": "secret credentials"},
            effect=ActionEffect.EXTERNAL,
            session_id="s1",
            session_context_label=LABEL_TRUSTED_SECRET,
        )
        dec = evaluator.evaluate(req)
        assert dec.type == DecisionType.REDACT

    # 28. Custom unconditional deny rule
    def test_28_unconditional_deny(self):
        cfg = TaintGateConfig(
            policy=PolicySection(
                preset=None,
                rules=[RuleDefinition(deny="external")],
            )
        )
        evaluator = PolicyEvaluator(cfg)
        req = DecisionRequest(
            tool_name="any_ext",
            arguments={},
            effect=ActionEffect.EXTERNAL,
            session_id="s",
            session_context_label=LABEL_TRUSTED_PUBLIC,
        )
        assert evaluator.evaluate(req).type == DecisionType.DENY

    # 29. Custom unconditional approve rule
    def test_29_unconditional_approve(self):
        cfg = TaintGateConfig(
            policy=PolicySection(
                preset=None,
                rules=[RuleDefinition(approve="local_write")],
            )
        )
        evaluator = PolicyEvaluator(cfg)
        req = DecisionRequest(
            tool_name="any_write",
            arguments={},
            effect=ActionEffect.LOCAL_WRITE,
            session_id="s",
            session_context_label=LABEL_TRUSTED_PUBLIC,
        )
        assert evaluator.evaluate(req).type == DecisionType.APPROVE

    # 30. Tool pattern matching: wildcard fs.*
    def test_30_tool_wildcard_matching(self, base_policy_config):
        evaluator = PolicyEvaluator(base_policy_config)
        cfg = evaluator.get_tool_config("fs.custom_read")
        assert cfg.effect == "read"

    # 31. Fallback for unannotated tool defaults to effect=read
    def test_31_unannotated_tool_fallback(self, base_policy_config):
        evaluator = PolicyEvaluator(base_policy_config)
        cfg = evaluator.get_tool_config("completely_unknown_tool")
        assert cfg.effect == "read"

    # 32. Multi-turn taint tracking and backward explanation
    def test_32_multiturn_flow_explanation(self, base_policy_config):
        evaluator = PolicyEvaluator(base_policy_config)
        session = SessionTracker(evaluator=evaluator)
        session.add_user_turn("Process resume")
        session.record_tool_result("fs.read_file", {"path": "resume.txt"}, LABEL_UNTRUSTED_PUBLIC)
        session.record_tool_result("fs.read_file", {"path": "~/company/secrets/q3.txt"}, LABEL_TRUSTED_SECRET)

        assert session.context_label.integrity == IntegrityLevel.UNTRUSTED
        assert session.context_label.confidentiality == ConfidentialityLevel.SECRET

        dec = session.evaluate_tool_call("email.send", {"to": "evil@hacker.com"})
        assert dec.type == DecisionType.DENY
        assert "Target Sink" in dec.explanation
        assert "resume.txt" in dec.explanation or "fs.read_file" in dec.explanation
