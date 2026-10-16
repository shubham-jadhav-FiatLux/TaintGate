"""Deterministic Policy Evaluator.

Evaluates DecisionRequests against configured presets, custom rules,
and sound information-flow lattice constraints.
"""

from __future__ import annotations

import fnmatch
import logging
import os
from pathlib import Path
import re
import secrets
from typing import Any, Dict, FrozenSet, List, Optional, Set, Tuple
from urllib.parse import urlparse

from taintgate.core.lattice import Label, IntegrityLevel, ConfidentialityLevel
from taintgate.core.decisions import (
    ActionEffect,
    Decision,
    DecisionRequest,
    DecisionType,
    CapabilityToken,
)
from taintgate.core.policy.schema import TaintGateConfig, ToolConfig, ToolOutputAnnotation
from taintgate.core.policy.dsl import compile_condition, EvalEnv, PolicyDSLError

logger = logging.getLogger(__name__)

# Standard path-like argument keys
PATH_ARG_KEYS = ("path", "file_path", "filepath", "filename", "file", "dest_path", "src_path", "target_path")

# Email regex for scanning string arguments for embedded recipient addresses
EMAIL_REGEX = re.compile(r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+")


def extract_destinations(
    request: DecisionRequest,
    tool_cfg: ToolConfig,
) -> FrozenSet[str]:
    """Extracts all destinations (email recipients, hostnames, URLs) from request arguments.

    Extracts from:
    1. request.recipients (if explicitly supplied)
    2. Any argument listed in tool_cfg.all_recipient_args() (to, cc, bcc, recipient, etc.)
    3. Any argument listed in tool_cfg.all_url_args() (url, endpoint, host, etc.)
    4. String values in arguments that contain email addresses or URLs
    """
    destinations: Set[str] = set()

    # 1. Explicit recipients
    if request.recipients:
        for r in request.recipients:
            if isinstance(r, str):
                for part in r.split(","):
                    p = part.strip().lower()
                    if p:
                        destinations.add(p)

    # 2. Recipient arguments
    recipient_arg_names = set(tool_cfg.all_recipient_args())
    url_arg_names = set(tool_cfg.all_url_args())

    for k, v in request.arguments.items():
        k_lower = k.lower()
        if k_lower in recipient_arg_names:
            _collect_dest_values(v, destinations)
        elif k_lower in url_arg_names:
            _collect_url_destinations(v, destinations)

    return frozenset(destinations)


def _collect_dest_values(val: Any, out: Set[str]) -> None:
    if isinstance(val, str):
        for part in val.split(","):
            p = part.strip().lower()
            if p:
                out.add(p)
    elif isinstance(val, (list, tuple, set, frozenset)):
        for item in val:
            _collect_dest_values(item, out)
    elif isinstance(val, dict):
        for item in val.values():
            _collect_dest_values(item, out)


def _collect_url_destinations(val: Any, out: Set[str]) -> None:
    if isinstance(val, str):
        v_clean = val.strip()
        try:
            parsed = urlparse(v_clean)
            # ``hostname`` strips any ``user:pass@`` userinfo and ``:port`` suffix, so a URL
            # such as ``https://trusted.example:443@evil.com/x`` resolves to ``evil.com`` and
            # cannot be laundered past an allowed_domains check by embedding an allowed host
            # in the userinfo component.
            host = parsed.hostname
            if host:
                out.add(host.lower())
                # Also surface the raw userinfo host (if any) so an allowlist rule that only
                # lists the *real* destination still fires; a mismatch between the two is
                # itself suspicious and will fail "every destination in allowed_domains".
                if "@" in parsed.netloc:
                    userinfo = parsed.netloc.rsplit("@", 1)[0].split(":")[0].strip().lower()
                    if userinfo:
                        out.add(userinfo)
            elif v_clean:
                out.add(v_clean.lower())
        except Exception:
            if v_clean:
                out.add(v_clean.lower())
    elif isinstance(val, (list, tuple, set, frozenset)):
        for item in val:
            _collect_url_destinations(item, out)


def is_egress_call(
    request: DecisionRequest,
    tool_cfg: ToolConfig,
    destinations: FrozenSet[str],
) -> bool:
    """Determines whether a tool invocation transmits data outside the local trust boundary."""
    if tool_cfg.egress is not None:
        return tool_cfg.egress
    if request.effect in (ActionEffect.EXTERNAL, ActionEffect.IRREVERSIBLE):
        return True
    if destinations:
        return True
    # Any tool starting with network/web prefixes is an egress sink
    tool_lower = request.tool_name.lower()
    if any(tool_lower.startswith(pfx) for pfx in ("web.", "http.", "curl.", "fetch.", "net.", "mail.", "email.")):
        return True
    return False


def normalize_and_match_path(arg_path: str, pattern: str) -> bool:
    """Matches a path argument against an override glob pattern with path normalization.

    Prevents path-traversal evasion like `~/company/./secrets/` or relative path escapes.
    """
    try:
        raw_arg = str(arg_path).strip()
        expanded_arg = os.path.expanduser(raw_arg)
        norm_arg = os.path.normpath(expanded_arg)
        abs_arg = os.path.abspath(norm_arg)

        raw_pattern = str(pattern).strip()
        expanded_pattern = os.path.expanduser(raw_pattern)
        norm_pattern = os.path.normpath(expanded_pattern)
        abs_pattern = os.path.abspath(norm_pattern)

        # 1. Direct fnmatch on normalized paths
        if fnmatch.fnmatch(norm_arg, norm_pattern) or fnmatch.fnmatch(abs_arg, abs_pattern):
            return True

        # 2. Match on original pattern
        if fnmatch.fnmatch(raw_arg, raw_pattern):
            return True

        # 3. Handle '**' directory prefixes
        clean_kw = raw_pattern.strip("*").strip("/").strip("\\")
        if clean_kw:
            # Check segment containment
            arg_parts = Path(norm_arg).parts
            kw_parts = Path(clean_kw).parts
            for i in range(len(arg_parts) - len(kw_parts) + 1):
                if arg_parts[i : i + len(kw_parts)] == kw_parts:
                    return True

        # 4. Relative to cwd check
        try:
            rel_to_cwd = os.path.relpath(abs_arg, os.getcwd())
            if fnmatch.fnmatch(rel_to_cwd, norm_pattern):
                return True
        except Exception:
            pass

        return False
    except Exception:
        return False


class PolicyEvaluator:
    """Evaluates DecisionRequests against configured presets and custom policy rules."""

    def __init__(self, config: TaintGateConfig, token_secret: Optional[bytes] = None):
        self.config = config
        # Cryptographically strong random key if none specified
        self.token_secret = token_secret or secrets.token_bytes(32)

    def is_known_tool(self, tool_name: str) -> bool:
        """Checks if a tool is explicitly configured or matches a configured pattern."""
        if tool_name in self.config.tools:
            return True
        for pattern in self.config.tools:
            if fnmatch.fnmatch(tool_name, pattern):
                return True
        return False

    def _effective_unknown_tools(self) -> str:
        """Resolves the ``unknown_tools`` policy, expanding the ``auto`` default.

        ``auto`` means: fail-closed (``deny``) when the policy annotates at least one tool
        (a missing tool is then a genuine omission), but ``pessimistic`` when no tools are
        annotated at all (a preset-only policy), so such a policy still functions while
        treating every unannotated call as ``irreversible`` + egress + ``untrusted|secret``
        rather than silently allowing it.
        """
        val = (self.config.policy.unknown_tools or "auto").lower()
        if val == "auto":
            return "deny" if self.config.tools else "pessimistic"
        return val

    def get_tool_config(self, tool_name: str) -> ToolConfig:
        """Looks up tool config, supporting wildcard patterns (e.g. 'fs.*')."""
        if tool_name in self.config.tools:
            return self.config.tools[tool_name]
        for pattern, cfg in self.config.tools.items():
            if fnmatch.fnmatch(tool_name, pattern):
                return cfg

        # Fallback for unannotated tools
        if self._effective_unknown_tools() == "pessimistic":
            return ToolConfig(
                effect="irreversible",
                egress=True,
                output=ToolOutputAnnotation(integrity="untrusted", confidentiality="secret"),
            )
        return ToolConfig(effect="read")

    def resolve_tool_output_label(self, tool_name: str, arguments: Dict[str, Any]) -> Label:
        """Determines the output label of a tool call based on annotations and overrides."""
        cfg = self.get_tool_config(tool_name)
        integ = IntegrityLevel.TRUSTED
        conf = ConfidentialityLevel.PUBLIC

        if cfg.output:
            integ = IntegrityLevel.from_str(cfg.output.integrity)
            conf = ConfidentialityLevel.from_str(cfg.output.confidentiality)

        # Check path overrides if path-like arguments exist
        path_arg = None
        for k in PATH_ARG_KEYS:
            if k in arguments and isinstance(arguments[k], str):
                path_arg = arguments[k]
                break

        if path_arg:
            for override in cfg.overrides:
                if normalize_and_match_path(path_arg, override.path):
                    if override.confidentiality:
                        conf = max(conf, ConfidentialityLevel.from_str(override.confidentiality))
                    if override.integrity:
                        integ = min(integ, IntegrityLevel.from_str(override.integrity))

        return Label(integrity=integ, confidentiality=conf)

    # Restrictiveness ordering used to combine the preset "floor" with custom rules.
    # A more restrictive verdict can never be relaxed by a less restrictive one, so a
    # custom ``allow`` rule can tighten nothing and, in particular, cannot override a
    # preset DENY/APPROVE (custom rules may only tighten, never weaken).
    _SEVERITY = {
        DecisionType.ALLOW: 0,
        DecisionType.REDACT: 1,
        DecisionType.APPROVE: 2,
        DecisionType.DENY: 3,
    }

    def _more_restrictive(self, a: Decision, b: Decision) -> Decision:
        """Returns whichever decision is at least as restrictive (ties favour ``a``)."""
        return a if self._SEVERITY[a.type] >= self._SEVERITY[b.type] else b

    def _effective_label(self, request: DecisionRequest) -> Label:
        """The effective flow label ``ℓ_ctx ⊔ ⨆_j ℓ_arg_j`` governing a call.

        Mirrors ``effectiveLabel`` in the Lean calculus: the join of the session context
        label with every argument label. Arguments can only raise taint, so no clean
        argument can launder a tainted context — keeping the Python monitor a refinement of
        the machine-checked theorems.
        """
        eff = request.session_context_label
        for lbl in (request.argument_labels or {}).values():
            eff = eff.join(lbl)
        return eff

    def evaluate(self, request: DecisionRequest) -> Decision:
        """Evaluates a request through Presets and Rules to produce a deterministic verdict.

        The verdict is the **most restrictive** of (1) the fail-closed unknown-tool check,
        (2) the active preset's "confinement floor", and (3) the first matching custom rule.
        Custom rules can therefore only tighten the floor; an ``allow`` rule never relaxes a
        preset DENY/APPROVE.
        """
        # 1. Unknown-tool fail-closed check (applies whether or not `tools:` is populated).
        if not self.is_known_tool(request.tool_name) and self._effective_unknown_tools() == "deny":
            return Decision(
                type=DecisionType.DENY,
                reason=f"Tool '{request.tool_name}' is not registered and policy denies unannotated tools (fail-closed).",
                rule_id="default.unknown_tool_deny",
            )

        tool_cfg = self.get_tool_config(request.tool_name)
        destinations = extract_destinations(request, tool_cfg)
        egress = is_egress_call(request, tool_cfg, destinations)

        # 2. Preset confinement floor (defaults to ALLOW when the preset is silent).
        floor = self._evaluate_preset(request, tool_cfg, destinations, egress) or Decision(
            type=DecisionType.ALLOW,
            reason="Conforms to standard policy",
            rule_id="default.allow",
        )

        # 3. Custom rules may only tighten the floor.
        custom = self._evaluate_custom_rules(request, tool_cfg, destinations, egress)
        decision = self._more_restrictive(floor, custom) if custom is not None else floor

        return self._enrich_decision(decision, request)

    def _evaluate_preset(
        self,
        request: DecisionRequest,
        tool_cfg: ToolConfig,
        destinations: FrozenSet[str],
        egress: bool,
    ) -> Optional[Decision]:
        """Evaluates the active preset, returning its verdict or ``None`` (= no constraint)."""
        preset = (self.config.policy.preset or "").lower()
        if preset == "rule_of_two":
            return self._evaluate_rule_of_two(request, tool_cfg, destinations, egress)
        if preset == "read_only_browsing":
            if request.effect != ActionEffect.READ or egress:
                return Decision(
                    type=DecisionType.DENY,
                    reason="Read-only browsing preset denies all state-changing or external/egress operations",
                    rule_id="preset.read_only",
                )
            return None
        if preset == "strict_exfil_guard":
            ctx = request.session_context_label
            eff_conf = ctx.confidentiality
            if request.argument_labels:
                eff_conf = max([eff_conf] + [lbl.confidentiality for lbl in request.argument_labels.values()])
            if egress and eff_conf >= ConfidentialityLevel.INTERNAL:
                return Decision(
                    type=DecisionType.DENY,
                    reason="Strict exfiltration guard denies external actions when internal/secret data is in context",
                    rule_id="preset.strict_exfil",
                )
            return None
        return None

    def _evaluate_rule_of_two(
        self,
        request: DecisionRequest,
        tool_cfg: ToolConfig,
        destinations: FrozenSet[str],
        egress: bool,
    ) -> Optional[Decision]:
        """Rule of Two: Never combine (1) untrusted input + (2) sensitive data + (3) external/irreversible action.

        The effective label is the lattice join of the session context and every argument
        label, i.e. ``ℓ_eff = ℓ_ctx ⊔ ⨆_j ℓ_arg_j`` — exactly the ``effectiveLabel`` of the
        mechanized Lean calculus (``formal/TaintGate/Calculus.lean``). Argument labels can
        only *raise* taint, never launder a tainted context, so this Python decision is a
        refinement of the machine-checked non-interference theorems.
        """
        eff = self._effective_label(request)
        is_sensitive = eff.confidentiality >= ConfidentialityLevel.INTERNAL
        is_untrusted = eff.integrity <= IntegrityLevel.UNTRUSTED

        # Bell–LaPadula confinement (matches Lean `isExfiltration` / Theorem 2): sensitive data
        # sent to an UNAUTHORIZED external recipient is denied regardless of integrity, so the
        # preset is sound on its own and does not rely on the operator adding a custom deny rule.
        if request.effect == ActionEffect.EXTERNAL and is_sensitive:
            contacts = frozenset(c.strip().lower() for c in self.config.policy.contacts)
            allowed = frozenset(d.strip().lower() for d in self.config.policy.allowed_domains)
            authorized = bool(destinations) and destinations <= (contacts | allowed)
            if not authorized:
                return Decision(
                    type=DecisionType.DENY,
                    reason=(
                        f"Bell–LaPadula confinement: {eff.confidentiality.name.lower()} data sent to an "
                        f"unauthorized external recipient {sorted(destinations) or '(none identified)'}."
                    ),
                    rule_id="preset.rule_of_two.confinement",
                )

        # Egress violation: untrusted context + sensitive data attempting egress (GET URL exfil or email/socket)
        if is_untrusted and is_sensitive and (egress or request.effect in (ActionEffect.EXTERNAL, ActionEffect.IRREVERSIBLE)):
            return Decision(
                type=DecisionType.DENY,
                reason=(
                    f"Violation of Rule of Two: untrusted input ({eff.integrity.name.lower()}) "
                    f"combined with sensitive data ({eff.confidentiality.name.lower()}) attempting "
                    f"egress/external tool '{request.tool_name}'."
                ),
                rule_id="preset.rule_of_two.violation",
            )

        # Untrusted context attempting external, local write, or irreversible side effects -> APPROVE
        if is_untrusted and (egress or request.effect in (ActionEffect.EXTERNAL, ActionEffect.LOCAL_WRITE, ActionEffect.IRREVERSIBLE)):
            return Decision(
                type=DecisionType.APPROVE,
                reason=(
                    f"Untrusted context attempting {request.effect.value} action '{request.tool_name}'. "
                    f"Human approval required by Rule of Two."
                ),
                rule_id="preset.rule_of_two.untrusted_side_effect",
            )

        return None

    def _evaluate_custom_rules(
        self,
        request: DecisionRequest,
        tool_cfg: ToolConfig,
        destinations: FrozenSet[str],
        egress: bool,
    ) -> Optional[Decision]:
        ctx = request.session_context_label
        contacts = frozenset(c.strip().lower() for c in self.config.policy.contacts)
        allowed_domains = frozenset(d.strip().lower() for d in self.config.policy.allowed_domains)

        # Effective data label = ctx ⊔ args (join); arguments can only raise taint. The DSL's
        # ``data.*`` names therefore agree with the Rule-of-Two effective label and the Lean model.
        eff = self._effective_label(request)
        data_conf_val = eff.confidentiality
        data_integ_val = eff.integrity

        env = EvalEnv(
            data_confidentiality=data_conf_val,
            data_integrity=data_integ_val,
            context_confidentiality=ctx.confidentiality,
            context_integrity=ctx.integrity,
            effect=request.effect.value,
            tool=request.tool_name,
            egress=egress,
            destinations=destinations,
            contacts=contacts,
            allowed_domains=allowed_domains,
        )

        for idx, rule in enumerate(self.config.policy.rules):
            rule_id = f"custom_rule_{idx + 1}"
            target = rule.target

            # Match target against tool name, effect, or '*'
            target_matches = (
                target == "*"
                or target == request.effect.value
                or (target == "egress" and egress)
                or target == request.tool_name
                or fnmatch.fnmatch(request.tool_name, target)
            )
            if not target_matches:
                continue

            # Evaluate condition
            when_clause = rule.when
            matched = False
            if not when_clause:
                matched = True
            else:
                try:
                    cond_fn = compile_condition(when_clause)
                    matched = cond_fn(env)
                except PolicyDSLError as exc:
                    logger.error(f"Policy DSL evaluation error on rule {rule_id}: {exc}")
                    # Fail-closed: evaluation error denies
                    return Decision(
                        type=DecisionType.DENY,
                        reason=f"Policy DSL condition evaluation failed (fail-closed): {exc}",
                        rule_id=rule_id,
                    )

            if matched:
                action_str = rule.action
                dec_type = {
                    "deny": DecisionType.DENY,
                    "approve": DecisionType.APPROVE,
                    "redact": DecisionType.REDACT,
                    "allow": DecisionType.ALLOW,
                }[action_str]

                dec = Decision(
                    type=dec_type,
                    reason=f"Matched custom rule {rule_id}: {rule.action} {target}" + (f" when {when_clause}" if when_clause else ""),
                    rule_id=rule_id,
                )
                if dec_type == DecisionType.REDACT:
                    # Provide redacted arguments
                    dec.redacted_arguments = self._redact_sensitive_arguments(request.arguments, tool_cfg)
                return dec

        return None

    def _redact_sensitive_arguments(self, arguments: Dict[str, Any], tool_cfg: ToolConfig) -> Dict[str, Any]:
        """Redacts sensitive arguments for REDACT decision verdicts."""
        redacted = dict(arguments)
        sensitive_keys = set(tool_cfg.sensitive_args) | {"body", "content", "payload", "data", "message"}
        for k in redacted:
            if k in sensitive_keys and isinstance(redacted[k], str):
                redacted[k] = "[REDACTED]"
        return redacted

    def _enrich_decision(self, decision: Decision, request: DecisionRequest) -> Decision:
        """Attaches capability tokens ONLY to ALLOW and REDACT actions (never unapproved APPROVE)."""
        if decision.type in (DecisionType.ALLOW, DecisionType.REDACT):
            token = CapabilityToken.mint(
                tool_name=request.tool_name,
                arguments=decision.redacted_arguments if decision.redacted_arguments is not None else request.arguments,
                secret_key=self.token_secret,
            )
            decision.capability_token = token
        return decision
