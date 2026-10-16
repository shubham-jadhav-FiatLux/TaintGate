"""Policy Configuration Schema.

All label/effect strings are validated at load time so that a typo in a policy
fails loudly instead of silently changing enforcement.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Literal, Optional

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from taintgate.core.lattice import ConfidentialityLevel, IntegrityLevel

logger = logging.getLogger(__name__)

VALID_EFFECTS = ("read", "local_write", "external", "irreversible")

# Argument names that, by default, are treated as message recipients for every tool.
DEFAULT_RECIPIENT_ARGS = (
    "to", "cc", "bcc", "recipient", "recipients", "dest", "destination", "destinations",
    "reply_to", "forward_to", "channel",
)
# Argument names that, by default, are treated as network endpoints for every tool.
DEFAULT_URL_ARGS = (
    "url", "uri", "urls", "endpoint", "href", "link", "host", "hostname", "domain",
    "webhook", "webhook_url", "callback", "callback_url", "server", "base_url",
)


def _check_integrity(v: Optional[str]) -> Optional[str]:
    if v is not None:
        IntegrityLevel.from_str(v)
    return v


def _check_confidentiality(v: Optional[str]) -> Optional[str]:
    if v is not None:
        ConfidentialityLevel.from_str(v)
    return v


class ToolOverride(BaseModel):
    model_config = ConfigDict(extra="forbid")

    path: str
    confidentiality: Optional[str] = None
    integrity: Optional[str] = None

    @field_validator("confidentiality")
    @classmethod
    def _v_conf(cls, v: Optional[str]) -> Optional[str]:
        return _check_confidentiality(v)

    @field_validator("integrity")
    @classmethod
    def _v_integ(cls, v: Optional[str]) -> Optional[str]:
        return _check_integrity(v)


class ToolOutputAnnotation(BaseModel):
    model_config = ConfigDict(extra="forbid")

    integrity: str = "trusted"
    confidentiality: str = "public"

    @field_validator("confidentiality")
    @classmethod
    def _v_conf(cls, v: str) -> str:
        return _check_confidentiality(v)

    @field_validator("integrity")
    @classmethod
    def _v_integ(cls, v: str) -> str:
        return _check_integrity(v)


class ToolConfig(BaseModel):
    """Per-tool annotation.

    ``effect`` describes the state change a call causes. ``egress`` describes
    whether the call's *arguments* leave the trust boundary (e.g. a GET request
    whose URL reaches a remote server). ``egress`` defaults to ``True`` for
    ``external`` tools and for any call that carries a URL-like argument; set it
    explicitly to ``false`` only for tools that provably never transmit arguments.
    """
    model_config = ConfigDict(extra="allow")

    effect: str = "read"
    egress: Optional[bool] = None
    output: Optional[ToolOutputAnnotation] = None
    recipients_arg: Optional[str] = None  # legacy single-argument form
    recipient_args: List[str] = Field(default_factory=list)
    url_args: List[str] = Field(default_factory=list)
    sensitive_args: List[str] = Field(default_factory=list)
    overrides: List[ToolOverride] = Field(default_factory=list)
    # Field-path -> {integrity?, confidentiality?}; applied to structured tool results
    # (labels can only be raised by field rules, never lowered below the tool output label).
    field_labels: Dict[str, Dict[str, str]] = Field(default_factory=dict)

    @field_validator("effect")
    @classmethod
    def _v_effect(cls, v: str) -> str:
        key = str(v).strip().lower()
        if key not in VALID_EFFECTS:
            raise ValueError(f"Unknown effect {v!r}; expected one of {VALID_EFFECTS}")
        return key

    @field_validator("field_labels")
    @classmethod
    def _v_field_labels(cls, v: Dict[str, Dict[str, str]]) -> Dict[str, Dict[str, str]]:
        for path, spec in v.items():
            if not isinstance(spec, dict) or not spec:
                raise ValueError(f"field_labels[{path!r}] must be a mapping with integrity/confidentiality")
            unknown = set(spec) - {"integrity", "confidentiality"}
            if unknown:
                raise ValueError(f"field_labels[{path!r}] has unknown keys {sorted(unknown)}")
            _check_integrity(spec.get("integrity"))
            _check_confidentiality(spec.get("confidentiality"))
        return v

    def all_recipient_args(self) -> List[str]:
        names = list(DEFAULT_RECIPIENT_ARGS) + list(self.recipient_args)
        if self.recipients_arg:
            names.append(self.recipients_arg)
        return sorted({n.lower() for n in names})

    def all_url_args(self) -> List[str]:
        return sorted({n.lower() for n in list(DEFAULT_URL_ARGS) + list(self.url_args)})


class RuleDefinition(BaseModel):
    """A custom rule. Exactly one of deny/approve/allow/redact must be set.

    The target is either ``"*"``, an effect name (``read``, ``local_write``,
    ``external``, ``irreversible``), the pseudo-effect ``egress``, or a tool-name
    glob (e.g. ``"web.*"``). Custom rules can only *tighten* the decision of the
    preset and the confinement floor; they can never weaken it.
    """
    model_config = ConfigDict(extra="forbid")

    deny: Optional[str] = None
    approve: Optional[str] = None
    allow: Optional[str] = None
    redact: Optional[str] = None
    when: Optional[str] = None

    @model_validator(mode="after")
    def _v_one_action(self) -> "RuleDefinition":
        set_actions = [a for a in ("deny", "approve", "allow", "redact") if getattr(self, a) is not None]
        if len(set_actions) != 1:
            raise ValueError(f"Rule must set exactly one of deny/approve/allow/redact, got {set_actions}")
        if self.when is not None:
            # Imported lazily to avoid a circular import (dsl -> schema constants).
            from taintgate.core.policy.dsl import compile_condition
            compile_condition(self.when)
        if self.allow is not None:
            logger.warning(
                "Policy rule 'allow: %s' has no effect beyond the default: custom rules cannot weaken "
                "the preset or the confinement floor.", self.allow,
            )
        return self

    @property
    def action(self) -> str:
        for a in ("deny", "approve", "redact", "allow"):
            if getattr(self, a) is not None:
                return a
        raise AssertionError("unreachable: validated in _v_one_action")

    @property
    def target(self) -> str:
        return str(getattr(self, self.action)).strip()


class PolicySection(BaseModel):
    model_config = ConfigDict(extra="forbid")

    preset: Optional[str] = "rule_of_two"
    contacts: List[str] = Field(default_factory=list)
    allowed_domains: List[str] = Field(default_factory=list)
    rules: List[RuleDefinition] = Field(default_factory=list)
    # How to treat tools that have no annotation in `tools:`.
    #   auto        -> deny when any tool is annotated, else pessimistic (default)
    #   deny        -> every call to an unannotated tool is DENIED (fail-closed)
    #   pessimistic -> treated as effect=irreversible, egress=true, output=untrusted|secret
    unknown_tools: Literal["auto", "deny", "pessimistic"] = "auto"

    @field_validator("preset")
    @classmethod
    def _v_preset(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return None
        key = v.strip().lower()
        valid = ("rule_of_two", "read_only_browsing", "strict_exfil_guard", "none")
        if key not in valid:
            raise ValueError(f"Unknown preset {v!r}; expected one of {valid}")
        return key


class TaintGateConfig(BaseModel):
    """Top-level configuration schema.

    Configured with extra="allow" so a single YAML file may also carry sections
    meant for other tools; TaintGate ignores unknown top-level sections.
    """
    model_config = ConfigDict(extra="allow")

    version: Optional[int] = 1
    policy_engine: Optional[str] = None
    labels: Dict[str, Any] = Field(default_factory=dict)
    tools: Dict[str, ToolConfig] = Field(default_factory=dict)
    policy: PolicySection = Field(default_factory=PolicySection)
