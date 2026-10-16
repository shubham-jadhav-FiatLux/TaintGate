"""Static configuration analyzer (CS6843 Static Reachability).

Checks for dangerous capability combinations ('lethal trifecta') across configured tools.
"""

from __future__ import annotations

from typing import List
from dataclasses import dataclass

from taintgate.core.policy.schema import TaintGateConfig


@dataclass
class LintIssue:
    level: str  # "ERROR", "WARNING", "INFO"
    code: str
    message: str


class ConfigLinter:
    """Performs static capability graph and reachability analysis on policy configurations."""

    def __init__(self, config: TaintGateConfig):
        self.config = config

    def lint(self) -> List[LintIssue]:
        issues: List[LintIssue] = []

        has_untrusted_source = False
        has_secret_source = False
        has_external_sink = False
        has_irreversible_sink = False

        for name, tool in self.config.tools.items():
            effect = (tool.effect or "").lower()
            if effect == "external":
                has_external_sink = True
            elif effect == "irreversible":
                has_irreversible_sink = True

            if tool.output:
                if tool.output.integrity.lower() == "untrusted":
                    has_untrusted_source = True
                if tool.output.confidentiality.lower() in ("internal", "secret"):
                    has_secret_source = True

            for override in tool.overrides:
                if override.integrity and override.integrity.lower() == "untrusted":
                    has_untrusted_source = True
                if override.confidentiality and override.confidentiality.lower() in ("internal", "secret"):
                    has_secret_source = True

        preset = (self.config.policy.preset or "").lower()

        # Check for lethal trifecta
        if has_untrusted_source and has_secret_source and (has_external_sink or has_irreversible_sink):
            if not preset and not self.config.policy.rules:
                issues.append(
                    LintIssue(
                        level="ERROR",
                        code="TG-001",
                        message=(
                            "Lethal trifecta detected: Configuration includes untrusted inputs, "
                            "sensitive data access, and external/irreversible sinks with no policy rules or presets active!"
                        ),
                    )
                )
            elif preset != "rule_of_two":
                issues.append(
                    LintIssue(
                        level="WARNING",
                        code="TG-002",
                        message="Lethal trifecta capabilities present without the strict 'rule_of_two' preset.",
                    )
                )

        if not self.config.tools:
            issues.append(
                LintIssue(
                    level="WARNING",
                    code="TG-003",
                    message="No tools declared in configuration.",
                )
            )

        return issues
