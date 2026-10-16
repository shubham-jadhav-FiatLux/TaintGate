"""CLI and Terminal Approval UI Prompt."""

from __future__ import annotations

import sys
from taintgate.core.approval import ApprovalRequest, ApprovalResponse, GrantScope


class CLIApprovalPrompt:
    """Renders human-in-the-loop approval prompts via terminal trusted path."""

    def prompt(self, request: ApprovalRequest) -> ApprovalResponse:
        print("\n" + "=" * 60, file=sys.stderr)
        print(" [TaintGate] APPROVAL REQUIRED", file=sys.stderr)
        print("=" * 60, file=sys.stderr)
        print(f"Tool      : {request.tool_name}", file=sys.stderr)
        print(f"Arguments : {request.arguments}", file=sys.stderr)
        print(f"Reason    : {request.explanation}", file=sys.stderr)
        if request.flow_summary:
            print("\nProvenance Trace:", file=sys.stderr)
            print(request.flow_summary, file=sys.stderr)
        print("-" * 60, file=sys.stderr)

        # In interactive mode, this would read user input: [y]es, [n]o, [s]ession
        return ApprovalResponse(
            request_id=request.request_id,
            approved=False,
            scope=GrantScope.ONCE,
        )
