"""Command-line interface for TaintGate."""

from __future__ import annotations

import argparse
import asyncio
from pathlib import Path
import sys

from taintgate.core.policy.parser import parse_policy
from taintgate.core.policy.evaluator import PolicyEvaluator
from taintgate.lint.analyzer import ConfigLinter
from taintgate.audit.log import HashChainLog
from taintgate.audit.replay import load_audit_events, reconstruct_provenance_graph, replay_audit_log
from taintgate.audit.export_graphviz import to_dot
from taintgate.proxy.stdio import StdioMCPProxy
from taintgate.server.pdp_service import UnixSocketPDPServer


def main() -> None:
    parser = argparse.ArgumentParser(description="TaintGate: Information-Flow Control for LLM Agents")
    subparsers = parser.add_subparsers(dest="subcommand", help="Available subcommands")

    # Lint
    lint_parser = subparsers.add_parser("lint", help="Statically analyze policy and capability configurations")
    lint_parser.add_argument("--config", "-c", required=True, help="Path to policy YAML configuration file")

    # Audit
    audit_parser = subparsers.add_parser("audit", help="Audit log operations")
    audit_sub = audit_parser.add_subparsers(dest="audit_action", help="Audit actions")
    
    verify_p = audit_sub.add_parser("verify", help="Verify hash chain integrity of an audit log")
    verify_p.add_argument("--log", "-l", required=True, help="Path to JSONL audit log")

    replay_p = audit_sub.add_parser("replay", help="Replay session events from an audit log")
    replay_p.add_argument("--log", "-l", required=True, help="Path to JSONL audit log")

    dot_p = audit_sub.add_parser("export-dot", help="Export provenance graph from audit log to Graphviz DOT format")
    dot_p.add_argument("--log", "-l", required=True, help="Path to JSONL audit log")
    dot_p.add_argument("--output", "-o", help="Path to write DOT output (defaults to stdout)")

    # Serve (PDP Daemon)
    serve_parser = subparsers.add_parser("serve", help="Run PDP reference monitor daemon over Unix domain socket")
    serve_parser.add_argument("--socket", "-s", required=True, help="Path to Unix domain socket")
    serve_parser.add_argument("--config", "-c", required=True, help="Path to policy YAML configuration file")

    # Proxy
    proxy_parser = subparsers.add_parser("proxy", help="Run MCP reference monitor proxy over stdio")
    proxy_parser.add_argument("--config", "-c", required=True, help="Path to policy YAML configuration file")
    proxy_parser.add_argument("--audit", "-a", help="Path to write tamper-evident JSONL audit log")
    proxy_parser.add_argument("cmd", nargs=argparse.REMAINDER, help="Target MCP server command to wrap")

    args = parser.parse_args()

    if args.subcommand == "lint":
        config_path = Path(args.config)
        if not config_path.exists():
            print(f"Error: Config file not found: {config_path}", file=sys.stderr)
            sys.exit(1)
        config = parse_policy(config_path)
        linter = ConfigLinter(config)
        issues = linter.lint()
        if not issues:
            print(f"[OK] No issues detected in {config_path}")
            sys.exit(0)
        for issue in issues:
            print(f"[{issue.level}] {issue.code}: {issue.message}")
        if any(i.level == "ERROR" for i in issues):
            sys.exit(1)

    elif args.subcommand == "audit" and args.audit_action == "verify":
        log_path = Path(args.log)
        logger = HashChainLog(log_path)
        valid, failing_line, status = logger.verify_detailed()
        if valid and status == "ok_authenticated":
            print(f"[OK] Audit log {log_path} is cryptographically valid (chain + authenticated tip anchor).")
            sys.exit(0)
        elif valid:
            print(
                f"[OK, INTEGRITY-ONLY] Audit log {log_path} hash-chain is consistent, but no tip "
                f"authentication key is configured ($TAINTGATE_AUDIT_KEY), so truncation/rollback by a "
                f"motivated attacker is NOT detectable. Set a key for tamper-evidence.",
            )
            sys.exit(0)
        else:
            print(f"[FAIL] Tampering or corruption detected at record #{failing_line} in {log_path}", file=sys.stderr)
            sys.exit(1)

    elif args.subcommand == "audit" and args.audit_action == "replay":
        log_path = Path(args.log)
        if not log_path.exists():
            print(f"Error: Audit log not found: {log_path}", file=sys.stderr)
            sys.exit(1)
        records = replay_audit_log(log_path)
        print(f"--- Replaying Audit Log: {log_path} ({len(records)} events) ---")
        for rec in records:
            print(f"Step {rec['step']} | Type: {rec['type']} | Label: {rec['label']} | Details: {rec['details']}")
        sys.exit(0)

    elif args.subcommand == "audit" and args.audit_action == "export-dot":
        log_path = Path(args.log)
        if not log_path.exists():
            print(f"Error: Audit log not found: {log_path}", file=sys.stderr)
            sys.exit(1)
        events = load_audit_events(log_path)
        graph = reconstruct_provenance_graph(events)
        dot_str = to_dot(graph)
        if args.output:
            out_path = Path(args.output)
            out_path.parent.mkdir(parents=True, exist_ok=True)
            out_path.write_text(dot_str, encoding="utf-8")
            print(f"[OK] Exported provenance DOT graph to {out_path}")
        else:
            print(dot_str)
        sys.exit(0)

    elif args.subcommand == "serve":
        config_path = Path(args.config)
        if not config_path.exists():
            print(f"Error: Config file not found: {config_path}", file=sys.stderr)
            sys.exit(1)
        config = parse_policy(config_path)
        evaluator = PolicyEvaluator(config)
        socket_path = Path(args.socket)

        server = UnixSocketPDPServer(evaluator=evaluator, socket_path=socket_path)

        async def _run_server():
            await server.start()
            print(f"[TaintGate PDP] Listening on Unix socket: {socket_path}")
            try:
                while True:
                    await asyncio.sleep(3600)
            except asyncio.CancelledError:
                pass
            finally:
                await server.stop()

        try:
            asyncio.run(_run_server())
        except KeyboardInterrupt:
            pass
        sys.exit(0)


    elif args.subcommand == "proxy":
        config_path = Path(args.config)
        if not config_path.exists():
            print(f"Error: Config file not found: {config_path}", file=sys.stderr)
            sys.exit(1)

        server_cmd = args.cmd
        if server_cmd and server_cmd[0] == "--":
            server_cmd = server_cmd[1:]

        if not server_cmd:
            print("Error: No target MCP server command specified after '--'", file=sys.stderr)
            sys.exit(1)

        config = parse_policy(config_path)
        evaluator = PolicyEvaluator(config)
        audit_path = Path(args.audit) if args.audit else None

        proxy = StdioMCPProxy(evaluator=evaluator, server_cmd=server_cmd, audit_log_path=audit_path)
        try:
            asyncio.run(proxy.run())
        except KeyboardInterrupt:
            pass
        sys.exit(0)

    else:
        parser.print_help()
        sys.exit(1)


if __name__ == "__main__":
    main()
