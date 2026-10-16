"""Stdio-based Model Context Protocol (MCP) Proxy Runner."""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
import sys
from typing import Any, Dict, List, Optional

from taintgate.core.policy.evaluator import PolicyEvaluator
from taintgate.proxy.interceptor import MCPInterceptor
from taintgate.audit.log import HashChainLog


class StdioMCPProxy:
    """Spawns an MCP server subprocess and intercepts JSON-RPC messages over stdio."""

    def __init__(
        self,
        evaluator: PolicyEvaluator,
        server_cmd: List[str],
        audit_log_path: Optional[Path] = None,
    ):
        self.evaluator = evaluator
        self.server_cmd = server_cmd
        self.audit_log = HashChainLog(audit_log_path) if audit_log_path else None
        self.interceptor = MCPInterceptor(evaluator=evaluator, audit_log=self.audit_log)
        self.proc: Optional[asyncio.subprocess.Process] = None

    async def run(self) -> None:
        """Runs the stdio proxy loop mediating stdin and stdout."""
        # 10 MiB buffer limit to prevent DoS via large lines
        stream_limit = 10 * 1024 * 1024
        self.proc = await asyncio.create_subprocess_exec(
            *self.server_cmd,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=sys.stderr,
            limit=stream_limit,
        )

        loop = asyncio.get_running_loop()
        reader = asyncio.StreamReader(limit=stream_limit)
        protocol = asyncio.StreamReaderProtocol(reader)
        await loop.connect_read_pipe(lambda: protocol, sys.stdin)

        client_task = asyncio.create_task(self._client_loop(reader))
        server_task = asyncio.create_task(self._server_loop())

        done, pending = await asyncio.wait(
            [client_task, server_task],
            return_when=asyncio.FIRST_COMPLETED,
        )

        for task in pending:
            task.cancel()

        if self.proc and self.proc.returncode is None:
            self.proc.terminate()
            await self.proc.wait()

    async def _client_loop(self, reader: asyncio.StreamReader) -> None:
        """Reads JSON-RPC from client stdin, evaluates, and forwards allowed calls."""
        while True:
            line = await reader.readline()
            if not line:
                break
            line_str = line.decode("utf-8").strip()
            if not line_str:
                continue

            try:
                msg = json.loads(line_str)
            except Exception as e:
                err_resp = {
                    "jsonrpc": "2.0",
                    "id": None,
                    "error": {"code": -32700, "message": f"Parse error: {e}"},
                }
                sys.stdout.write(json.dumps(err_resp) + "\n")
                sys.stdout.flush()
                continue

            if not isinstance(msg, dict):
                err_resp = {
                    "jsonrpc": "2.0",
                    "id": None,
                    "error": {
                        "code": -32600,
                        "message": "Invalid Request: Batch requests and non-object payloads are not supported",
                    },
                }
                sys.stdout.write(json.dumps(err_resp) + "\n")
                sys.stdout.flush()
                continue

            forward_to_server, immediate_resp = self.interceptor.handle_client_message(msg)

            if immediate_resp is not None:
                resp_str = json.dumps(immediate_resp, sort_keys=True) + "\n"
                sys.stdout.write(resp_str)
                sys.stdout.flush()

            if forward_to_server is not None and self.proc and self.proc.stdin:
                req_str = json.dumps(forward_to_server, sort_keys=True) + "\n"
                self.proc.stdin.write(req_str.encode("utf-8"))
                await self.proc.stdin.drain()

    async def _server_loop(self) -> None:
        """Reads JSON-RPC from server stdout, intercepts responses, and forwards to client."""
        if not self.proc or not self.proc.stdout:
            return

        while True:
            line = await self.proc.stdout.readline()
            if not line:
                break
            line_str = line.decode("utf-8").strip()
            if not line_str:
                continue

            try:
                msg = json.loads(line_str)
            except Exception:
                continue

            forward_to_client = self.interceptor.handle_server_message(msg)
            if forward_to_client is not None:
                resp_str = json.dumps(forward_to_client, sort_keys=True) + "\n"
                sys.stdout.write(resp_str)
                sys.stdout.flush()
