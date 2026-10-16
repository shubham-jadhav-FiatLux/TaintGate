"""High-Precision Microsecond Overhead Profiler.

Benchmarks reference monitor latency across:
1. Policy Evaluation Decision (Rule-of-Two + custom rules)
2. Capability Token Minting & Verification (HMAC-SHA256)
3. Provenance Graph Backward Slicing (CS6843 Slicing)
4. JSON-RPC Proxy Interception & Forwarding
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import time
from typing import Dict, List

from taintgate.core.labels import LABEL_TRUSTED_PUBLIC, LABEL_UNTRUSTED_SECRET
from taintgate.core.decisions import ActionEffect, DecisionRequest, CapabilityToken
from taintgate.core.policy.parser import parse_policy
from taintgate.core.policy.evaluator import PolicyEvaluator
from taintgate.core.provenance import ProvenanceGraph, NodeType
from taintgate.proxy.interceptor import MCPInterceptor


@dataclass
class MicrobenchmarkResult:
    operation: str
    iterations: int
    p50_us: float
    p90_us: float
    p99_us: float
    mean_us: float


def benchmark_overhead(iterations: int = 1000) -> List[MicrobenchmarkResult]:
    config_path = Path("policy.yaml")
    config = parse_policy(config_path)
    evaluator = PolicyEvaluator(config)

    results: List[MicrobenchmarkResult] = []

    # 1. Policy Evaluation
    req = DecisionRequest(
        tool_name="email.send",
        arguments={"to": "colleague@example.com", "body": "Weekly update"},
        effect=ActionEffect.EXTERNAL,
        session_id="bench_sess",
        session_context_label=LABEL_TRUSTED_PUBLIC,
        recipients=["colleague@example.com"],
    )

    # Warmup
    for _ in range(10):
        evaluator.evaluate(req)

    times_eval: List[float] = []
    for _ in range(iterations):
        t0 = time.perf_counter_ns()
        evaluator.evaluate(req)
        t1 = time.perf_counter_ns()
        times_eval.append((t1 - t0) / 1000.0)  # convert ns to us

    times_eval.sort()
    results.append(
        MicrobenchmarkResult(
            operation="Policy Decision Evaluation",
            iterations=iterations,
            p50_us=round(times_eval[int(iterations * 0.50)], 2),
            p90_us=round(times_eval[int(iterations * 0.90)], 2),
            p99_us=round(times_eval[int(iterations * 0.99)], 2),
            mean_us=round(sum(times_eval) / len(times_eval), 2),
        )
    )

    # 2. Capability Token Minting & Verification
    secret_key = b"benchmark-secret-key-12345"
    args = {"to": "colleague@example.com", "body": "Weekly update"}
    # Warmup
    for _ in range(10):
        token = CapabilityToken.mint("email.send", args, secret_key, ttl_seconds=60)
        token.verify("email.send", args, secret_key)

    times_token: List[float] = []
    for _ in range(iterations):
        t0 = time.perf_counter_ns()
        token = CapabilityToken.mint("email.send", args, secret_key, ttl_seconds=60)
        token.verify("email.send", args, secret_key)
        t1 = time.perf_counter_ns()
        times_token.append((t1 - t0) / 1000.0)

    times_token.sort()
    results.append(
        MicrobenchmarkResult(
            operation="HMAC Token Mint + Verification",
            iterations=iterations,
            p50_us=round(times_token[int(iterations * 0.50)], 2),
            p90_us=round(times_token[int(iterations * 0.90)], 2),
            p99_us=round(times_token[int(iterations * 0.99)], 2),
            mean_us=round(sum(times_token) / len(times_token), 2),
        )
    )

    # 3. Provenance Graph Backward Slicing (15 nodes)
    graph = ProvenanceGraph()
    prev_id = None
    for turn in range(1, 16):
        n = graph.add_node(NodeType.TOOL_RESULT, LABEL_TRUSTED_PUBLIC, f"step_{turn}", turn=turn)
        if prev_id:
            graph.add_edge(prev_id, n.node_id)
        prev_id = n.node_id
    target_id = prev_id

    # Warmup
    for _ in range(10):
        graph.backward_slice(target_id)

    times_slice: List[float] = []
    for _ in range(iterations):
        t0 = time.perf_counter_ns()
        graph.backward_slice(target_id)
        t1 = time.perf_counter_ns()
        times_slice.append((t1 - t0) / 1000.0)

    times_slice.sort()
    results.append(
        MicrobenchmarkResult(
            operation="Backward Program Slice (15 nodes)",
            iterations=iterations,
            p50_us=round(times_slice[int(iterations * 0.50)], 2),
            p90_us=round(times_slice[int(iterations * 0.90)], 2),
            p99_us=round(times_slice[int(iterations * 0.99)], 2),
            mean_us=round(sum(times_slice) / len(times_slice), 2),
        )
    )

    # 4. JSON-RPC Proxy Message Interception
    interceptor = MCPInterceptor(evaluator=evaluator)
    rpc_msg = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {
            "name": "fs.read_file",
            "arguments": {"path": "/workspace/docs/readme.txt"},
        },
    }

    # Warmup
    for _ in range(10):
        interceptor.handle_client_message(rpc_msg)

    times_proxy: List[float] = []
    for _ in range(iterations):
        t0 = time.perf_counter_ns()
        interceptor.handle_client_message(rpc_msg)
        t1 = time.perf_counter_ns()
        times_proxy.append((t1 - t0) / 1000.0)


    times_proxy.sort()
    results.append(
        MicrobenchmarkResult(
            operation="JSON-RPC Proxy Interception",
            iterations=iterations,
            p50_us=round(times_proxy[int(iterations * 0.50)], 2),
            p90_us=round(times_proxy[int(iterations * 0.90)], 2),
            p99_us=round(times_proxy[int(iterations * 0.99)], 2),
            mean_us=round(sum(times_proxy) / len(times_proxy), 2),
        )
    )

    return results


def print_overhead_table(results: List[MicrobenchmarkResult]) -> None:
    print("\n=== TaintGate Reference Monitor Microsecond Latency Profiling ===")
    print(f"{'Operation':<38} | {'Iterations':<10} | {'p50 (µs)':<10} | {'p90 (µs)':<10} | {'p99 (µs)':<10} | {'Mean (µs)':<10}")
    print("-" * 98)
    for r in results:
        print(f"{r.operation:<38} | {r.iterations:<10} | {r.p50_us:>8.2f} µs | {r.p90_us:>8.2f} µs | {r.p99_us:>8.2f} µs | {r.mean_us:>8.2f} µs")
    print("=" * 98)


if __name__ == "__main__":
    res = benchmark_overhead(iterations=1000)
    print_overhead_table(res)
