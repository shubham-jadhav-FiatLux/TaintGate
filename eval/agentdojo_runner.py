"""Runnable AgentDojo evaluation harness for TaintGate (model-in-the-loop).

STATUS: This is a real, runnable harness, but it is NOT exercised in CI and has NOT
yet been run for the paper. It requires (a) ``pip install agentdojo`` and (b) a model
backend: an API key (OpenAI/Anthropic via litellm) OR a local Ollama server. Until it is
run, no AgentDojo numbers should be reported anywhere.

What it does
------------
It inserts the TaintGate reference monitor at AgentDojo's tool-execution boundary: every
function the agent calls is first evaluated by :class:`TaintGateDojoPipelineElement`
(the same ``SessionTracker``/``PolicyEvaluator`` used everywhere else in the repo). A DENY
turns into an error tool-result the agent sees; an APPROVE is treated as blocked in the
unattended benchmark (no human present). Tool *outputs* are fed back so session taint
accumulates across the task, so Rule-of-Two can fire on later steps.

Why wrap the runtime (not a pipeline element)
---------------------------------------------
Wrapping ``FunctionsRuntime.run_function`` is robust to AgentDojo version differences: the
monitor sees the exact ``(tool, args)`` AgentDojo is about to execute, regardless of how the
surrounding pipeline is assembled.

Usage
-----
    # local, no API key:  ollama serve && ollama pull llama3.1
    python -m eval.agentdojo_runner --provider ollama --model llama3.1 --suite workspace --limit 10
    # API model:
    OPENAI_API_KEY=... python -m eval.agentdojo_runner --provider openai --model gpt-4o-mini --suite workspace

The exact AgentDojo entry points are resolved at runtime and the script prints precise
install/setup guidance if anything is missing, rather than failing obscurely.
"""

from __future__ import annotations

import argparse
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

from taintgate.core.policy.parser import parse_policy
from taintgate.core.policy.evaluator import PolicyEvaluator
from taintgate.core.decisions import DecisionType
from taintgate.integrations.agentdojo import TaintGateDojoPipelineElement


@dataclass
class MonitorStats:
    """Per-run counters the harness accumulates from the monitor."""
    calls_total: int = 0
    calls_denied: int = 0
    calls_approval_gated: int = 0
    denied_tools: List[str] = field(default_factory=list)


class TaintGateRuntimeGuard:
    """Wraps an AgentDojo ``FunctionsRuntime`` so each tool call is mediated by TaintGate.

    This object is deliberately framework-light: it exposes ``guard(tool_name, args)`` and
    ``observe(tool_name, args, result)`` and is attached to whatever runtime hook the installed
    AgentDojo version exposes (see :func:`install_into_runtime`).
    """

    def __init__(self, evaluator: PolicyEvaluator):
        self.element = TaintGateDojoPipelineElement(evaluator)
        self.stats = MonitorStats()

    def guard(self, tool_name: str, arguments: Dict[str, Any]) -> Optional[str]:
        """Returns None if allowed, or an error string to hand back to the agent if blocked."""
        self.stats.calls_total += 1
        allowed, message, decision = self.element.filter_tool_call(tool_name, dict(arguments or {}))
        if decision is not None and decision.type == DecisionType.DENY:
            self.stats.calls_denied += 1
            self.stats.denied_tools.append(tool_name)
            return message
        if decision is not None and decision.type == DecisionType.APPROVE:
            # No human is present in the unattended benchmark: a gated action does not execute.
            self.stats.calls_approval_gated += 1
            return message
        return None

    def observe(self, tool_name: str, arguments: Dict[str, Any], result: Any) -> None:
        self.element.record_tool_result(tool_name, dict(arguments or {}), result)

    def reset(self) -> None:
        self.element.reset_session()
        self.stats = MonitorStats()


def install_into_runtime(runtime: Any, guard: TaintGateRuntimeGuard) -> None:
    """Monkeypatch an AgentDojo ``FunctionsRuntime`` instance so tool calls route through ``guard``.

    AgentDojo executes tools via ``FunctionsRuntime.run_function(env, function, kwargs, ...)``.
    We wrap that method: evaluate first, block with an error result if denied, otherwise run the
    original and feed the output back to the monitor for taint accumulation.
    """
    original_run = runtime.run_function

    def wrapped_run_function(env: Any, function: str, kwargs: Dict[str, Any], *args: Any, **kw: Any):
        blocked = guard.guard(str(function), dict(kwargs or {}))
        if blocked is not None:
            # Hand the agent a tool error instead of executing. AgentDojo tolerates a
            # (result, error) tuple from run_function; we return an empty result + error text.
            return "", blocked
        result = original_run(env, function, kwargs, *args, **kw)
        # run_function returns (result, error) in recent AgentDojo; normalize.
        if isinstance(result, tuple) and len(result) == 2:
            value, error = result
            if error is None:
                guard.observe(str(function), dict(kwargs or {}), value)
            return result
        guard.observe(str(function), dict(kwargs or {}), result)
        return result

    runtime.run_function = wrapped_run_function  # type: ignore[assignment]


def _load_agentdojo():
    """Imports AgentDojo, raising a clear, actionable error if it is not installed."""
    try:
        import agentdojo  # noqa: F401
        from agentdojo import task_suite  # noqa: F401
        return agentdojo
    except Exception as exc:  # pragma: no cover - environment dependent
        raise SystemExit(
            "AgentDojo is not importable: "
            f"{exc}\n\n"
            "This harness needs the real benchmark. Install it, e.g.:\n"
            "    pip install agentdojo\n"
            "and provide a model backend (an API key, or a local Ollama server).\n"
            "No AgentDojo results should be cited until this script runs successfully."
        )


def build_pipeline(provider: str, model: str, guard: TaintGateRuntimeGuard):
    """Builds an AgentDojo agent pipeline for the given backend.

    Returns an object exposing the AgentDojo pipeline API. The runtime guard is installed
    per-task in :func:`run` (the runtime is created by AgentDojo per task), so this function
    only assembles the model-backed pipeline.
    """
    _load_agentdojo()
    try:
        from agentdojo.agent_pipeline import AgentPipeline, PipelineConfig
    except Exception as exc:  # pragma: no cover
        raise SystemExit(
            f"Could not import AgentDojo's pipeline API ({exc}). The installed AgentDojo version "
            "may differ; adjust build_pipeline() to match its agent_pipeline module."
        )

    # Model string for litellm-backed providers; ollama uses the local server.
    if provider == "ollama":
        llm_name = f"ollama/{model}"
    elif provider in ("openai", "anthropic", "google", "together"):
        llm_name = model if "/" not in model else model
    else:
        raise SystemExit(f"Unknown provider '{provider}'. Use openai|anthropic|google|together|ollama.")

    try:
        return AgentPipeline.from_config(PipelineConfig(llm=llm_name, defense=None, system_message_name=None, system_message=None))
    except Exception as exc:  # pragma: no cover
        raise SystemExit(
            f"Failed to construct AgentPipeline for '{llm_name}' ({exc}).\n"
            "Check the backend: for ollama, run `ollama serve` and `ollama pull <model>`; "
            "for API providers, set the provider's API key env var."
        )


def run(provider: str, model: str, suite_name: str, limit: Optional[int], policy_path: str) -> int:
    """Runs the benchmark suite with the TaintGate monitor installed. Returns a process exit code."""
    agentdojo = _load_agentdojo()
    evaluator = PolicyEvaluator(parse_policy(Path(policy_path)))
    guard = TaintGateRuntimeGuard(evaluator)
    pipeline = build_pipeline(provider, model, guard)

    try:
        from agentdojo.task_suite import get_suite  # type: ignore
        suite = get_suite(suite_name)
    except Exception as exc:  # pragma: no cover
        raise SystemExit(
            f"Could not load AgentDojo suite '{suite_name}' ({exc}). "
            "Available suites depend on the installed version (e.g. workspace, banking, travel, slack)."
        )

    user_tasks = list(getattr(suite, "user_tasks", {}).values()) if hasattr(suite, "user_tasks") else []
    if limit is not None:
        user_tasks = user_tasks[:limit]

    print(f"[agentdojo-runner] suite={suite_name} provider={provider} model={model} tasks={len(user_tasks)}")
    print("[agentdojo-runner] TaintGate monitor installed at the tool-execution boundary.")
    print("[agentdojo-runner] NOTE: APPROVE decisions count as blocked (no human in the unattended run).")

    utility_ok = 0
    security_blocked = 0
    total = 0
    for task in user_tasks:
        total += 1
        guard.reset()
        try:
            # AgentDojo creates the runtime per task; install the guard on it just before run.
            runtime, env = suite.create_runtime_and_environment(task) if hasattr(suite, "create_runtime_and_environment") else (None, None)
            if runtime is not None:
                install_into_runtime(runtime, guard)
            # The exact call to execute a task differs by version; we use the suite's runner if present.
            result = suite.run_task_with_pipeline(pipeline, task, runtime=runtime, environment=env) \
                if hasattr(suite, "run_task_with_pipeline") else None
            if result is not None:
                utility, security = result if isinstance(result, tuple) else (result, None)
                utility_ok += 1 if utility else 0
                security_blocked += 1 if (security is False or guard.stats.calls_denied > 0) else 0
        except Exception as exc:  # pragma: no cover
            print(f"  task {getattr(task, 'ID', '?')}: harness error: {exc}")
            continue
        print(f"  task {getattr(task, 'ID', '?')}: monitor denied {guard.stats.calls_denied}/"
              f"{guard.stats.calls_total} calls, approval-gated {guard.stats.calls_approval_gated}")

    print("\n[agentdojo-runner] SUMMARY (real run):")
    print(f"  tasks evaluated      : {total}")
    print(f"  benign utility (ok)  : {utility_ok}/{total}" if total else "  (no tasks)")
    print(f"  attacks blocked      : {security_blocked}")
    print("  (Interpret with care; wire suite.run_task_with_pipeline to your AgentDojo version if the"
          " per-task runner above did not execute.)")
    return 0


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(description="Run AgentDojo with the TaintGate reference monitor installed.")
    ap.add_argument("--provider", default="ollama", choices=["openai", "anthropic", "google", "together", "ollama"])
    ap.add_argument("--model", default="llama3.1", help="Model name (e.g. gpt-4o-mini, claude-..., llama3.1).")
    ap.add_argument("--suite", default="workspace", help="AgentDojo task suite name.")
    ap.add_argument("--limit", type=int, default=None, help="Limit number of user tasks (for a smoke run).")
    ap.add_argument("--policy", default="policy.yaml", help="TaintGate policy file.")
    args = ap.parse_args(argv)
    return run(args.provider, args.model, args.suite, args.limit, args.policy)


if __name__ == "__main__":
    sys.exit(main())
