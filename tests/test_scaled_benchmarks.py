"""Unit tests for SWE-bench Lite and ToolBench evaluation harnesses (Phase A.3)."""

import pytest

from eval.swebench import SWEBenchEvaluator, SWEEvaluationReport
from eval.toolbench import ToolBenchEvaluator, ToolBenchEvaluationReport


def test_swebench_evaluator_runs_all_defenses():
    evaluator = SWEBenchEvaluator()
    reports = evaluator.run_all()

    assert len(reports) == 5

    report_map = {r.defense_name: r for r in reports}

    # No defense allows attacks
    assert report_map["No Defense"].attack_success_rate_pct == 100.0
    assert report_map["No Defense"].benign_utility_pct == 100.0

    # TaintGate blocks attacks and preserves 100% utility
    tg_report = report_map["TaintGate (Ours)"]
    assert tg_report.benign_utility_pct == 100.0
    assert tg_report.attack_success_rate_pct == 0.0
    assert tg_report.mean_latency_ms < 1.0

    # Naive HITL has high approval burden
    hitl_report = report_map["Naive HITL (CS6570)"]
    assert hitl_report.approval_count > tg_report.approval_count


def test_toolbench_evaluator_runs_all_defenses():
    evaluator = ToolBenchEvaluator()
    reports = evaluator.run_all()

    assert len(reports) == 5

    report_map = {r.defense_name: r for r in reports}

    # TaintGate blocks all attacks (0% ASR). Benign utility is 66.7%, not 100%: one benign
    # ToolBench workflow reads a CUSTOMER-authored support ticket (untrusted) and then emails a
    # colleague, which is correctly gated to human approval. This is the honest cost of sound
    # conservative labeling of attacker-influenced input, not a regression.
    tg_report = report_map["TaintGate (Ours)"]
    assert tg_report.attack_success_rate_pct == 0.0
    assert tg_report.benign_utility_pct == pytest.approx(66.6667, abs=0.1)
    assert tg_report.mean_latency_ms < 1.0

    # No Defense admits attacks
    assert report_map["No Defense"].attack_success_rate_pct == 100.0
