"""Tests for Adaptive Attacker Evaluation Suite."""

from eval.adaptive_attacker import run_adaptive_evaluation, create_adaptive_attack_scenarios


def test_adaptive_attack_scenarios_count():
    scenarios = create_adaptive_attack_scenarios()
    assert len(scenarios) == 4
    classes = {s.attack_class for s in scenarios}
    assert "Encoding Smuggling" in classes
    assert "Multi-Turn Splitting" in classes
    assert "Tool Schema Tampering" in classes
    assert "Token Forgery / TOCTOU" in classes


def test_taintgate_robustness_against_adaptive_attacks():
    results = run_adaptive_evaluation()
    taintgate_result = next(r for r in results if "TaintGate" in r.defense_name)
    filter_result = next(r for r in results if "Static Tool Filter" in r.defense_name)
    inspector_result = next(r for r in results if "Keyword Inspector" in r.defense_name)

    # TaintGate maintains 0.0% ASR against all adaptive evasion techniques
    assert taintgate_result.adaptive_asr_pct == 0.0
    assert len(taintgate_result.bypassed_scenarios) == 0

    # Naive filters and keyword inspectors fail against adaptive evasion
    assert filter_result.adaptive_asr_pct > 50.0
    assert inspector_result.adaptive_asr_pct > 0.0
