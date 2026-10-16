"""Unit tests for Tier 2 precision feature ablation suite."""

from eval.ablations import run_ablation_evaluation, create_precision_benchmark_suite


def test_precision_benchmark_suite_creation():
    workflows = create_precision_benchmark_suite()
    assert len(workflows) == 6
    benign = [w for w in workflows if not w.is_attack]
    attacks = [w for w in workflows if w.is_attack]
    assert len(benign) == 4
    assert len(attacks) == 2


def test_ablation_is_a_sound_negative_result():
    """Honest ablation invariant.

    Under a decision function sound w.r.t. the mechanized non-interference theorem (effective
    label = ctx join args), argument-level precision features do NOT recover utility: every
    configuration yields identical utility/ASR/approval. This test pins that negative result so
    it cannot silently regress into the earlier (fabricated) 25%->75% recovery curve. See
    docs/evaluation.md Section 6 for the analysis and the declassification-aware future work.
    """
    metrics = run_ablation_evaluation()
    assert len(metrics) == 5

    cfg_a = metrics[0]
    # Security is preserved at 0.0% ASR across all configurations.
    assert all(m.attack_success_rate_pct == 0.0 for m in metrics)
    # Negative result: utility and approval are identical across configs (no sound recovery).
    assert all(m.benign_utility_pct == cfg_a.benign_utility_pct for m in metrics)
    assert all(m.approval_rate_pct == cfg_a.approval_rate_pct for m in metrics)
    # A precision feature must never WORSEN security or utility relative to the baseline.
    assert all(m.benign_utility_pct >= cfg_a.benign_utility_pct for m in metrics)
    # Overhead remains sub-millisecond.
    assert all(m.median_latency_ms < 1.0 for m in metrics)
