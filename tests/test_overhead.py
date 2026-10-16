"""Tests for reference monitor latency and overhead benchmarks."""

from eval.benchmark_overhead import benchmark_overhead


def test_overhead_microbenchmarks():
    results = benchmark_overhead(iterations=100)
    assert len(results) == 4

    for r in results:
        # Assert that median (p50) latency is sub-millisecond (< 1000 µs)
        assert r.p50_us < 1000.0
        # Assert that 90th percentile latency is sub-millisecond / under 2 ms
        assert r.p90_us < 2000.0
        # Accommodate potential cloud runner thread preemption spikes on p99
        assert r.p99_us < 50000.0
        assert r.iterations == 100
