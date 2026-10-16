# Evaluation Methodology & Benchmark Plan

## 1. Experimental Objectives

The goal of TaintGate evaluation is to quantitatively assess:
1. **Security Effectiveness**: Resistance to indirect prompt injection (IPI) and unauthorized data exfiltration under standard attack suites.
2. **Benign Task Utility**: The degree to which legitimate, non-malicious agent workflows complete unimpeded.
3. **Approval Burden**: The frequency of human-in-the-loop approval requests required.
4. **Latency Overhead**: Proxy and reference monitor evaluation latency.

---

## 2. Evaluation Benchmarks and Workflows

Evaluation uses representative multi-step agent workflows and synthetic execution traces:
- **Workflows**: Multi-turn environments (workspaces, banking, web, email, calendar).
- **Synthetic Traces**: Execution traces modeled after realistic software engineering (SWE-bench Lite) and multi-hop API orchestration (ToolBench) tasks.
- **Attacks**: Representative prompt injection vectors embedded in simulated tool outputs.
- **Evaluation Modes**: Benign utility, attack success rate (ASR), and human approval prompts.

---

## 3. Defense Baselines for Comparison

We compare TaintGate against four defense configurations:
1. **No Defense**: Raw model loop with unmediated tool execution.
2. **Static Tool Filter**: Simple static allow/deny rules on tool names.
3. **Naive Human-in-the-Loop (HITL)**: Asking human approval for every non-read action.
4. **Dual-LLM Inspector**: An auxiliary LLM prompting an inspector model before each tool call.
5. **TaintGate (Ours)**:
   - Tier 1: Conservative context-level IFC + Rule of Two.
   - Tier 2: Precision features (field-level labels, typed extractors, clean-context subagents).

---

## 4. Metrics

| Metric | Definition | Ideal Direction |
|---|---|---|
| **Benign Utility (%)** | Proportion of benign tasks completed successfully without false blocks | Higher ($\uparrow$) |
| **Attack Success Rate (%)** | Proportion of attacks successfully exfiltrating data or triggering target action | Lower ($\downarrow$) |
| **Approval Request Count** | Human approval requests required | Lower ($\downarrow$) |
| **Latency Overhead (ms)** | Median time added by reference monitor check | Lower ($\downarrow$) |

---

## 5. Measured Benchmark Results

The following table reports empirical measurements across the five defense baselines evaluated on the multi-step orchestration workflows:

| Defense | Benign Utility (%) | Attack Success Rate (%) | Approval Prompts | Latency Overhead (ms) |
|---|---|---|---|---|
| **No Defense** | 100.0% | 100.0% | 0 | 0.001 ms |
| **Static Tool Filter** | 75.0% | 25.0% | 0 | 0.001 ms |
| **Naive HITL (CS6570)** | 100.0% | 0.0% | 5 | 0.001 ms |
| **Keyword Inspector (static)** | 100.0% | 75.0% | 0 | 0.001 ms |
| **TaintGate (Ours)** | **100.0%** | **0.0%** | **1** | **~0.1 ms** |

> **Scope and honesty caveats (read before citing these numbers):**
> - These are **deterministic tool-call traces**, not live-model runs. No LLM/AgentDojo has been executed; a runnable harness is provided (`eval/agentdojo_runner.py`) but the model-in-the-loop study is not yet done.
> - The **"Keyword Inspector" is a regex**, not an LLM. Its 75% ASR means "pattern inspection is evadable", and must **not** be generalized to real dual-LLM inspectors.
> - On the **ToolBench fixtures**, TaintGate utility is **66.7%** (not 100%): a benign workflow that reads a *customer-authored* support ticket (untrusted) and then emails a colleague is gated to human approval. This is the honest cost of sound conservative labeling.

### Key Findings
1. **Security**: TaintGate attains 0.0% ASR on the tested injection vectors by dataflow confinement, independent of payload encoding or phrasing.
2. **Approval burden**: On the standard suite it needs 1 approval vs. 5 for naive HITL; on ToolBench the conservative labeling costs one additional gated workflow (66.7% utility).
3. **Overhead**: tens of microseconds per in-process decision (reproducible via `eval/benchmark_overhead.py`); absolute numbers vary with hardware.
4. **Soundness**: the Python monitor is a verified sound refinement of the Lean-mechanized decision function (0 of 72 label×effect×recipient inputs more permissive than the proved model).

---

## 6. Tier 2 Precision Feature Ablation Study

To analyze the contribution of fine-grained precision mechanisms (Milestone M4) in recovering benign utility without violating non-interference, we evaluate five incremental configurations across complex field-sensitive workflows:

| Configuration | Benign Utility (%) | Attack Success Rate (%) | Approval Rate (%) | Median Latency (ms) |
|---|---|---|---|---|
| **Config A: Conservative Baseline (Tier 1)** | 25.0% | 0.0% | 28.6% | ~0.1 ms |
| **Config B: + Exact-Provenance Arguments** | 25.0% | 0.0% | 28.6% | ~0.1 ms |
| **Config C: + Field-Sensitive Labels** | 25.0% | 0.0% | 28.6% | ~0.1 ms |
| **Config D: + Typed Quarantined Extractors** | 25.0% | 0.0% | 28.6% | ~0.1 ms |
| **Config E: Full Tier 2 (+ Clean Sub-Agents)** | **25.0%** | **0.0%** | **28.6%** | **~0.1 ms** |

### Ablation Insights — a negative result (reported honestly)

Under a decision function that is **sound** with respect to the mechanized non-interference theorem — the effective label is the lattice join `ℓ_ctx ⊔ ⊔ⱼ ℓ_argⱼ`, matching `formal/TaintGate/Calculus.lean` — **the four precision mechanisms recover no benign utility**: every configuration yields identical utility/ASR/approval.

The cause is structural: because taint is the *join* of context and arguments, relabeling an argument more cleanly cannot launder a tainted context, and a sub-agent that soundly inherits its parent's integrity cannot escape it. Argument-level precision would recover utility only under an **arguments-override** decision function that is strictly more permissive than — and therefore *not covered by* — the proved theorem.

**Conclusion:** sound utility recovery for conservative IFC requires an explicit **declassification-aware** security condition (endorsement with a discharged proof obligation), which we identify as the central open problem and leave to future work. We report this rather than adopt the unsound permissive function that would produce a flattering 25%→75% curve (which earlier revisions of this table did, incorrectly).

---

## 8. Defensive Robustness Against Adaptive Adversaries

To evaluate resilience beyond static prompt injection scenarios, we benchmark defenses against an **adaptive attacker** attempting four circumvention techniques:
1. **Encoding Smuggling**: Obfuscating secret data inside Base64 payloads to evade keyword inspection.
2. **Multi-Turn Instruction Splitting**: Segmenting malicious directives across separate turns.
3. **Runtime Tool Schema Alteration**: Dynamically modifying MCP tool descriptions to disguise external sinks as read-only.
4. **Capability Token Forgery & Argument Tampering**: Attempting to alter arguments post-authorization or synthesize token signatures.

Static ASR is measured by running each defense on the standard suite; adaptive ASR on the four-class adaptive suite. Both columns are now measured (no hardcoded verdicts).

| Defense | Static ASR (%) | Adaptive ASR (%) | Notes |
|---|---|---|---|
| **No Defense** | 100.0% | 100.0% | No mediation |
| **Static Tool Filter** | 75.0% | 100.0% | Blind to permitted sinks (only blocks named tools) |
| **Naive HITL (CS6570)** | 0.0% | 0.0% | Blocks everything stateful; high approval fatigue |
| **Keyword Inspector (static)** | 75.0% | 50.0% | A **regex**, not an LLM; evadable by encoding/innocuous recipient |
| **TaintGate (Ours)** | **0.0%** | **0.0%** | Dataflow confinement; independent of payload content |

### Security Analysis
- **Why TaintGate holds**: it decides on the lattice label of the data flowing to a sink (and the session context), not on string/regex matches, so base64 encoding, paraphrase, and multi-turn splitting do not change the untrusted origin — the exfiltration is blocked at the sink regardless of content.
- **Honesty note**: the "Keyword Inspector" is a deterministic regex standing in for the *cheap* tier of content inspection. Its evasion demonstrates that **pattern inspection** is evadable; it is **not** evidence about real LLM-based inspectors, which we have not evaluated (that requires the live-model harness).
- **Cryptographic binding**: tool-description tampering is detected by SHA-256 pinning (first-observation pinned; tampered tools disabled), and capability tokens are HMAC-SHA256 bound to the exact `(tool, arguments)` and verified immediately before dispatch.

---

## 9. Microsecond Latency and System Overhead Profiling

Measured over $N = 1,000$ iterations using hardware high-resolution timers (`perf_counter_ns`):

| Operation | Iterations | p50 (µs) | p90 (µs) | p99 (µs) | Mean (µs) |
|---|---|---|---|---|---|
| **Policy Decision Evaluation** | 1,000 | 60.55 µs | 74.62 µs | 127.73 µs | 65.32 µs |
| **HMAC Token Mint + Verification** | 1,000 | 22.46 µs | 25.50 µs | 59.06 µs | 24.48 µs |
| **Backward Program Slice (15 nodes)** | 1,000 | 8.18 µs | 8.93 µs | 26.63 µs | 8.84 µs |
| **JSON-RPC Proxy Interception** | 1,000 | 37.63 µs | 46.81 µs | 94.10 µs | 40.72 µs |

### Latency Summary
- **Sub-Millisecond Overhead**: Total reference monitor mediation overhead is under **0.13 ms at p99**, orders of magnitude below token generation latency in modern LLMs (typically 20–100 ms per token).



