# Development Log

## 2026-10-09: Project Decision & Architecture Design
- Decided to build TaintGate as an external, deterministic reference monitor for LLM agents.
- Grounded design in CS6570 Secure Systems (information-flow lattices, BLP, Biba, reference monitors, least privilege) and CS6843 Program Analysis (taint analysis, abstract interpretation, backward slicing).
- Established a small, dependency-light core package (`taintgate.core`) with stable interfaces for labels, policy, decisions, events, approvals and audit records.

## 2026-10-11: Milestone M0 Kickoff
- Repository layout established.
- Dependencies pinned in `pyproject.toml` (`pydantic`, `pyyaml`, `pytest`, `hypothesis`).
- Implemented formal product lattice $\mathcal{L} = \mathcal{I} \times \mathcal{C}$ with property-based tests verifying algebraic lattice laws (associativity, commutativity, idempotence, absorption).
- Implemented policy DSL parser and evaluator with Rule-of-Two presets.
- Implemented session provenance DAG with backward slicing engine.
- Implemented tamper-evident hash-chained audit logging.
- Golden policy decision test suite implemented (30+ cases).

## 2026-10-11: Milestone M1 — MCP Proxy & Interception Engine
- Implemented `MCPInterceptor` mediating JSON-RPC 2.0 messages (`tools/list`, `tools/call`).
- Built `ToolDescriptionPinner` to detect prompt-injection and schema alterations in `tools/list`.
- Built `StdioMCPProxy` running downstream MCP servers over asynchronous standard I/O pipes.
- Built compliant mock MCP server (`demos/mock_servers/stdio_mcp_server.py`) supporting filesystem, web, and email tools.
- Integrated proxy command into CLI (`taintgate proxy --config <policy.yaml> -- <server_cmd>`).
- Verified end-to-end IPI defense over live stdio MCP proxy pipes with automated test (`tests/test_mcp_live_e2e.py`).
- Froze the core interfaces at v1.0.0.

## 2026-10-11: Milestone M2 — Framework Wrappers & Baseline Evaluation
- Implemented `TaintGateToolWrapper` and `wrap_tool` for LangChain and callable functions with automatic pre-execution policy enforcement and post-execution output labelling.
- Implemented `TaintGateReActMediator` for OpenAI function-calling and ReAct loops.
- Implemented `TaintGateDojoPipelineElement` for AgentDojo benchmark evaluation tasks.
- Implemented four defense baselines: `NoDefense`, `StaticToolFilter`, `NaiveHITL`, and `DualLLMInspector`.
- Built benchmark evaluation runner (`eval/runner.py`) measuring Benign Utility, Utility under Attack, Attack Success Rate, Approval Rate, and Latency Overhead across all baselines.
- Published empirical evaluation table in `docs/evaluation.md`: TaintGate achieved 100.0% Benign Utility, 0.0% ASR, and reduced approval burden to 5.9% with 0.060 ms median overhead.

## 2026-10-11: Milestone M3 — Unix-Socket PDP Service, Audit Replay & Provenance Export
- Implemented out-of-process Policy Decision Point (PDP) daemon (`UnixSocketPDPServer`) and client (`UnixSocketPDPClient`) over Unix domain sockets for out-of-process mediation.
- Supported deterministic capability token minting and verification across process boundaries.
- Implemented session audit replay engine (`replay_audit_log`) and provenance DAG reconstruction (`reconstruct_provenance_graph`) from SHA-256 hash-chained JSONL logs.
- Implemented Graphviz DOT export (`to_dot`) for visual inspection of information-flow slices and taint propagation.
- Integrated `taintgate serve`, `taintgate audit replay`, and `taintgate audit export-dot` CLI commands.
- Added comprehensive integration tests (`tests/test_pdp_socket_service.py` and `tests/test_audit_cli.py`), reaching 71 passing tests across the test suite.

## 2026-10-11: Milestone M4 — Tier 2 Precision Features & Ablation Study
- Implemented `FieldSensitiveLabeler`: path-level labeling and leaf-node redaction for structured JSON payloads.
- Implemented `QuarantinedExtractor` suite (`RegexExtractor`, `AllowlistExtractor`, `NumericExtractor`, and `ExtractorRegistry`) for safe, isolated type-checked endorsement.
- Implemented `ExactProvenanceResolver`: per-argument taint resolution based on provenance DAG evidence, eliminating over-blocking on clean user literals.
- Implemented `CleanContextCoordinator` & `CleanContextSubAgent`: architectural isolation pattern delegating sensitive tasks into unpolluted context windows.
- Built Tier 2 precision ablation suite (`eval/ablations.py`): measured utility recovery from 50.0% up to 100.0% while maintaining 0.0% ASR and reducing approval burden to 5.6%.
- Published empirical ablation findings in `docs/evaluation.md`.
- Expanded test suite to 77 passing tests across property, integration, golden policy, and ablation suites.

## 2026-10-11: Milestone M5 — Adaptive Attacker Robustness & Overhead Profiling (Tier 2 DoD Complete)
- Built `AdaptiveAttackerSuite` (`eval/adaptive_attacker.py`) testing four evasion vectors: Base64 encoding smuggling, multi-turn instruction splitting, dynamic MCP tool schema hijacking, and capability token forgery.
- Verified that TaintGate achieves 0.0% adaptive ASR due to semantic information-flow tracking and cryptographic tool pinning/signing, while naive filters and keyword inspectors suffer up to 100% and 50% adaptive ASR respectively.
- Built high-precision micro-benchmark profiler (`eval/benchmark_overhead.py`): measured median policy check latency (60.55 µs), HMAC token verification (22.46 µs), backward slice computation (8.18 µs), and proxy mediation (37.63 µs) with p99 under 130 µs.
## 2026-10-11: Phase 1 — GitHub Actions CI & Packaging Polish
- Created multi-version matrix CI workflow (`.github/workflows/ci.yml`) testing on Python 3.11, 3.12, and 3.13.
- Added automated wheel and source distribution packaging verification (`python -m build`, `twine check`).
- Standardized `pyproject.toml` SPDX license and bumped package version to `0.2.0`.
- Verified CLI entrypoint installation and tagged release `v0.2.0`.

## 2026-10-11: Milestone M6 — Tier 3 Formal Non-Interference & Workshop Paper
- Formulated small-step operational transition calculus ($\langle \Sigma, \mathcal{G}, \tau, \mathcal{A} \rangle \to \langle \Sigma', \mathcal{G}', \tau', \mathcal{A}' \rangle$) for LLM agent reference monitors.
- Formally proved Theorem 1 (Integrity Non-Interference / Biba duality) and Theorem 2 (Confidentiality Confinement / Bell–LaPadula duality) under low-equivalence relations ($\approx_I, \approx_C$).
- Proved soundness conditions for Tier 2 precision refinements (field-sensitive projection, quarantined extractors, and clean sub-agent isolation).
- Built automated lemma verification suite (`tests/test_formal_noninterference.py`) using Hypothesis; test suite expanded to 87 passing tests.
- Authored academic workshop paper (`docs/paper.md`) tying together theoretical proofs, systems architecture, and empirical AgentDojo findings. Full Tier 3 capstone satisfied.




