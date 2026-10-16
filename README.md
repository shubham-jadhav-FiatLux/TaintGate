# TaintGate

**Information-Flow Control for LLM Agents**

[![CI](https://github.com/shubham-jadhav-FiatLux/TaintGate/actions/workflows/ci.yml/badge.svg)](https://github.com/shubham-jadhav-FiatLux/TaintGate/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)

TaintGate is a deterministic **reference monitor outside the LLM** that labels data by provenance and sensitivity, tracks how labels flow through an agent session, and **allows / blocks / asks a human** before risky tool calls execute.

Security in TaintGate does not depend on probabilistic model guardrails or fine-tuning behavior. Instead, it places a trusted mediation barrier between the agent harness and external tools, enforcing classical non-interference and information-flow principles (Biba and Bell–LaPadula lattices).

---

## Key Features

- **Formal Product Lattice ($\text{Biba} \times \text{Bell–LaPadula}$)**:
  - **Integrity**: `trusted` $\succ$ `endorsed` $\succ$ `untrusted` (Biba model: prevents untrusted data from corrupting trusted execution).
  - **Confidentiality**: `public` $\prec$ `internal` $\prec$ `secret` (Bell–LaPadula model: prevents sensitive data from leaking to untrusted sinks).
  - Sound join ($\sqcup$) and meet ($\sqcap$) operators with verified algebraic lattice properties.
- **Rule of Two & Policy DSL**:
  - Declarative YAML/Python policy specifications.
  - Native **Rule of Two** preset: never automatically combine untrusted input, sensitive data, and external/state-changing tool effects.
  - Per-tool and per-resource effect annotations (`read`, `local_write`, `external`, `irreversible`).
- **Explainable Slicing (Provenance Graph)**:
  - Tracks session-level data flows as a directed acyclic graph (DAG).
  - Explains blocked actions through backward program slicing (source $\rightarrow$ sink path), identifying the exact point untrusted data poisoned the context.
- **Tamper-Evident Audit Logging**:
  - Hash-chained JSONL records ($H_i = \text{SHA256}(H_{i-1} \parallel \text{Event}_i)$) with session replay capability.
- **Embeddable Policy Decision Point**:
  - A small, dependency-light core (`taintgate.core`) that any enforcement point can call in-process or over a Unix domain socket.

---

## Architecture

```
 user ──► agent host (Claude Desktop/Code, LangChain, OpenAI SDK, AgentDojo)
                 │  tool calls / results
                 ▼
        ┌──────────────────────────── TaintGate (reference monitor, TCB) ────────────────────────────┐
        │ interception: MCP proxy │ framework wrappers                                              │
        │ labels: provenance + sensitivity on every datum   provenance graph (flows, per session)  │
        │ policy engine (deterministic DSL) → allow · deny · approve · redact                       │
        │ approval UI (trusted path)   audit (hash chain, replay)   lint (static analyzer)          │
        └───────────────────────────────────────────────────────────────────────────────────────────┘
                 │  only permitted calls
                 ▼
        MCP servers / tools (files, email, web, shell…)
```

---

## Quickstart

### Installation

```bash
git clone https://github.com/shubh/TaintGate.git
cd TaintGate
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

### Running Tests

Verify formal lattice laws (Hypothesis property tests) and golden policy suites:

```bash
pytest tests/ -v
```

---

## Policy Example (`policy.yaml`)

```yaml
labels:
  integrity: [trusted, endorsed, untrusted]          # high → low
  confidentiality: [public, internal, secret]        # low → high

tools:
  fs.read_file:
    effect: read
    output:
      integrity: trusted
      confidentiality: internal
    overrides:
      - path: "~/company/secrets/**"
        confidentiality: secret
  web.fetch:
    effect: read
    output:
      integrity: untrusted
      confidentiality: public
  email.send:
    effect: external
    recipients_arg: to
  fs.write_file:
    effect: local_write

policy:
  preset: rule_of_two
  rules:
    - deny: external
      when: data.confidentiality >= internal and recipient not in contacts
    - approve: external
      when: context.integrity == untrusted
    - approve: local_write
      when: context.integrity == untrusted
```

---

## CLI Reference

### 1. Static Policy Linter
Check policies against capability matrices and dangling rules:
```bash
taintgate lint --config policy.yaml
```

### 2. Live MCP Interception Proxy
Transparently wrap any stdio MCP server with reference monitor policy checks and tamper-evident audit logging:
```bash
taintgate proxy --config policy.yaml --audit audit.jsonl -- python my_mcp_server.py
```

### 3. Unix Domain Socket PDP Daemon
Run TaintGate as an out-of-process Policy Decision Point:
```bash
taintgate serve --socket /tmp/taintgate.sock --config policy.yaml
```

### 4. Audit Log Integrity, Replay & Export
Verify cryptographic SHA-256 hash chaining, replay session dataflows, or export provenance slices to Graphviz:
```bash
# Verify log integrity
taintgate audit verify --log audit.jsonl

# Replay session event trace
taintgate audit replay --log audit.jsonl

# Export provenance DAG to Graphviz DOT
taintgate audit export-dot --log audit.jsonl --output provenance.dot
```

---

## Documentation

- [Threat Model](docs/threat-model.md): Assets, adversaries, trust assumptions, and scope.
- [Labels and Policy](docs/labels-and-policy.md): Lattice mathematics and policy evaluation semantics.
- [Formal Security Argument](docs/formal_security_argument.md): Operational small-step transition calculus, non-interference theorems, and inductive proofs.
- [Workshop Paper](docs/paper.md): Academic research writeup formatted for systems-security publication.
- [Integrations Guide](docs/integrations.md): MCP proxy and Python framework integration.
- [Evaluation Plan & Results](docs/evaluation.md): Benchmark results, baseline comparisons, and metrics.
- [Limitations](docs/limitations.md): Explicit operational bounds, covert channels, and OS separation.
- [Development Log](docs/devlog.md): Milestone progress and architectural decisions.

