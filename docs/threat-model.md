# TaintGate Threat Model

## 1. Overview and Core Philosophy

In agentic systems, Large Language Models (LLMs) transition from passive text oracles to active autonomous agents empowered with tool execution (file manipulation, web requests, email transmission, code execution). The key architectural vulnerability of the Transformer architecture is that self-attention possesses **no inherent notion of trust or provenance**: a system-prompt token, a user-instruction token, and untrusted payload data ingested from an external website or email reside in the exact same token space.

Consequently, indirect prompt injection (IPI) cannot be reliably solved via model-internal defenses (such as fine-tuning, system prompt exhortations, or classifier inspectors). TaintGate models the LLM as an **untrusted, confused deputy** situated inside an agent host. Enforcement is strictly externalized into a deterministic **reference monitor** governed by information-flow control (IFC).

---

## 2. Assets

TaintGate protects the following assets against unauthorized access and corruption:

1. **Confidential Data and Secrets**:
   - Files stored on the host filesystem (e.g., credentials, internal records, intellectual property).
   - Private communication stores (emails, chat logs, contact lists).
   - API tokens and authentication keys.
2. **State and Action Integrity**:
   - The user's external accounts and services (preventing unauthorized financial transfers, external messaging, data exfiltration).
   - The user's local operating environment (preventing destructive writes, unwanted process spawning, privilege escalations).
3. **Execution Decision Path**:
   - The integrity of the decision process itself, ensuring untrusted third-party content cannot commandeer privileged actions without explicit authorization.

---

## 3. Adversary Model

### Capabilities
- The adversary controls or influences **content** that the agent ingests:
  - Untrusted web pages visited via browsing tools (`web.fetch`).
  - Incoming email messages and document attachments (`email.read`).
  - Untrusted files and resumes uploaded or analyzed (`fs.read_file`).
  - Descriptions and schemas advertised by third-party MCP servers.
- The adversary can craft sophisticated indirect prompt injection payloads embedded in this content (zero-width characters, encoded instructions, role-confusion prompts, jailbreak patterns).

### Non-Capabilities (Restrictions)
- The adversary **cannot** modify the reference monitor itself, its configuration, or the active policy rules (the TCB is protected).
- The adversary **cannot** modify the user's initial prompt directly.
- The adversary **cannot** tamper with the trusted path of human approval prompts or cryptographic audit logs.

---

## 4. Adversary Goals

1. **Exfiltration**: Leaking confidential data (e.g., internal company files) to external endpoints under the adversary's control.
2. **Unauthorized State Mutations**: Triggering high-impact side effects (sending malicious emails to third parties, overwriting critical files, modifying system configuration).
3. **Integrity Violations**: Forcing trusted decisions to rely on untrusted, unendorsed inputs.

---

## 5. Trusted Computing Base (TCB)

The TCB comprises:
1. The host operating system kernel and runtime process boundaries.
2. The TaintGate reference monitor core (`taintgate.core`), interceptors, and policy evaluator.
3. The policy configuration file (`policy.yaml`) and tool effect annotations.
4. The human operator communicating across a trusted path.

**The LLM itself is explicitly untrusted and excluded from the TCB.** It is treated as an arbitrary mixing function that may combine any elements present in its context window.

---

## 6. Out of Scope & Limitations

The following threat vectors are deliberately out of scope for TaintGate as a standalone reference monitor:
1. **Host Sandbox Breakouts**: OS-level isolation and container escape prevention are the responsibility of the system execution tier (an OS-level sandbox), not of the reference monitor.
2. **Hardware and Microarchitectural Side Channels**: Cache timing, speculative execution leakage, and acoustic/EM side channels.
3. **Human Approval Fatigue / Bad Approvals**: If the human operator explicitly approves an action despite a clear flow explanation warning of untrusted taint, the monitor obeys the human grant.
4. **Policy Misconfigurations**: Actions explicitly allowed by a lax user-defined policy.
