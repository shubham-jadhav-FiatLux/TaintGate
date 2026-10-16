# Stated Limitations

TaintGate is designed with rigorous bounds regarding what it guarantees and what lies outside its protection domain.

---

## 1. Conservative Context Over-Blocking

Under Tier 1 context-level tainting, the reference monitor conservatively assumes that any data admitted into the LLM's context window can influence all subsequent outputs.
- **Limitation**: In long sessions where an agent reads an untrusted web page to research a query, the session context remains tainted with `integrity = untrusted` for the duration of the conversation. Subsequent legitimate tool actions (e.g. saving notes or sending an email) will trigger approval prompts or blocks unless explicit scoped human grants or Tier 2 precision declassification features are applied.
- **Mitigation**: Scoped approval grants ("allow this recipient for this session") and Tier 2 precision extractors.

---

## 2. No OS-Level Host Isolation

TaintGate operates at the semantic protocol level (mediating tool calls and arguments).
- **Limitation**: If an allowed tool binary itself contains a memory safety vulnerability (e.g. buffer overflow, command injection in a shell tool), TaintGate cannot prevent the tool process from executing arbitrary syscalls or escaping its process boundary.
- **Architecture Separation**: OS-level sandboxing (bubblewrap, Landlock, seccomp-bpf, gVisor, Firecracker) is orthogonal and out of scope: TaintGate decides whether a tool call may run, so deployments that execute untrusted tool binaries should also run them inside an OS-level sandbox.

---

## 3. Human Approval Bypass (Rubber-Stamping)

When an operation triggers an `APPROVE` decision, TaintGate displays a complete backward flow slice showing why the data is tainted.
- **Limitation**: If the user ignores the explanation and clicks "Approve", the security boundary is crossed. TaintGate provides a trusted path and provenance explanation, but cannot force human vigilance.

---

## 4. Covert Channels

Covert channels are out of scope:
- **Timing and Token Rate Channels**: An attacker encoding secrets via tool call timing variations or packet sizes.
- **Rejection Status Oracle**: Probing policy limits through sequence trial-and-error.

---

## 5. Scope Boundaries

TaintGate does **not** claim to mathematically "solve" all prompt injection attacks. It guarantees that **information cannot flow between annotated sources and unauthorized sinks without either satisfying the policy or obtaining explicit human endorsement**.
