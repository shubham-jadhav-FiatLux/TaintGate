# Labels and Policy Semantics

## 1. Information-Flow Product Lattice

TaintGate constructs a formal product lattice $\mathcal{L} = \mathcal{I} \times \mathcal{C} \times \mathcal{P}(\mathcal{R})$ combining Biba's integrity model, Bell–LaPadula's (BLP) confidentiality model, and decentralized recipient/reader bounds.

### 1.1 Integrity Domain ($\mathcal{I}$)
The integrity lattice models provenance and trust. Higher levels reflect higher trustworthiness.

$$\text{TRUSTED} \succ \text{ENDORSED} \succ \text{UNTRUSTED}$$

- **`TRUSTED`**: Content originating directly from the authenticated user or verified first-party tools.
- **`ENDORSED`**: Content originating from untrusted sources that has passed through a verified declassifier, schema sanitizer, or human approval.
- **`UNTRUSTED`**: Arbitrary third-party content (scraped websites, external emails, unverified files).

**Algebraic Operations:**
- **Join ($\sqcup$)**: Represents conservative taint accumulation when data sources are combined.
  $$i_1 \sqcup i_2 = \min(i_1, i_2)$$
  Combining trusted data with untrusted data yields `UNTRUSTED`.
- **Meet ($\sqcap$)**: Greatest lower bound of taint (dual).
  $$i_1 \sqcap i_2 = \max(i_1, i_2)$$

### 1.2 Confidentiality Domain ($\mathcal{C}$)
The confidentiality lattice models data sensitivity. Higher levels denote stricter sensitivity constraints.

$$\text{PUBLIC} \prec \text{INTERNAL} \prec \text{SECRET}$$

- **`PUBLIC`**: Information safe for general disclosure and external export.
- **`INTERNAL`**: Operational data restricted to internal organization/session tools.
- **`SECRET`**: High-value assets (credentials, keys, proprietary source code).

**Algebraic Operations:**
- **Join ($\sqcup$)**: Combines sensitivities when data is merged.
  $$c_1 \sqcup c_2 = \max(c_1, c_2)$$
  Combining public data with secret data yields `SECRET`.
- **Meet ($\sqcap$)**: Least upper bound of permissiveness.
  $$c_1 \sqcap c_2 = \min(c_1, c_2)$$

### 1.3 Permissible Flow Relation ($\sqsubseteq$)
In accordance with classical non-interference:
- **BLP (No Read-Up / No Write-Down)**: Information at confidentiality level $c_1$ may flow to $c_2$ only if $c_1 \le c_2$.
- **Biba (No Read-Down / No Write-Up)**: Information at integrity level $i_1$ may flow to $i_2$ only if $i_1 \ge i_2$.

Formally, a flow from source label $L_1 = (i_1, c_1)$ to target sink label $L_2 = (i_2, c_2)$ is valid ($L_1 \sqsubseteq L_2$) iff:
$$c_1 \le c_2 \quad \land \quad i_1 \ge i_2$$

---

## 2. Session Context Propagation (Tier 1 Soundness)

Because an LLM's autoregressive generation mixes all prompt tokens without internal isolation, Tier 1 enforces **sound context-level tainting**:

1. At session initialization $t=0$, context label $L_{\text{ctx}}^{(0)} = (\text{TRUSTED}, \text{PUBLIC})$.
2. Whenever the agent receives user input with label $L_{\text{user}}$, or a tool returns an observation with output label $L_{\text{obs}}$, the session context updates via lattice join:
   $$L_{\text{ctx}}^{(t+1)} = L_{\text{ctx}}^{(t)} \sqcup L_{\text{obs}}$$
3. For any subsequent tool call requested by the model at step $t+1$, all arguments implicitly carry the accumulated context taint $L_{\text{ctx}}^{(t+1)}$.

This formulation is provably **sound** (no untrusted or secret influence can escape untracked) but **conservative** (it may trigger false blocks if benign operations mix with untrusted data).

---

## 3. Tool Effects and Action Categories

Tools register effect annotations declaring their operational blast radius:

- **`read`**: Pure observation retrieval with no external or state side effects (`fs.read_file`, `web.fetch`).
- **`local_write`**: Modifies local system state (`fs.write_file`, updating local cache).
- **`external`**: Emits communication or requests across the network perimeter (`email.send`, `http.post`).
- **`irreversible`**: High-consequence mutations (deleting databases, executing financial payments).

---

## 4. Policy Rules & The Rule of Two

### 4.1 The Rule of Two Preset
The canonical security baseline is Meta's "Agents Rule of Two":
> **Never simultaneously combine: (1) Untrusted Inputs, (2) Sensitive Data, and (3) External or State-Changing Actions without human authorization.**

When `preset: rule_of_two` is active:
- If $L_{\text{ctx}}.\text{integrity} \le \text{UNTRUSTED}$ AND $L_{\text{ctx}}.\text{confidentiality} \ge \text{INTERNAL}$ AND effect $\in \{\text{external}, \text{irreversible}\}$: **DENIED**.
- If $L_{\text{ctx}}.\text{integrity} \le \text{UNTRUSTED}$ AND effect $\in \{\text{external}, \text{local\_write}, \text{irreversible}\}$: **APPROVE** (requires human sign-off).
- If effect is `read`: **ALLOW** (reads are permitted to update context labels).

### 4.2 Decisions
The policy engine returns one of four decisions:
1. **`ALLOW`**: The operation conforms to policy and executes immediately.
2. **`DENY`**: The operation violates an invariant (e.g. exfiltration of secret data) and is blocked with an explanation.
3. **`APPROVE`**: Suspicious or sensitive operation held pending human confirmation across the trusted path.
4. **`REDACT`**: The operation is allowed only after confidential fields matching the policy pattern are excised from arguments.
