# Formal Security Argument: Non-Interference in TaintGate

**Academic Context**: CS6570 Secure Systems & CS6843 Program Analysis  
**System**: TaintGate (Milestone M6 — Tier 3 Formal Foundation)  
**Date**: October 2026

---

## 1. Introduction and Objectives

Modern Large Language Model (LLM) agents operate as probabilistic, autoregressive text engines that interleave generative text tokens with executable tool invocations (ReAct loops). Because an LLM combines instructions, retrieved documents, external web pages, and user secrets into a unified attention context, **indirect prompt injection (IPI)** can cause the model to act as an attacker-controlled confused deputy.

Probabilistic guardrails (such as fine-tuned alignment, system prompt instructions, or auxiliary LLM inspectors) are inherently heuristic: an adaptive attacker can evade them via syntax obfuscation, multi-turn splitting, or semantic rephrasing.

**TaintGate** enforces security **strictly outside the model** by realizing a classical reference monitor (Anderson'72, Graham-Denning'72). In this document, we construct the formal operational calculus of TaintGate, define possibilistic and observational non-interference over its information-flow lattice, and prove that:
1. **Low-integrity (untrusted) inputs cannot induce unauthorized state-changing tool executions** (*Integrity Non-Interference*).
2. **High-confidentiality (secret) assets cannot reach external sinks without authorized policy declassification** (*Confidentiality Confinement*).
3. **Fine-grained precision refinements (field-sensitive labeling, quarantined extractors, and clean sub-agents) preserve non-interference invariance** (*Soundness of Precision*).

---

## 2. Mathematical Preliminaries & Label Lattice

### 2.1 The Product Lattice $\mathcal{L} = \mathcal{I} \times \mathcal{C}$

Let $\mathcal{L} = \langle \mathcal{I} \times \mathcal{C}, \sqsubseteq, \sqcup, \sqcap, \bot, \top \rangle$ be a bounded product lattice formed by the Cartesian product of an **Integrity Lattice** $\mathcal{I}$ (Biba'77) and a **Confidentiality Lattice** $\mathcal{C}$ (Bell–LaPadula'73).

#### Integrity Ordering ($\mathcal{I}$)
The integrity scale reflects the trustworthiness and provenance of information:
$$\mathcal{I} = \{\text{trusted}, \text{endorsed}, \text{untrusted}\}$$
Ordered by information integrity (cleaner $\succ$ contaminated):
$$\text{untrusted} \sqsubset_I \text{endorsed} \sqsubset_I \text{trusted}$$
* Greatest element (cleanest): $\top_I = \text{trusted}$
* Least element (most contaminated): $\bot_I = \text{untrusted}$
* Join operator (lower-bound integrity under data mixing): $i_1 \sqcup_I i_2 = \min_{\sqsubseteq_I}(i_1, i_2)$
* Meet operator: $i_1 \sqcap_I i_2 = \max_{\sqsubseteq_I}(i_1, i_2)$

#### Confidentiality Ordering ($\mathcal{C}$)
The confidentiality scale reflects secrecy and exfiltration risk:
$$\mathcal{C} = \{\text{public}, \text{internal}, \text{secret}\}$$
Ordered by information sensitivity (restricted $\succ$ open):
$$\text{public} \sqsubset_C \text{internal} \sqsubset_C \text{secret}$$
* Greatest element (highest secrecy): $\top_C = \text{secret}$
* Least element (public data): $\bot_C = \text{public}$
* Join operator (upper-bound secrecy under data mixing): $c_1 \sqcup_C c_2 = \max_{\sqsubseteq_C}(c_1, c_2)$
* Meet operator: $c_1 \sqcap_C c_2 = \min_{\sqsubseteq_C}(c_1, c_2)$

#### Product Lattice Operators
For any labels $\ell_1 = (i_1, c_1)$ and $\ell_2 = (i_2, c_2) \in \mathcal{L}$:
1. **Partial Order**:
   $$\ell_1 \sqsubseteq \ell_2 \iff (i_1 \sqsubseteq_I i_2) \land (c_1 \sqsubseteq_C c_2)$$
2. **Conservative Information Join ($\sqcup$)**:
   When an LLM context combines multiple pieces of data, integrity degrades to the lowest input integrity, and confidentiality escalates to the highest secrecy:
   $$\ell_1 \sqcup \ell_2 = (i_1 \sqcup_I i_2, c_1 \sqcup_C c_2) = (\min_{\sqsubseteq_I}(i_1, i_2), \max_{\sqsubseteq_C}(c_1, c_2))$$
3. **Lattice Axioms**:
   The operator $\sqcup$ satisfies:
   * **Commutativity**: $\ell_1 \sqcup \ell_2 = \ell_2 \sqcup \ell_1$
   * **Associativity**: $(\ell_1 \sqcup \ell_2) \sqcup \ell_3 = \ell_1 \sqcup (\ell_2 \sqcup \ell_3)$
   * **Idempotence**: $\ell \sqcup \ell = \ell$
   * **Monotonicity**: $\ell_1 \sqsubseteq \ell_2 \implies (\ell_1 \sqcup \ell_3) \sqsubseteq (\ell_2 \sqcup \ell_3)$

---

## 3. Small-Step Operational Transition Semantics

### 3.1 Syntax and Domains

* **Values and Variables**: $v \in \mathcal{V}$, $x \in \mathcal{X}$.
* **Tools**: $t \in \mathcal{T}$, each equipped with an effect class:
  $$E(t) \in \{\text{read}, \text{local\_write}, \text{external}, \text{irreversible}\}$$
* **Arguments**: $\vec{a} = \langle a_1, a_2, \dots, a_k \rangle$, where each $a_j \in \mathcal{V}$.
* **Decisions**: $d \in \{\text{ALLOW}, \text{DENY}, \text{APPROVE}\}$.
* **Approval Grants**: $\mathcal{A}: \mathcal{T} \times \mathcal{V}^* \to \{\text{ONCE}, \text{SESSION}, \text{FOREVER}, \emptyset\}$.
* **Provenance DAG**: $\mathcal{G} = \langle V, E_G, \lambda \rangle$ where $V$ are execution and data nodes, $E_G \subseteq V \times V$ are directed dependency edges, and $\lambda: V \to \mathcal{L}$ labels nodes with their product lattice security level.
* **Observable Trace**: $\tau \in (\mathcal{T} \times \mathcal{V}^*)^*$, an append-only sequence of executed tool calls.

### 3.2 Machine Configuration

A global reference monitor configuration is a 4-tuple:
$$C = \langle \Sigma, \mathcal{G}, \tau, \mathcal{A} \rangle$$
where $\Sigma = \langle \ell_{\text{ctx}}, \sigma \rangle$:
* $\ell_{\text{ctx}} \in \mathcal{L}$ is the current cumulative context taint of the agent session.
* $\sigma: \mathcal{X} \to \mathcal{V} \times \mathcal{L}$ maps known state variables to labelled values.

### 3.3 Reference Monitor Decision Function $\mathcal{R}$

Given a tool call request $\text{call}(t, \vec{a})$ in configuration $C$, the reference monitor deterministically evaluates:
$$\mathcal{R}(\text{call}(t, \vec{a}), C) \in \{\text{ALLOW}, \text{DENY}, \text{APPROVE}\}$$

Let $\ell_{\text{eff}} = \ell_{\text{ctx}} \sqcup \bigsqcup_{a \in \vec{a}} \text{Label}(a) = (i_{\text{eff}}, c_{\text{eff}})$.
Under the **Rule of Two** preset:
1. **Rule of Two (Denial of Unchecked External Exfiltration)**:
   If $c_{\text{eff}} \ge_C \text{internal}$ and $E(t) = \text{external}$ and $\text{Recipient}(\vec{a}) \notin \text{Contacts}$:
   $$\mathcal{R}(\text{call}(t, \vec{a}), C) = \text{DENY}$$
2. **Approval Gate (Contaminated State Modification)**:
   If $i_{\text{eff}} \le_I \text{untrusted}$ and $E(t) \in \{\text{local\_write}, \text{external}, \text{irreversible}\}$:
   $$\mathcal{R}(\text{call}(t, \vec{a}), C) = \begin{cases} \text{ALLOW} & \text{if } (t, \vec{a}) \in \mathcal{A} \\ \text{APPROVE} & \text{otherwise} \end{cases}$$
3. **Passive Read / Authorized Clean Call**:
   Otherwise, if no deny or approval rule matches:
   $$\mathcal{R}(\text{call}(t, \vec{a}), C) = \text{ALLOW}$$

### 3.4 Operational Transition Rules

#### [STEP-READ] Passive Information Retrieval
When a read tool $t$ is called with output label $\ell_{\text{out}} = (i_{\text{out}}, c_{\text{out}})$:
$$\frac{\mathcal{R}(\text{call}(t, \vec{a}), C) = \text{ALLOW} \quad E(t) = \text{read} \quad \text{Exec}(t, \vec{a}) \Downarrow v}
{\langle \Sigma, \mathcal{G}, \tau, \mathcal{A} \rangle \xrightarrow{\text{call}(t, \vec{a})} \langle \Sigma', \mathcal{G}', \tau \cdot \langle t, \vec{a} \rangle, \mathcal{A} \rangle}$$
where:
* $\ell_{\text{ctx}}' = \ell_{\text{ctx}} \sqcup \ell_{\text{out}}$
* $\mathcal{G}' = \mathcal{G} \cup \{v_{\text{new}}\}$ with edges from inputs to $v_{\text{new}}$ and $\lambda(v_{\text{new}}) = \ell_{\text{out}}$.

#### [STEP-WRITE-ALLOW] Authorized Clean State Action
When a write or external tool is called and cleared by the monitor:
$$\frac{\mathcal{R}(\text{call}(t, \vec{a}), C) = \text{ALLOW} \quad E(t) \neq \text{read} \quad \text{Exec}(t, \vec{a}) \Downarrow \text{ok}}
{\langle \Sigma, \mathcal{G}, \tau, \mathcal{A} \rangle \xrightarrow{\text{call}(t, \vec{a})} \langle \Sigma, \mathcal{G}', \tau \cdot \langle t, \vec{a} \rangle, \mathcal{A} \setminus \{(t, \vec{a}) \mid \text{scope}=\text{ONCE}\} \rangle}$$

#### [STEP-DENY] Blocked Dangerous Action
When a tool invocation violates policy:
$$\frac{\mathcal{R}(\text{call}(t, \vec{a}), C) = \text{DENY}}
{\langle \Sigma, \mathcal{G}, \tau, \mathcal{A} \rangle \xrightarrow{\text{call}(t, \vec{a})} \langle \Sigma, \mathcal{G}, \tau, \mathcal{A} \rangle \quad [\text{Exception: Blocked with Slice}]}$$

---

## 4. Formal Definition of Non-Interference

### 4.1 Low-Equivalence Relation ($\approx_L$)

Following Goguen & Meseguer (1982) and McLean (1992), we formulate non-interference by defining equivalence relations over configurations with respect to observation levels.

#### Definition 1 (Integrity Low-Equivalence $\approx_I$)
Two configurations $C_1 = \langle \Sigma_1, \mathcal{G}_1, \tau_1, \mathcal{A}_1 \rangle$ and $C_2 = \langle \Sigma_2, \mathcal{G}_2, \tau_2, \mathcal{A}_2 \rangle$ are **integrity low-equivalent** ($C_1 \approx_I C_2$) iff:
1. All trusted inputs, environment variables, and system instructions are identical:
   $$\forall x \in \text{dom}(\Sigma_1) \cap \text{dom}(\Sigma_2), \quad i(\sigma_1(x)) \ge_I \text{endorsed} \implies \sigma_1(x) = \sigma_2(x)$$
2. $C_1$ and $C_2$ may differ **arbitrarily** in values labelled $\text{untrusted}$.

#### Definition 2 (Confidentiality Low-Equivalence $\approx_C$)
Two configurations $C_1$ and $C_2$ are **confidentiality low-equivalent** ($C_1 \approx_C C_2$) iff:
1. All public inputs and environment variables are identical:
   $$\forall x, \quad c(\sigma_1(x)) \le_C \text{internal} \implies \sigma_1(x) = \sigma_2(x)$$
2. $C_1$ and $C_2$ may differ **arbitrarily** in values labelled $\text{secret}$.

### 4.2 Observable Trace Projections

* **Integrity Projection ($\pi_I(\tau)$)**: The projection of trace $\tau$ onto state-modifying actions executed without prior explicit human approval:
  $$\pi_I(\tau) = [ \langle t, \vec{a} \rangle \in \tau \mid E(t) \in \{\text{local\_write}, \text{external}, \text{irreversible}\} \land \text{unapproved} ]$$
* **External Projection ($\pi_{\text{ext}}(\tau)$)**: The projection of trace $\tau$ onto external sink calls:
  $$\pi_{\text{ext}}(\tau) = [ \langle t, \vec{a} \rangle \in \tau \mid E(t) = \text{external} ]$$

---

## 5. Security Theorems and Soundness Proofs

### Theorem 1: Integrity Non-Interference (Biba Duality)

> **Theorem 1 (Resistance to Indirect Prompt Injection).**  
> Let $C_1 \approx_I C_2$ be two configurations whose high-integrity states are identical but whose untrusted inputs (e.g. attacker-controlled documents or web pages) differ arbitrarily. If the human operator grants no approvals ($\mathcal{A}_1 = \mathcal{A}_2 = \emptyset$), then for any sequence of steps, the observable trace of unapproved state modifications is identical:
> $$\pi_I(\tau_1') = \pi_I(\tau_2')$$

#### Proof by Structural Induction:
1. **Base Case**: Initially, $\tau_1 = \tau_2 = \epsilon \implies \pi_I(\tau_1) = \pi_I(\tau_2) = \epsilon$. Holds trivially.
2. **Inductive Step**: Assume $\pi_I(\tau_1) = \pi_I(\tau_2)$ after $k$ steps. Consider step $k+1$ where the agent emits $\text{call}(t, \vec{a})$:
   * **Case A: The agent was exposed to an untrusted input** at some turn $m \le k$.  
     By rule `[STEP-READ]`, $\ell_{\text{ctx}} = \ell_{\text{ctx}} \sqcup \ell_{\text{untrusted}}$. Since $\ell_{\text{untrusted}} = (\text{untrusted}, c)$, by definition of $\sqcup$:
     $$i_{\text{ctx}} = \min(i_{\text{prev}}, \text{untrusted}) = \text{untrusted}$$
   * **Subcase A.1: $E(t) = \text{read}$.**  
     $t$ has no external or state-modifying effect. Thus $\langle t, \vec{a} \rangle \notin \pi_I(\tau)$. The projection remains unchanged.
   * **Subcase A.2: $E(t) \in \{\text{local\_write}, \text{external}, \text{irreversible}\}$.**  
     The reference monitor evaluates $\mathcal{R}(\text{call}(t, \vec{a}), C)$. Because $i_{\text{eff}} = i_{\text{ctx}} \sqcup \dots = \text{untrusted}$, Rule 2 applies:
     $$\mathcal{R}(\text{call}(t, \vec{a}), C) = \text{APPROVE}$$
     Since $\mathcal{A} = \emptyset$ (no human approval), the step cannot proceed via `[STEP-WRITE-ALLOW]`. Execution is suspended or rejected.
     Therefore, $\langle t, \vec{a} \rangle$ is **never appended** to $\tau$ without human endorsement.
   * **Case B: The agent was never exposed to untrusted input.**  
     Then $i_{\text{ctx}} \ge_I \text{endorsed}$. Since $C_1 \approx_I C_2$, all inputs up to step $k$ were identical, meaning the deterministic model context received identical inputs, emitting identical tool calls.
3. By induction, $\pi_I(\tau_1') = \pi_I(\tau_2')$ for all finite traces. $\blacksquare$

---

### Theorem 2: Confidentiality Confinement (Bell–LaPadula Duality)

> **Theorem 2 (Exfiltration Invariance).**  
> Let $C_1 \approx_C C_2$ be two configurations whose public states are identical but whose secret data assets differ ($s_1 \neq s_2$). Under the Rule of Two policy, no sequence of model actions can exfiltrate secret data to an unauthorized external recipient:
> $$\pi_{\text{ext}}(\tau_1') = \pi_{\text{ext}}(\tau_2')$$

#### Proof:
1. Let secret asset $s$ have label $\ell_s = (i_s, \text{secret})$.
2. If $s$ is accessed via any tool call, rule `[STEP-READ]` updates the context taint:
   $$c_{\text{ctx}}' = c_{\text{ctx}} \sqcup \text{secret} = \max(c_{\text{ctx}}, \text{secret}) = \text{secret}$$
3. Any subsequent tool invocation with $E(t) = \text{external}$ incurs effective confidentiality:
   $$c_{\text{eff}} \ge_C c_{\text{ctx}}' = \text{secret} \ge_C \text{internal}$$
4. If the destination recipient is not in the trusted contacts allowlist:
   $$\mathcal{R}(\text{call}(t, \vec{a}), C) = \text{DENY} \quad \text{(Rule of Two, Clause 1)}$$
5. Transition rule `[STEP-DENY]` triggers, raising an exception and halting exfiltration. The call is never appended to $\tau$.
6. If the destination is an authorized recipient, it acts as an approved declassification sink under explicit policy rule.
7. Hence, differing secret values cannot cause observable differences across unauthorized external sinks. $\blacksquare$

---

### Theorem 3: Soundness of Provenance Slicing

> **Theorem 3 (Completeness of Explanation Graph).**  
> For any blocked or approved node $v_{\text{sink}} \in V$ in DAG $\mathcal{G} = \langle V, E_G, \lambda \rangle$, the backward program slice:
> $$\text{Slice}(v_{\text{sink}}) = \{ u \in V \mid u \rightsquigarrow^* v_{\text{sink}} \}$$
> contains all nodes with transitive causal influence on $v_{\text{sink}}$.

#### Proof:
1. By construction of `[STEP-READ]` and `[STEP-WRITE]`, every argument $a_j$ supplied to a tool call creates directed edges $(u_j, v_{\text{sink}})$ where $u_j$ is the generator of $a_j$.
2. In session-level tracking, an implicit edge $(v_{\text{ctx}}, v_{\text{sink}})$ is added from the active context head to the invocation node.
3. The relation $\rightsquigarrow^*$ is the reflexive-transitive closure of $E_G$.
4. By induction on graph path length, every node that contributed to the taint label $\lambda(v_{\text{sink}})$ has a path to $v_{\text{sink}}$ and is therefore included in $\text{Slice}(v_{\text{sink}})$. $\blacksquare$

---

### Theorem 4: Soundness of Tier 2 Precision Refinements

#### Lemma 4.1 (Field-Sensitive Labeling Soundness)
*Let $J$ be a structured JSON payload with schema $\mathcal{S}$. Let $\text{PathLabel}(p)$ assign labels to path $p \in \text{paths}(J)$.*  
Field-sensitive projection is sound iff the root label satisfies:
$$\ell(J) \sqsubseteq \bigsqcup_{p \in \text{paths}(J)} \text{PathLabel}(p)$$
*Proof*: When an argument $a_j$ is extracted from path $p$, its effective label is $\text{PathLabel}(p)$. Since $\text{PathLabel}(p) \sqsubseteq \ell(J)$, isolating sensitive paths preserves secrecy bounds on untainted fields without leaking contaminated attributes. $\blacksquare$

#### Lemma 4.2 (Quarantined Extractor Soundness)
*Let $\mathcal{X}: \text{String} \to \mathcal{T}_{\text{typed}}$ be an extractor validator (e.g. Regex or Numeric schema).*  
Declassification $\text{untrusted} \to \text{endorsed}$ is sound iff:
$$\forall s \in \text{String}, \quad \mathcal{X}(s) \neq \bot \implies \mathcal{X}(s) \in \mathcal{L}_{\text{clean}}$$
where $\mathcal{L}_{\text{clean}}$ is a regular grammar containing no control sequences, prompt delimiters, or instruction escape tokens.  
*Proof*: Because the output alphabet is restricted to benign literal tokens (e.g. pure digits `^[0-9]+$`), no adversarial instruction payload can survive validation to alter the agent's semantic execution path. $\blacksquare$

#### Lemma 4.3 (Clean Sub-Agent Context Isolation)
*Let coordinator $A_0$ spawn sub-agent $A_1$ with isolated configuration $C_1 = \langle \Sigma_1, \mathcal{G}_1, \tau_1, \emptyset \rangle$.*  
If $C_1$ is initialized with clean context $\ell_{\text{ctx}, 1} = \bot_{\text{taint}} = (\text{trusted}, \text{public})$, then:
$$\text{Taint}(C_1) \cap \text{Taint}(C_0) = \emptyset$$
*Proof*: Sub-agent $A_1$ executes in an independent process/context. Taint accumulation in $\mathcal{G}_1$ does not commute into $\mathcal{G}_0$ except via explicit return values passed through the coordinator's reference monitor filter. $\blacksquare$

---

## 6. Summary of Theoretical Guarantees

| Property | Classical Model | TaintGate Enforcement | Invariant Guaranteed |
|---|---|---|---|
| **Integrity** | Biba Strict Integrity | External Reference Monitor | Untrusted inputs cannot trigger state side effects without human sign-off |
| **Confidentiality** | Bell–LaPadula $\star$-Property | Rule of Two Engine | Secrets cannot reach external recipients without explicit policy declassification |
| **Auditability** | Graham-Denning Access Matrix | Hash-Chained JSONL ($H_i$) | Every decision is cryptographically anchored and replayable |
| **Explainability** | Program Slicing (Weiser'84) | Provenance Reachability DAG | Every block provides a minimal causal proof path from contamination to sink |
