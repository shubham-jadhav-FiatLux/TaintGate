/-
  Multi-Step Non-Interference over Execution Traces
  Author: Shubham Jadhav (IIT Madras)
  Date: October 2026

  Lifts the single-step results of TaintGate.NonInterference to whole runs
  (the reflexive-transitive closure of Step), by induction over the run.
-/
import TaintGate.Calculus
import TaintGate.NonInterference

namespace TaintGate

/-- One proposed call: tool, arguments, label of the observation it returns,
    and whether its recipient is authorised. The (untrusted) model may propose
    any sequence of these. -/
abbrev Input := Tool × List Argument × Label × Bool

/-- The configuration after an ALLOWed step (exactly the target of `Step.step_allow`). -/
def afterAllow (c : Config) (t : Tool) (a : List Argument) (o : Label) : Config :=
  { c with ctxLabel := Label.join c.ctxLabel o, trace := (t.name, a.map Argument.val) :: c.trace }

/-- Multi-step executions. `log` lists the (tool, recipientAuthorised) pairs that executed. -/
inductive Run : Config → List Input → Config → List (Tool × Bool) → Prop where
  | nil (c : Config) : Run c [] c []
  | allow (c c' : Config) (t : Tool) (a : List Argument) (o : Label) (r : Bool)
      (rest : List Input) (log : List (Tool × Bool)) :
      decide c t a r = Decision.allow →
      Run (afterAllow c t a o) rest c' log →
      Run c ((t, a, o, r) :: rest) c' ((t, r) :: log)
  | block (c c' : Config) (t : Tool) (a : List Argument) (o : Label) (r : Bool)
      (rest : List Input) (log : List (Tool × Bool)) :
      decide c t a r ≠ Decision.allow →
      Run c rest c' log →
      Run c ((t, a, o, r) :: rest) c' log

/-- Every ALLOW transition of `Run` is a `Step` of the paper's calculus. -/
theorem allow_is_step (c : Config) (t : Tool) (a : List Argument) (o : Label) (r : Bool)
    (h : decide c t a r = Decision.allow) : Step c t a o r (afterAllow c t a o) :=
  Step.step_allow c t a o r h

/-! ### Integrity -/

theorem join_keeps_untrusted (l o : Label) (h : l.integrity = .untrusted) :
    (Label.join l o).integrity = .untrusted := by
  simp [Label.join, h, Integrity.join]

theorem effective_keeps_untrusted : ∀ (args : List Argument) (ctx : Label),
    ctx.integrity = .untrusted → (effectiveLabel ctx args).integrity = .untrusted
  | [], _, h => h
  | a :: as, ctx, h => effective_keeps_untrusted as (Label.join ctx a.label) (join_keeps_untrusted _ _ h)

theorem untrusted_blocks_side_effect (c : Config) (t : Tool) (a : List Argument) (r : Bool)
    (hu : c.ctxLabel.integrity = .untrusted) (ha : c.approvals = [])
    (hs : t.effect.isStateModifying = true) : decide c t a r ≠ Decision.allow := by
  refine integrity_non_interference c t a r hs ?_ ha
  rw [effective_keeps_untrusted a c.ctxLabel hu]
  exact Nat.le_refl _

/-- Multi-step integrity confinement, by induction over the execution: from an untrusted,
    approval-free state, no state-modifying tool ever executes, whatever calls are proposed. -/
theorem tainted_run_has_no_side_effects :
    ∀ {c c' : Config} {xs : List Input} {log : List (Tool × Bool)},
    Run c xs c' log → c.ctxLabel.integrity = .untrusted → c.approvals = [] →
    ∀ e ∈ log, e.1.effect.isStateModifying = false := by
  intro c c' xs log hrun
  induction hrun with
  | nil c => intro _ _ e he; simp at he
  | allow c c' t a o r rest log hdec _ ih =>
    intro hu ha e he
    rcases List.mem_cons.mp he with h | h
    · subst h
      show t.effect.isStateModifying = false
      cases hs : t.effect.isStateModifying with
      | false => rfl
      | true => exact absurd hdec (untrusted_blocks_side_effect c t a r hu ha hs)
    · exact ih (join_keeps_untrusted _ _ hu) ha e h
  | block c c' t a o r rest log _ _ ih =>
    intro hu ha e he
    exact ih hu ha e he

/-- Two-run corollary: executions from tainted, approval-free states, driven by ARBITRARY
    (attacker-steered, possibly different) call sequences, have identical side-effect projections. -/
theorem two_run_side_effects_equal
    {c₁ c₁' c₂ c₂' : Config} {xs₁ xs₂ : List Input} {log₁ log₂ : List (Tool × Bool)}
    (h₁ : Run c₁ xs₁ c₁' log₁) (h₂ : Run c₂ xs₂ c₂' log₂)
    (hu₁ : c₁.ctxLabel.integrity = .untrusted) (ha₁ : c₁.approvals = [])
    (hu₂ : c₂.ctxLabel.integrity = .untrusted) (ha₂ : c₂.approvals = []) :
    log₁.filter (fun e => e.1.effect.isStateModifying) =
    log₂.filter (fun e => e.1.effect.isStateModifying) := by
  have e₁ : log₁.filter (fun e => e.1.effect.isStateModifying) = [] :=
    List.filter_eq_nil_iff.mpr (fun e he => by simp [tainted_run_has_no_side_effects h₁ hu₁ ha₁ e he])
  have e₂ : log₂.filter (fun e => e.1.effect.isStateModifying) = [] :=
    List.filter_eq_nil_iff.mpr (fun e he => by simp [tainted_run_has_no_side_effects h₂ hu₂ ha₂ e he])
  rw [e₁, e₂]

/-! ### Confidentiality -/

theorem Confidentiality.join_rank_ge_left (a b : Confidentiality) :
    a.rank ≤ (Confidentiality.join a b).rank := by
  cases a <;> cases b <;> decide

theorem join_keeps_sensitive (l o : Label)
    (h : l.confidentiality.rank ≥ Confidentiality.«internal».rank) :
    (Label.join l o).confidentiality.rank ≥ Confidentiality.«internal».rank :=
  Nat.le_trans h (Confidentiality.join_rank_ge_left _ _)

theorem effective_keeps_sensitive : ∀ (args : List Argument) (ctx : Label),
    ctx.confidentiality.rank ≥ Confidentiality.«internal».rank →
    (effectiveLabel ctx args).confidentiality.rank ≥ Confidentiality.«internal».rank
  | [], _, h => h
  | a :: as, ctx, h => effective_keeps_sensitive as (Label.join ctx a.label) (join_keeps_sensitive _ _ h)

/-- Multi-step confidentiality confinement: once internal/secret data is in context, no
    external call to an unauthorised recipient ever executes along the run. -/
theorem sensitive_run_never_leaks :
    ∀ {c c' : Config} {xs : List Input} {log : List (Tool × Bool)},
    Run c xs c' log → c.ctxLabel.confidentiality.rank ≥ Confidentiality.«internal».rank →
    ∀ e ∈ log, ¬ (e.1.effect = Effect.external ∧ e.2 = false) := by
  intro c c' xs log hrun
  induction hrun with
  | nil c => intro _ e he; simp at he
  | allow c c' t a o r rest log hdec _ ih =>
    intro hc e he
    rcases List.mem_cons.mp he with h | h
    · subst h
      rintro ⟨hext, hr⟩
      simp only at hext hr
      subst hr
      have hdeny := confidentiality_confinement c t a hext (effective_keeps_sensitive a c.ctxLabel hc)
      rw [hdeny] at hdec
      exact Decision.noConfusion hdec
    · exact ih (join_keeps_sensitive _ _ hc) e h
  | block c c' t a o r rest log _ _ ih =>
    intro hc e he
    exact ih hc e he

end TaintGate

