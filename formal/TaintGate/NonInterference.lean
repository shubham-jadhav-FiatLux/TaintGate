/-
  Formal Non-Interference and Confinement Proofs
  Author: Shubham Jadhav (IIT Madras)
  Date: October 2026
-/

import TaintGate.Lattice
import TaintGate.Calculus

namespace TaintGate

/-- Theorem 1: Integrity Non-Interference (Biba Duality)
    If context or inputs are contaminated (rank <= untrusted) and an action is state-modifying,
    then without prior approval (approvals = []), the reference monitor NEVER produces ALLOW. -/
theorem integrity_non_interference
    (cfg : Config)
    (tool : Tool)
    (args : List Argument)
    (recip : Bool)
    (h_state_modifying : tool.effect.isStateModifying = true)
    (h_untrusted : (effectiveLabel cfg.ctxLabel args).integrity.rank ≤ Integrity.untrusted.rank)
    (h_no_approvals : cfg.approvals = []) :
    decide cfg tool args recip ≠ Decision.allow := by
  dsimp [decide]
  split
  · -- Case: exfiltration was true -> deny ≠ allow
    intro h_eq; contradiction
  · -- Case: exfiltration was false
    have h_contam : isContaminatedSideEffect (effectiveLabel cfg.ctxLabel args) tool.effect = true := by
      dsimp [isContaminatedSideEffect]
      rw [h_state_modifying]
      simp [h_untrusted]
    rw [h_contam]
    dsimp
    have h_any : cfg.approvals.any (fun ap => ap.toolName == tool.name && ap.argVals == args.map Argument.val) = false := by
      rw [h_no_approvals]
      rfl
    rw [h_any]
    dsimp
    intro h_eq; contradiction

/-- Theorem 2: Confidentiality Confinement (Bell–LaPadula Duality)
    If effective confidentiality is at least internal and an action is external
    with an unauthorized recipient (recip = false), the decision is ALWAYS DENY. -/
theorem confidentiality_confinement
    (cfg : Config)
    (tool : Tool)
    (args : List Argument)
    (h_external : tool.effect = Effect.external)
    (h_conf : (effectiveLabel cfg.ctxLabel args).confidentiality.rank ≥ Confidentiality.«internal».rank) :
    decide cfg tool args false = Decision.deny := by
  dsimp [decide, isExfiltration]
  rw [h_external]
  simp [h_conf]

/-- Theorem 3: Two-Run Integrity Non-Interference
    Given two execution configurations (potentially differing arbitrarily in untrusted inputs)
    where effective integrity is untrusted and no approvals are cached,
    for any candidate transition step in either run, neither run can produce
    an unauthorized state-modifying trace entry (both traces remain invariant). -/
theorem two_run_integrity_non_interference
    (cfg1 cfg2 cfg1' cfg2' : Config)
    (tool : Tool)
    (args1 args2 : List Argument)
    (obsLabel1 obsLabel2 : Label)
    (recip1 recip2 : Bool)
    (h_state_modifying : tool.effect.isStateModifying = true)
    (h_untrusted1 : (effectiveLabel cfg1.ctxLabel args1).integrity.rank ≤ Integrity.untrusted.rank)
    (h_untrusted2 : (effectiveLabel cfg2.ctxLabel args2).integrity.rank ≤ Integrity.untrusted.rank)
    (h_no_approvals1 : cfg1.approvals = [])
    (h_no_approvals2 : cfg2.approvals = [])
    (h_step1 : Step cfg1 tool args1 obsLabel1 recip1 cfg1')
    (h_step2 : Step cfg2 tool args2 obsLabel2 recip2 cfg2') :
    cfg1'.trace = cfg1.trace ∧ cfg2'.trace = cfg2.trace := by
  have h_dec1 := integrity_non_interference cfg1 tool args1 recip1 h_state_modifying h_untrusted1 h_no_approvals1
  have h_dec2 := integrity_non_interference cfg2 tool args2 recip2 h_state_modifying h_untrusted2 h_no_approvals2
  have h_tr1 : cfg1'.trace = cfg1.trace := by
    cases h_step1 with
    | step_allow h_allow => contradiction
    | step_blocked _ => rfl
  have h_tr2 : cfg2'.trace = cfg2.trace := by
    cases h_step2 with
    | step_allow h_allow => contradiction
    | step_blocked _ => rfl
  exact ⟨h_tr1, h_tr2⟩

/-- Theorem 4: Two-Run Confidentiality Confinement
    Given two configurations containing confidential context/inputs attempting egress
    to an unauthorized external sink (recip = false), both executions are unconditionally
    blocked with Decision.deny, and neither run modifies its trace. -/
theorem two_run_confidentiality_confinement
    (cfg1 cfg2 cfg1' cfg2' : Config)
    (tool : Tool)
    (args1 args2 : List Argument)
    (obsLabel1 obsLabel2 : Label)
    (h_external : tool.effect = Effect.external)
    (h_conf1 : (effectiveLabel cfg1.ctxLabel args1).confidentiality.rank ≥ Confidentiality.«internal».rank)
    (h_conf2 : (effectiveLabel cfg2.ctxLabel args2).confidentiality.rank ≥ Confidentiality.«internal».rank)
    (h_step1 : Step cfg1 tool args1 obsLabel1 false cfg1')
    (h_step2 : Step cfg2 tool args2 obsLabel2 false cfg2') :
    decide cfg1 tool args1 false = Decision.deny ∧
    decide cfg2 tool args2 false = Decision.deny ∧
    cfg1'.trace = cfg1.trace ∧ cfg2'.trace = cfg2.trace := by
  have h_dec1 := confidentiality_confinement cfg1 tool args1 h_external h_conf1
  have h_dec2 := confidentiality_confinement cfg2 tool args2 h_external h_conf2
  have h_tr1 : cfg1'.trace = cfg1.trace := by
    cases h_step1 with
    | step_allow h_allow =>
      rw [h_dec1] at h_allow
      contradiction
    | step_blocked _ => rfl
  have h_tr2 : cfg2'.trace = cfg2.trace := by
    cases h_step2 with
    | step_allow h_allow =>
      rw [h_dec2] at h_allow
      contradiction
    | step_blocked _ => rfl
  exact ⟨h_dec1, h_dec2, h_tr1, h_tr2⟩

end TaintGate
