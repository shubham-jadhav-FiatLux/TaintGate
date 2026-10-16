/-
  Formal Operational Calculus and Reference Monitor Semantics
  Author: Shubham Jadhav (IIT Madras)
  Date: October 2026
-/

import TaintGate.Lattice

namespace TaintGate

/-- Tool effect classes -/
inductive Effect where
  | read
  | local_write
  | external
  | irreversible
deriving Repr, DecidableEq

/-- Helper to identify state-modifying actions -/
def Effect.isStateModifying : Effect → Bool
  | .local_write | .external | .irreversible => true
  | .read => false

/-- Reference monitor decisions -/
inductive Decision where
  | allow
  | deny
  | approve
deriving Repr, DecidableEq

/-- Tool specification -/
structure Tool where
  name : String
  effect : Effect
deriving Repr, DecidableEq

/-- Invocation argument with provenance label -/
structure Argument where
  name : String
  val : String
  label : Label
deriving Repr, DecidableEq

/-- An approval authorization granted by the operator -/
structure Approval where
  toolName : String
  argVals : List String
deriving Repr, DecidableEq

/-- Reference Monitor State Configuration C = ⟨context_label, approval_cache, trace⟩ -/
structure Config where
  ctxLabel : Label
  approvals : List Approval
  trace : List (String × List String)
deriving Repr

/-- Effective label calculation: joins context label with all argument labels -/
def effectiveLabel (ctx : Label) (args : List Argument) : Label :=
  args.foldl (fun acc a => Label.join acc a.label) ctx

/-- Predicate: external transmission of internal or secret data to unallowed destination -/
def isExfiltration (eff : Label) (effClass : Effect) (isAllowedRecipient : Bool) : Bool :=
  (effClass == Effect.external) && (eff.confidentiality.rank ≥ Confidentiality.«internal».rank) && (!isAllowedRecipient)

/-- Predicate: state modification executed from untrusted context -/
def isContaminatedSideEffect (eff : Label) (effClass : Effect) : Bool :=
  effClass.isStateModifying && (eff.integrity.rank ≤ Integrity.untrusted.rank)

/-- Reference Monitor Decision Function R under the Rule of Two preset:
    1. If exfiltration detected -> DENY
    2. Else if contaminated side-effect -> ALLOW if in approvals else APPROVE
    3. Else -> ALLOW -/
def decide (cfg : Config) (tool : Tool) (args : List Argument) (isAllowedRecipient : Bool) : Decision :=
  let eff := effectiveLabel cfg.ctxLabel args
  if isExfiltration eff tool.effect isAllowedRecipient then
    Decision.deny
  else if isContaminatedSideEffect eff tool.effect then
    let argVals := args.map Argument.val
    let isApproved := cfg.approvals.any (fun ap => ap.toolName == tool.name && ap.argVals == argVals)
    if isApproved then Decision.allow else Decision.approve
  else
    Decision.allow

/-- Small-step transition:
    If ALLOW, the tool executes, emits an observation with label obsLabel,
    and appends to trace while updating ctxLabel with obsLabel.
    If blocked (DENY or APPROVE without clearance), the state is unchanged. -/
inductive Step : Config → Tool → List Argument → Label → Bool → Config → Prop where
  | step_allow (cfg : Config) (tool : Tool) (args : List Argument) (obsLabel : Label) (recip : Bool) :
      decide cfg tool args recip = Decision.allow →
      Step cfg tool args obsLabel recip {
        cfg with
        ctxLabel := Label.join cfg.ctxLabel obsLabel,
        trace := (tool.name, args.map Argument.val) :: cfg.trace
      }
  | step_blocked (cfg : Config) (tool : Tool) (args : List Argument) (obsLabel : Label) (recip : Bool) :
      decide cfg tool args recip ≠ Decision.allow →
      Step cfg tool args obsLabel recip cfg

/-- Information-Flow Monotonicity Theorem:
    Across every operational transition step, the context label is monotonically
    non-decreasing under the product lattice flow order. -/
theorem step_context_monotonic
    (cfg cfg' : Config)
    (tool : Tool)
    (args : List Argument)
    (obsLabel : Label)
    (recip : Bool) :
    Step cfg tool args obsLabel recip cfg' →
    cfg.ctxLabel ≤ cfg'.ctxLabel := by
  intro h_step
  cases h_step with
  | step_allow _ =>
    dsimp
    exact Label.le_join_left _ _
  | step_blocked _ =>
    exact Label.le_refl _

end TaintGate
