/-
  Formal Provenance DAG and Backward Program Slicing Soundness
  Author: Shubham Jadhav (IIT Madras)
  Date: October 2026
-/

import TaintGate.Lattice
import TaintGate.Calculus

namespace TaintGate

/-- Directed edge in provenance graph -/
structure Edge where
  src : Nat
  dst : Nat
deriving Repr, DecidableEq

/-- Path reachability in DAG: reflexive-transitive closure of directed edges -/
inductive Reaches (edges : List Edge) : Nat → Nat → Prop where
  | refl (u : Nat) : Reaches edges u u
  | step (u v w : Nat) : Edge.mk u v ∈ edges → Reaches edges v w → Reaches edges u w

/-- Backward reachability slice definition: all nodes that reach the target -/
def inSlice (edges : List Edge) (target : Nat) (node : Nat) : Prop :=
  Reaches edges node target

/-- Theorem 3 (Soundness of Backward Slicing):
    For any direct dependency edge (u, v) ∈ edges, u is guaranteed to be in the backward slice of v. -/
theorem direct_dependency_in_slice (edges : List Edge) (u v : Nat) (h_edge : Edge.mk u v ∈ edges) :
    inSlice edges v u := by
  dsimp [inSlice]
  apply Reaches.step u v v h_edge
  exact Reaches.refl v

/-- Transitivity of Slicing (Causal Closure):
    If w reaches u and u reaches target v, then w is causally contained in the slice of v. -/
theorem slice_transitive (edges : List Edge) (w u v : Nat)
    (h_wu : Reaches edges w u) (h_uv : inSlice edges v u) :
    inSlice edges v w := by
  dsimp [inSlice] at h_uv ⊢
  induction h_wu with
  | refl _ => exact h_uv
  | step a b c h_ab _ ih =>
    apply Reaches.step a b v h_ab
    exact ih h_uv

end TaintGate
