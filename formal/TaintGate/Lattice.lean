/-
  Formal Security Model: Product Lattice L = I × C
  Author: Shubham Jadhav (IIT Madras)
  Date: October 2026
-/

namespace TaintGate

/-- Biba integrity scale: untrusted < endorsed < trusted -/
inductive Integrity where
  | untrusted
  | endorsed
  | trusted
deriving Repr, DecidableEq

/-- Bell–LaPadula confidentiality scale: public < internal < secret -/
inductive Confidentiality where
  | «public»
  | «internal»
  | secret
deriving Repr, DecidableEq

/-- Numeric ranking for integrity (higher value is cleaner / more trustworthy) -/
def Integrity.rank : Integrity → Nat
  | .untrusted => 0
  | .endorsed  => 1
  | .trusted   => 2

/-- Numeric ranking for confidentiality (higher value is more sensitive) -/
def Confidentiality.rank : Confidentiality → Nat
  | .«public»   => 0
  | .«internal» => 1
  | .secret    => 2

/-- Information-flow order on Integrity (Biba: clean data may flow to dirty sinks).
    i1 flows to i2 iff i2 is at most as trustworthy as i1 (i2.rank ≤ i1.rank). -/
def Integrity.flowLe (i1 i2 : Integrity) : Prop :=
  i2.rank ≤ i1.rank

instance : LE Integrity where
  le := Integrity.flowLe

instance (i1 i2 : Integrity) : Decidable (i1 ≤ i2) :=
  inferInstanceAs (Decidable (i2.rank ≤ i1.rank))

/-- Information-flow order on Confidentiality (Bell–LaPadula: public data may flow to secret).
    c1 flows to c2 iff c1 is at most as confidential as c2 (c1.rank ≤ c2.rank). -/
def Confidentiality.flowLe (c1 c2 : Confidentiality) : Prop :=
  c1.rank ≤ c2.rank

instance : LE Confidentiality where
  le := Confidentiality.flowLe

instance (c1 c2 : Confidentiality) : Decidable (c1 ≤ c2) :=
  inferInstanceAs (Decidable (c1.rank ≤ c2.rank))

/-- Join operator on Integrity: degrades to minimum integrity under data mixing -/
def Integrity.join : Integrity → Integrity → Integrity
  | .untrusted, _ => .untrusted
  | _, .untrusted => .untrusted
  | .endorsed, _  => .endorsed
  | _, .endorsed  => .endorsed
  | .trusted, .trusted => .trusted

/-- Meet operator on Integrity: elevates to maximum integrity -/
def Integrity.meet : Integrity → Integrity → Integrity
  | .trusted, _ => .trusted
  | _, .trusted => .trusted
  | .endorsed, _ => .endorsed
  | _, .endorsed => .endorsed
  | .untrusted, .untrusted => .untrusted

/-- Join operator on Confidentiality: escalates to maximum secrecy under data mixing -/
def Confidentiality.join : Confidentiality → Confidentiality → Confidentiality
  | .secret, _ => .secret
  | _, .secret => .secret
  | .«internal», _ => .«internal»
  | _, .«internal» => .«internal»
  | .«public», .«public» => .«public»

/-- Meet operator on Confidentiality: relaxes to minimum secrecy -/
def Confidentiality.meet : Confidentiality → Confidentiality → Confidentiality
  | .«public», _ => .«public»
  | _, .«public» => .«public»
  | .«internal», _ => .«internal»
  | _, .«internal» => .«internal»
  | .secret, .secret => .secret

/-- Product Lattice Label L = I × C -/
structure Label where
  integrity : Integrity
  confidentiality : Confidentiality
deriving Repr, DecidableEq

/-- Information-flow product lattice ordering: l1 ⊑ l2 -/
def Label.le (l1 l2 : Label) : Prop :=
  l1.integrity ≤ l2.integrity ∧ l1.confidentiality ≤ l2.confidentiality

instance : LE Label where
  le := Label.le

instance (l1 l2 : Label) : Decidable (l1 ≤ l2) :=
  inferInstanceAs (Decidable (l1.integrity ≤ l2.integrity ∧ l1.confidentiality ≤ l2.confidentiality))

/-- Least upper bound (join) on Product Lattice -/
def Label.join (l1 l2 : Label) : Label where
  integrity := Integrity.join l1.integrity l2.integrity
  confidentiality := Confidentiality.join l1.confidentiality l2.confidentiality

/-- Greatest lower bound (meet) on Product Lattice -/
def Label.meet (l1 l2 : Label) : Label where
  integrity := Integrity.meet l1.integrity l2.integrity
  confidentiality := Confidentiality.meet l1.confidentiality l2.confidentiality

-- =========================================================================
-- Partial Order Properties
-- =========================================================================

theorem Integrity.le_refl (a : Integrity) : a ≤ a := by
  cases a <;> decide

theorem Integrity.le_trans (a b c : Integrity) : a ≤ b → b ≤ c → a ≤ c := by
  cases a <;> cases b <;> cases c <;> decide

theorem Integrity.le_antisymm (a b : Integrity) : a ≤ b → b ≤ a → a = b := by
  cases a <;> cases b <;> intro h1 h2 <;> first | rfl | contradiction

theorem Confidentiality.le_refl (a : Confidentiality) : a ≤ a := by
  cases a <;> decide

theorem Confidentiality.le_trans (a b c : Confidentiality) : a ≤ b → b ≤ c → a ≤ c := by
  cases a <;> cases b <;> cases c <;> decide

theorem Confidentiality.le_antisymm (a b : Confidentiality) : a ≤ b → b ≤ a → a = b := by
  cases a <;> cases b <;> intro h1 h2 <;> first | rfl | contradiction

theorem Label.le_refl (l : Label) : l ≤ l := by
  cases l
  exact ⟨Integrity.le_refl _, Confidentiality.le_refl _⟩

theorem Label.le_trans (l1 l2 l3 : Label) : l1 ≤ l2 → l2 ≤ l3 → l1 ≤ l3 := by
  intro ⟨hi1, hc1⟩ ⟨hi2, hc2⟩
  exact ⟨Integrity.le_trans _ _ _ hi1 hi2, Confidentiality.le_trans _ _ _ hc1 hc2⟩

theorem Label.le_antisymm (l1 l2 : Label) : l1 ≤ l2 → l2 ≤ l1 → l1 = l2 := by
  intro ⟨hi1, hc1⟩ ⟨hi2, hc2⟩
  have hi := Integrity.le_antisymm _ _ hi1 hi2
  have hc := Confidentiality.le_antisymm _ _ hc1 hc2
  cases l1; cases l2
  dsimp at hi hc
  rw [hi, hc]

-- =========================================================================
-- Join & Meet Algebraic Laws (Commutativity, Associativity, Idempotence)
-- =========================================================================

theorem Integrity.join_comm (a b : Integrity) : Integrity.join a b = Integrity.join b a := by
  cases a <;> cases b <;> rfl

theorem Integrity.meet_comm (a b : Integrity) : Integrity.meet a b = Integrity.meet b a := by
  cases a <;> cases b <;> rfl

theorem Confidentiality.join_comm (a b : Confidentiality) : Confidentiality.join a b = Confidentiality.join b a := by
  cases a <;> cases b <;> rfl

theorem Confidentiality.meet_comm (a b : Confidentiality) : Confidentiality.meet a b = Confidentiality.meet b a := by
  cases a <;> cases b <;> rfl

theorem Label.join_comm (l1 l2 : Label) : Label.join l1 l2 = Label.join l2 l1 := by
  cases l1; cases l2
  dsimp [Label.join]
  rw [Integrity.join_comm, Confidentiality.join_comm]

theorem Label.meet_comm (l1 l2 : Label) : Label.meet l1 l2 = Label.meet l2 l1 := by
  cases l1; cases l2
  dsimp [Label.meet]
  rw [Integrity.meet_comm, Confidentiality.meet_comm]

theorem Integrity.join_assoc (a b c : Integrity) :
    Integrity.join (Integrity.join a b) c = Integrity.join a (Integrity.join b c) := by
  cases a <;> cases b <;> cases c <;> rfl

theorem Integrity.meet_assoc (a b c : Integrity) :
    Integrity.meet (Integrity.meet a b) c = Integrity.meet a (Integrity.meet b c) := by
  cases a <;> cases b <;> cases c <;> rfl

theorem Confidentiality.join_assoc (a b c : Confidentiality) :
    Confidentiality.join (Confidentiality.join a b) c = Confidentiality.join a (Confidentiality.join b c) := by
  cases a <;> cases b <;> cases c <;> rfl

theorem Confidentiality.meet_assoc (a b c : Confidentiality) :
    Confidentiality.meet (Confidentiality.meet a b) c = Confidentiality.meet a (Confidentiality.meet b c) := by
  cases a <;> cases b <;> cases c <;> rfl

theorem Label.join_assoc (l1 l2 l3 : Label) :
    Label.join (Label.join l1 l2) l3 = Label.join l1 (Label.join l2 l3) := by
  cases l1; cases l2; cases l3
  dsimp [Label.join]
  rw [Integrity.join_assoc, Confidentiality.join_assoc]

theorem Label.meet_assoc (l1 l2 l3 : Label) :
    Label.meet (Label.meet l1 l2) l3 = Label.meet l1 (Label.meet l2 l3) := by
  cases l1; cases l2; cases l3
  dsimp [Label.meet]
  rw [Integrity.meet_assoc, Confidentiality.meet_assoc]

theorem Integrity.join_idem (a : Integrity) : Integrity.join a a = a := by
  cases a <;> rfl

theorem Integrity.meet_idem (a : Integrity) : Integrity.meet a a = a := by
  cases a <;> rfl

theorem Confidentiality.join_idem (a : Confidentiality) : Confidentiality.join a a = a := by
  cases a <;> rfl

theorem Confidentiality.meet_idem (a : Confidentiality) : Confidentiality.meet a a = a := by
  cases a <;> rfl

theorem Label.join_idem (l : Label) : Label.join l l = l := by
  cases l
  dsimp [Label.join]
  rw [Integrity.join_idem, Confidentiality.join_idem]

theorem Label.meet_idem (l : Label) : Label.meet l l = l := by
  cases l
  dsimp [Label.meet]
  rw [Integrity.meet_idem, Confidentiality.meet_idem]

-- =========================================================================
-- Absorption Laws
-- =========================================================================

theorem Integrity.join_meet_absorb (a b : Integrity) : Integrity.join a (Integrity.meet a b) = a := by
  cases a <;> cases b <;> rfl

theorem Integrity.meet_join_absorb (a b : Integrity) : Integrity.meet a (Integrity.join a b) = a := by
  cases a <;> cases b <;> rfl

theorem Confidentiality.join_meet_absorb (a b : Confidentiality) : Confidentiality.join a (Confidentiality.meet a b) = a := by
  cases a <;> cases b <;> rfl

theorem Confidentiality.meet_join_absorb (a b : Confidentiality) : Confidentiality.meet a (Confidentiality.join a b) = a := by
  cases a <;> cases b <;> rfl

theorem Label.join_meet_absorb (l1 l2 : Label) : Label.join l1 (Label.meet l1 l2) = l1 := by
  cases l1; cases l2
  dsimp [Label.join, Label.meet]
  rw [Integrity.join_meet_absorb, Confidentiality.join_meet_absorb]

theorem Label.meet_join_absorb (l1 l2 : Label) : Label.meet l1 (Label.join l1 l2) = l1 := by
  cases l1; cases l2
  dsimp [Label.join, Label.meet]
  rw [Integrity.meet_join_absorb, Confidentiality.meet_join_absorb]

-- =========================================================================
-- Least Upper Bound (LUB) Proofs for Join
-- =========================================================================

theorem Integrity.le_join_left (a b : Integrity) : a ≤ Integrity.join a b := by
  cases a <;> cases b <;> decide

theorem Integrity.le_join_right (a b : Integrity) : b ≤ Integrity.join a b := by
  cases a <;> cases b <;> decide

theorem Integrity.join_le (a b u : Integrity) : a ≤ u → b ≤ u → Integrity.join a b ≤ u := by
  cases a <;> cases b <;> cases u <;> decide

theorem Confidentiality.le_join_left (a b : Confidentiality) : a ≤ Confidentiality.join a b := by
  cases a <;> cases b <;> decide

theorem Confidentiality.le_join_right (a b : Confidentiality) : b ≤ Confidentiality.join a b := by
  cases a <;> cases b <;> decide

theorem Confidentiality.join_le (a b u : Confidentiality) : a ≤ u → b ≤ u → Confidentiality.join a b ≤ u := by
  cases a <;> cases b <;> cases u <;> decide

theorem Label.le_join_left (l1 l2 : Label) : l1 ≤ Label.join l1 l2 := by
  exact ⟨Integrity.le_join_left _ _, Confidentiality.le_join_left _ _⟩

theorem Label.le_join_right (l1 l2 : Label) : l2 ≤ Label.join l1 l2 := by
  exact ⟨Integrity.le_join_right _ _, Confidentiality.le_join_right _ _⟩

theorem Label.join_le (l1 l2 u : Label) : l1 ≤ u → l2 ≤ u → Label.join l1 l2 ≤ u := by
  intro ⟨hi1, hc1⟩ ⟨hi2, hc2⟩
  exact ⟨Integrity.join_le _ _ _ hi1 hi2, Confidentiality.join_le _ _ _ hc1 hc2⟩

-- =========================================================================
-- Greatest Lower Bound (GLB) Proofs for Meet
-- =========================================================================

theorem Integrity.meet_le_left (a b : Integrity) : Integrity.meet a b ≤ a := by
  cases a <;> cases b <;> decide

theorem Integrity.meet_le_right (a b : Integrity) : Integrity.meet a b ≤ b := by
  cases a <;> cases b <;> decide

theorem Integrity.le_meet (w a b : Integrity) : w ≤ a → w ≤ b → w ≤ Integrity.meet a b := by
  cases w <;> cases a <;> cases b <;> decide

theorem Confidentiality.meet_le_left (a b : Confidentiality) : Confidentiality.meet a b ≤ a := by
  cases a <;> cases b <;> decide

theorem Confidentiality.meet_le_right (a b : Confidentiality) : Confidentiality.meet a b ≤ b := by
  cases a <;> cases b <;> decide

theorem Confidentiality.le_meet (w a b : Confidentiality) : w ≤ a → w ≤ b → w ≤ Confidentiality.meet a b := by
  cases w <;> cases a <;> cases b <;> decide

theorem Label.meet_le_left (l1 l2 : Label) : Label.meet l1 l2 ≤ l1 := by
  exact ⟨Integrity.meet_le_left _ _, Confidentiality.meet_le_left _ _⟩

theorem Label.meet_le_right (l1 l2 : Label) : Label.meet l1 l2 ≤ l2 := by
  exact ⟨Integrity.meet_le_right _ _, Confidentiality.meet_le_right _ _⟩

theorem Label.le_meet (w l1 l2 : Label) : w ≤ l1 → w ≤ l2 → w ≤ Label.meet l1 l2 := by
  intro ⟨hi1, hc1⟩ ⟨hi2, hc2⟩
  exact ⟨Integrity.le_meet _ _ _ hi1 hi2, Confidentiality.le_meet _ _ _ hc1 hc2⟩

end TaintGate
