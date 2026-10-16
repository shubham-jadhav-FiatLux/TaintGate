/-
  Formal Verification of Frontier Data Sanitizer and Homoglyph Laundering
  Author: Shubham Jadhav (IIT Madras)
  Date: October 2026
-/

import TaintGate.Lattice
import TaintGate.Calculus
import TaintGate.NonInterference

namespace TaintGate

/-- Predicate determining whether a character is an invisible zero-width smuggling token -/
def isZeroWidth (c : Char) : Bool :=
  c == '\u200B' || c == '\u200C' || c == '\u200D' || c == '\uFEFF' || c == '\u202E'

/-- Filter removing all invisible zero-width smuggling tokens -/
def stripZeroWidth : List Char → List Char
  | [] => []
  | c :: cs =>
    if isZeroWidth c then
      stripZeroWidth cs
    else
      c :: stripZeroWidth cs

/-- Canonical homoglyph normalization mapping (e.g. NFKC character collapse) -/
def canonicalizeChar (c : Char) : Char :=
  if c == '\uFF41' then 'a'
  else if c == '\uFF42' then 'b'
  else c

/-- Normalizes a sequence of characters by collapsing lookalike homoglyphs -/
def normalizeHomoglyphs (cs : List Char) : List Char :=
  cs.map canonicalizeChar

/-- Full frontier sanitization pipeline: strip invisible smuggling tokens then normalize -/
def sanitizeChars (cs : List Char) : List Char :=
  normalizeHomoglyphs (stripZeroWidth cs)

/-- Theorem 1: Length Monotonicity of Zero-Width Stripping
    Stripping zero-width characters never increases the sequence length. -/
theorem stripZeroWidth_length_le (cs : List Char) :
    (stripZeroWidth cs).length ≤ cs.length := by
  induction cs with
  | nil =>
    dsimp [stripZeroWidth]
    exact Nat.le_refl 0
  | cons c rest ih =>
    dsimp [stripZeroWidth]
    split
    · -- isZeroWidth c = true
      have h_step : rest.length ≤ (c :: rest).length := Nat.le_succ rest.length
      exact Nat.le_trans ih h_step
    · -- isZeroWidth c = false
      dsimp [List.length]
      exact Nat.succ_le_succ ih

/-- Lemma: Homoglyph normalization preserves character list length -/
theorem normalizeHomoglyphs_length (cs : List Char) :
    (normalizeHomoglyphs cs).length = cs.length := by
  simp [normalizeHomoglyphs]

/-- Theorem 2: Frontier Sanitization Length Monotonicity
    The sanitized output length is bounded by the original input length. -/
theorem sanitizeChars_length_le (cs : List Char) :
    (sanitizeChars cs).length ≤ cs.length := by
  dsimp [sanitizeChars]
  rw [normalizeHomoglyphs_length]
  exact stripZeroWidth_length_le cs

/-- Lemma: Canonicalization mapping is idempotent on target alphabet -/
theorem canonicalizeChar_idempotent (c : Char) :
    canonicalizeChar (canonicalizeChar c) = canonicalizeChar c := by
  dsimp [canonicalizeChar]
  by_cases h1 : c == '\uFF41'
  · simp [h1]
  · by_cases h2 : c == '\uFF42'
    · simp [h1, h2]
    · simp [h1, h2]

/-- Theorem 3: Idempotence of Homoglyph Normalization
    Normalizing an already-normalized string yields the identical string. -/
theorem normalizeHomoglyphs_idempotent (cs : List Char) :
    normalizeHomoglyphs (normalizeHomoglyphs cs) = normalizeHomoglyphs cs := by
  dsimp [normalizeHomoglyphs]
  rw [List.map_map]
  have h_comp : (canonicalizeChar ∘ canonicalizeChar) = canonicalizeChar := by
    funext x
    exact canonicalizeChar_idempotent x
  rw [h_comp]

/-- Theorem 4: Clean Strings are Invariant under Zero-Width Stripping -/
theorem stripZeroWidth_clean_id (cs : List Char) (h_clean : ∀ c ∈ cs, isZeroWidth c = false) :
    stripZeroWidth cs = cs := by
  induction cs with
  | nil => rfl
  | cons c rest ih =>
    dsimp [stripZeroWidth]
    have h_c : isZeroWidth c = false := h_clean c (List.Mem.head rest)
    rw [h_c]
    dsimp
    have h_rest : ∀ x ∈ rest, isZeroWidth x = false := by
      intro x hx
      exact h_clean x (List.Mem.tail c hx)
    rw [ih h_rest]

end TaintGate
