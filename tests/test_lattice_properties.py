"""Property-based testing of algebraic lattice laws using Hypothesis.

Verifies that (I x C, <=, join, meet) forms a mathematically sound, complete lattice:
- Join & meet idempotence, commutativity, associativity, absorption
- Partial order laws: reflexivity, transitivity, antisymmetry
- Bound laws: a <= a ⊔ b, b <= a ⊔ b, a ⊓ b <= a, a ⊓ b <= b
"""

from hypothesis import given, strategies as st
from taintgate.core.lattice import Label, IntegrityLevel, ConfidentialityLevel

# Strategies for generating lattice elements
integrity_st = st.sampled_from([IntegrityLevel.UNTRUSTED, IntegrityLevel.ENDORSED, IntegrityLevel.TRUSTED])
confidentiality_st = st.sampled_from([ConfidentialityLevel.PUBLIC, ConfidentialityLevel.INTERNAL, ConfidentialityLevel.SECRET])

label_st = st.builds(
    Label,
    integrity=integrity_st,
    confidentiality=confidentiality_st,
)


class TestLatticeAxioms:
    """Verifies that (I x C, <=, join, meet) satisfies all formal lattice axioms."""

    @given(label_st)
    def test_join_idempotence(self, a: Label) -> None:
        """a ⊔ a = a"""
        assert a.join(a) == a

    @given(label_st)
    def test_meet_idempotence(self, a: Label) -> None:
        """a ⊓ a = a"""
        assert a.meet(a) == a

    @given(label_st, label_st)
    def test_join_commutativity(self, a: Label, b: Label) -> None:
        """a ⊔ b = b ⊔ a"""
        assert a.join(b) == b.join(a)

    @given(label_st, label_st)
    def test_meet_commutativity(self, a: Label, b: Label) -> None:
        """a ⊓ b = b ⊓ a"""
        assert a.meet(b) == b.meet(a)

    @given(label_st, label_st, label_st)
    def test_join_associativity(self, a: Label, b: Label, c: Label) -> None:
        """(a ⊔ b) ⊔ c = a ⊔ (b ⊔ c)"""
        assert (a.join(b)).join(c) == a.join(b.join(c))

    @given(label_st, label_st, label_st)
    def test_meet_associativity(self, a: Label, b: Label, c: Label) -> None:
        """(a ⊓ b) ⊓ c = a ⊓ (b ⊓ c)"""
        assert (a.meet(b)).meet(c) == a.meet(b.meet(c))

    @given(label_st, label_st)
    def test_absorption_laws(self, a: Label, b: Label) -> None:
        """a ⊔ (a ⊓ b) = a and a ⊓ (a ⊔ b) = a"""
        assert a.join(a.meet(b)) == a
        assert a.meet(a.join(b)) == a

    @given(label_st, label_st)
    def test_least_upper_bound(self, a: Label, b: Label) -> None:
        """a <= a ⊔ b and b <= a ⊔ b"""
        j = a.join(b)
        assert a <= j
        assert b <= j

    @given(label_st, label_st)
    def test_greatest_lower_bound(self, a: Label, b: Label) -> None:
        """a ⊓ b <= a and a ⊓ b <= b"""
        m = a.meet(b)
        assert m <= a
        assert m <= b


class TestInformationFlowOrder:
    """Verifies that flow relation (<=) is a valid partial order."""

    @given(label_st)
    def test_reflexivity(self, a: Label) -> None:
        """a <= a for all a"""
        assert a.can_flow_to(a)
        assert a <= a

    @given(label_st, label_st, label_st)
    def test_transitivity(self, a: Label, b: Label, c: Label) -> None:
        """If a <= b and b <= c, then a <= c"""
        if (a <= b) and (b <= c):
            assert a <= c

    @given(label_st, label_st)
    def test_antisymmetry(self, a: Label, b: Label) -> None:
        """If a <= b and b <= a, then a = b"""
        if (a <= b) and (b <= a):
            assert a == b
