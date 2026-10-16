"""Information-Flow Product Lattice.

Combines Biba's integrity model (Biba, 1977) with Bell–LaPadula's
confidentiality model (Bell & LaPadula, 1973) into the product lattice
``L = I × C``.

Flow order (``l1 ⊑ l2``: information labelled ``l1`` may flow to ``l2``)::

    l1 ⊑ l2  ⇔  l1.confidentiality ≤ l2.confidentiality      (BLP: no write-down)
              ∧ l1.integrity       ≥ l2.integrity            (Biba: no write-up)

so ``⊥ = trusted|public`` and ``⊤ = untrusted|secret``. Under this order the
join (least upper bound) is ``(min integrity, max confidentiality)`` and the
meet (greatest lower bound) is ``(max integrity, min confidentiality)``.

Destination/recipient authorisation is deliberately *not* part of the label:
an earlier revision carried a recipient set whose join/meet violated the
lattice laws (associativity, absorption, antisymmetry). Recipient
confinement is enforced at the sink by the policy evaluator instead
(``policy.contacts`` / ``policy.allowed_domains``).
"""

from __future__ import annotations

from enum import IntEnum
from dataclasses import dataclass


class IntegrityLevel(IntEnum):
    """Integrity scale: higher value corresponds to higher trustworthiness.

    TRUSTED > ENDORSED > UNTRUSTED
    """
    UNTRUSTED = 0
    ENDORSED = 1
    TRUSTED = 2

    @classmethod
    def from_str(cls, val: str) -> "IntegrityLevel":
        mapping = {
            "untrusted": cls.UNTRUSTED,
            "endorsed": cls.ENDORSED,
            "trusted": cls.TRUSTED,
        }
        key = str(val).strip().lower()
        if key not in mapping:
            raise ValueError(f"Unknown integrity level: {val!r} (expected one of {sorted(mapping)})")
        return mapping[key]


class ConfidentialityLevel(IntEnum):
    """Confidentiality scale: higher value corresponds to higher sensitivity.

    PUBLIC < INTERNAL < SECRET
    """
    PUBLIC = 0
    INTERNAL = 1
    SECRET = 2

    @classmethod
    def from_str(cls, val: str) -> "ConfidentialityLevel":
        mapping = {
            "public": cls.PUBLIC,
            "internal": cls.INTERNAL,
            "secret": cls.SECRET,
        }
        key = str(val).strip().lower()
        if key not in mapping:
            raise ValueError(f"Unknown confidentiality level: {val!r} (expected one of {sorted(mapping)})")
        return mapping[key]


@dataclass(frozen=True)
class Label:
    """An element of the product lattice ``L = I × C``."""
    integrity: IntegrityLevel
    confidentiality: ConfidentialityLevel

    def join(self, other: "Label") -> "Label":
        """Least upper bound under the flow order ``⊑``.

        When data sources mix, integrity degrades (min) and confidentiality
        escalates (max).
        """
        if not isinstance(other, Label):
            return NotImplemented
        return Label(
            integrity=IntegrityLevel(min(self.integrity, other.integrity)),
            confidentiality=ConfidentialityLevel(max(self.confidentiality, other.confidentiality)),
        )

    def meet(self, other: "Label") -> "Label":
        """Greatest lower bound under the flow order ``⊑`` (dual of join)."""
        if not isinstance(other, Label):
            return NotImplemented
        return Label(
            integrity=IntegrityLevel(max(self.integrity, other.integrity)),
            confidentiality=ConfidentialityLevel(min(self.confidentiality, other.confidentiality)),
        )

    def can_flow_to(self, target: "Label") -> bool:
        """Flow relation ``self ⊑ target``.

        - BLP (no write-down): ``self.confidentiality <= target.confidentiality``
        - Biba (no write-up):  ``self.integrity >= target.integrity``
        """
        if not isinstance(target, Label):
            return NotImplemented
        return (
            self.confidentiality <= target.confidentiality
            and self.integrity >= target.integrity
        )

    def __or__(self, other: "Label") -> "Label":
        return self.join(other)

    def __and__(self, other: "Label") -> "Label":
        return self.meet(other)

    def __le__(self, other: "Label") -> bool:
        return self.can_flow_to(other)

    def __ge__(self, other: "Label") -> bool:
        if not isinstance(other, Label):
            return NotImplemented
        return other.can_flow_to(self)

    def to_dict(self) -> dict:
        return {
            "integrity": self.integrity.name.lower(),
            "confidentiality": self.confidentiality.name.lower(),
        }

    @classmethod
    def from_dict(cls, data: dict) -> "Label":
        """Deserialises a label. Missing fields are an error (no silent default to ⊥).

        A legacy ``recipients`` key, if present, is ignored.
        """
        if "integrity" not in data or "confidentiality" not in data:
            raise ValueError(f"Label requires 'integrity' and 'confidentiality': {data!r}")
        return cls(
            integrity=IntegrityLevel.from_str(data["integrity"]),
            confidentiality=ConfidentialityLevel.from_str(data["confidentiality"]),
        )

    def __str__(self) -> str:
        return f"[{self.integrity.name.lower()} | {self.confidentiality.name.lower()}]"
