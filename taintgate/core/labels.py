"""Standard label constants and value containers."""

from __future__ import annotations

from typing import Any, Generic, TypeVar
from dataclasses import dataclass
from taintgate.core.lattice import Label, IntegrityLevel, ConfidentialityLevel

# Standard canonical labels
LABEL_TRUSTED_PUBLIC = Label(
    integrity=IntegrityLevel.TRUSTED,
    confidentiality=ConfidentialityLevel.PUBLIC,
)

LABEL_TRUSTED_INTERNAL = Label(
    integrity=IntegrityLevel.TRUSTED,
    confidentiality=ConfidentialityLevel.INTERNAL,
)

LABEL_TRUSTED_SECRET = Label(
    integrity=IntegrityLevel.TRUSTED,
    confidentiality=ConfidentialityLevel.SECRET,
)

LABEL_UNTRUSTED_PUBLIC = Label(
    integrity=IntegrityLevel.UNTRUSTED,
    confidentiality=ConfidentialityLevel.PUBLIC,
)

LABEL_UNTRUSTED_INTERNAL = Label(
    integrity=IntegrityLevel.UNTRUSTED,
    confidentiality=ConfidentialityLevel.INTERNAL,
)

LABEL_UNTRUSTED_SECRET = Label(
    integrity=IntegrityLevel.UNTRUSTED,
    confidentiality=ConfidentialityLevel.SECRET,
)

LABEL_ENDORSED_PUBLIC = Label(
    integrity=IntegrityLevel.ENDORSED,
    confidentiality=ConfidentialityLevel.PUBLIC,
)

LABEL_ENDORSED_INTERNAL = Label(
    integrity=IntegrityLevel.ENDORSED,
    confidentiality=ConfidentialityLevel.INTERNAL,
)


T = TypeVar("T")


@dataclass(frozen=True)
class LabelledValue(Generic[T]):
    """Wraps an arbitrary Python object with an information-flow label and provenance identifier."""
    value: T
    label: Label
    source_id: str = ""

    def __repr__(self) -> str:
        return f"LabelledValue({self.value!r}, label={self.label}, source={self.source_id!r})"
