"""Tier 2 Precision: Field-Sensitive Labeling for Structured Payloads.

Enables fine-grained information-flow tracking across structured dictionaries and
nested JSON trees, avoiding coarse-grained contamination of clean fields.
"""

from __future__ import annotations

import copy
import fnmatch
from typing import Any, Dict, List, Optional, Tuple

from taintgate.core.lattice import Label, IntegrityLevel, ConfidentialityLevel
from taintgate.core.labels import LABEL_TRUSTED_PUBLIC


class FieldSensitiveLabeler:
    """Manages path-level label assignment, extraction, and field-level redactions."""

    def __init__(self, field_rules: Optional[Dict[str, Label]] = None):
        """field_rules maps dot-separated path patterns (e.g. 'user.ssn', 'billing.*') to Labels."""
        self.field_rules: Dict[str, Label] = field_rules or {}

    def get_field_label(self, path: str, default_label: Label = LABEL_TRUSTED_PUBLIC) -> Label:
        """Finds the most specific label rule matching the given dot-path."""
        if path in self.field_rules:
            return self.field_rules[path]

        # Check wildcard patterns
        for pattern, label in self.field_rules.items():
            if fnmatch.fnmatch(path, pattern):
                return label

        return default_label

    def label_payload(
        self,
        data: Any,
        prefix: str = "",
        default_label: Label = LABEL_TRUSTED_PUBLIC,
    ) -> Dict[str, Label]:
        """Traverses structured data recursively, returning path -> Label mappings for all leaf nodes."""
        results: Dict[str, Label] = {}

        if isinstance(data, dict):
            for k, v in data.items():
                curr_path = f"{prefix}.{k}" if prefix else str(k)
                if isinstance(v, (dict, list)):
                    sub = self.label_payload(v, prefix=curr_path, default_label=default_label)
                    results.update(sub)
                else:
                    results[curr_path] = self.get_field_label(curr_path, default_label)
        elif isinstance(data, list):
            for idx, item in enumerate(data):
                curr_path = f"{prefix}[{idx}]" if prefix else f"[{idx}]"
                if isinstance(item, (dict, list)):
                    sub = self.label_payload(item, prefix=curr_path, default_label=default_label)
                    results.update(sub)
                else:
                    results[curr_path] = self.get_field_label(curr_path, default_label)
        else:
            curr_path = prefix or "root"
            results[curr_path] = self.get_field_label(curr_path, default_label)

        return results

    def compute_composite_label(
        self,
        data: Any,
        default_label: Label = LABEL_TRUSTED_PUBLIC,
    ) -> Label:
        """Computes the overall join label across all leaf fields in the data."""
        path_labels = self.label_payload(data, default_label=default_label)
        if not path_labels:
            return default_label
        res = default_label
        for lbl in path_labels.values():
            res = res.join(lbl)
        return res

    def extract_field(
        self,
        data: Any,
        path: str,
        default_label: Label = LABEL_TRUSTED_PUBLIC,
    ) -> Tuple[Any, Label]:
        """Extracts the value and label at a dot-separated path (e.g. 'user.profile.name')."""
        parts = path.split(".")
        curr = data
        for p in parts:
            if isinstance(curr, dict) and p in curr:
                curr = curr[p]
            else:
                raise KeyError(f"Path '{path}' not found at segment '{p}'")

        label = self.get_field_label(path, default_label)
        return curr, label

    def redact(
        self,
        data: Any,
        max_confidentiality: ConfidentialityLevel,
        redact_value: Any = "[REDACTED]",
    ) -> Any:
        """Returns a deep copy of data with any fields exceeding max_confidentiality redacted."""
        if not isinstance(data, (dict, list)):
            return data

        copied = copy.deepcopy(data)

        def _walk_and_redact(obj: Any, prefix: str = "") -> Any:
            if isinstance(obj, dict):
                for k, v in list(obj.items()):
                    curr_path = f"{prefix}.{k}" if prefix else str(k)
                    lbl = self.get_field_label(curr_path)
                    if lbl.confidentiality > max_confidentiality:
                        obj[k] = redact_value
                    elif isinstance(v, (dict, list)):
                        _walk_and_redact(v, prefix=curr_path)
            elif isinstance(obj, list):
                for idx, item in enumerate(obj):
                    curr_path = f"{prefix}[{idx}]" if prefix else f"[{idx}]"
                    lbl = self.get_field_label(curr_path)
                    if lbl.confidentiality > max_confidentiality:
                        obj[idx] = redact_value
                    elif isinstance(item, (dict, list)):
                        _walk_and_redact(item, prefix=curr_path)
            return obj

        return _walk_and_redact(copied)
