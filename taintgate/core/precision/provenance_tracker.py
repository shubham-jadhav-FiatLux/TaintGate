"""Tier 2 Precision: Exact-Provenance Argument Tracking.

Determines argument-level labels by matching tool call arguments against recorded
provenance nodes, isolating clean arguments from contaminated context history.
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional

from taintgate.core.lattice import Label
from taintgate.core.labels import LABEL_TRUSTED_PUBLIC
from taintgate.core.provenance import ProvenanceGraph, NodeType


class ExactProvenanceResolver:
    """Resolves precise per-argument labels based on provenance DAG evidence."""

    def __init__(self, provenance_graph: ProvenanceGraph):
        self.provenance_graph = provenance_graph

    def resolve_argument_labels(
        self,
        arguments: Dict[str, Any],
        fallback_context_label: Label,
    ) -> Dict[str, Label]:
        """Infers individual argument labels.
        
        If an argument value is provably traceable to a trusted user turn or clean
        literal and does not match untrusted observations, it receives that clean label.
        If it contains data from an untrusted or sensitive source, it receives that
        source's label via lattice join. If untraceable or ambiguous, falls back
        conservatively to session context taint.
        """
        arg_labels: Dict[str, Label] = {}

        for arg_name, arg_val in arguments.items():
            arg_labels[arg_name] = self.resolve_single_argument_label(arg_val, fallback_context_label)

        return arg_labels

    def resolve_single_argument_label(
        self,
        value: Any,
        fallback_context_label: Label,
    ) -> Label:
        """Evaluates provenance of a single argument value."""
        if value is None:
            return LABEL_TRUSTED_PUBLIC

        # Convert value to normalized search string
        search_str = str(value).strip()
        # Single-character or trivial strings cannot be safely attributed to one source.
        if len(search_str) < 3:
            return fallback_context_label

        matched_labels: List[Label] = []

        # Word-boundary match against user turns. A clean-origin argument inherits *that turn's*
        # label, never a hard-coded trusted|public: a secret the user typed stays secret, so it
        # cannot be exfiltrated by routing it through "exact provenance".
        boundary = re.compile(r"(?:^|\W)" + re.escape(search_str) + r"(?:\W|$)")
        for node in self.provenance_graph.nodes.values():
            if node.node_type == NodeType.USER_INPUT:
                content = str(node.metadata.get("content", "")) or node.description
                if boundary.search(content):
                    matched_labels.append(node.label)

        # Substring match against tool results: data propagated from an observation keeps its taint.
        for node in self.provenance_graph.nodes.values():
            if node.node_type == NodeType.TOOL_RESULT:
                node_content = str(node.metadata.get("arguments", "")) + " " + node.description
                if search_str in node_content:
                    matched_labels.append(node.label)

        if not matched_labels:
            # Untraceable or ambiguous: conservatively inherit the session context taint.
            return fallback_context_label

        # The argument's label is the join over every source it provably came from. Only a value
        # traceable *solely* to clean (trusted|public) user input is declassified below context.
        res = matched_labels[0]
        for lbl in matched_labels[1:]:
            res = res.join(lbl)
        return res
