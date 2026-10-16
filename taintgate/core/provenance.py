"""Provenance Graph and Backward Slicing.

Maintains an explicit session dataflow DAG and computes backward program slices
to explain blocked actions and taint origin (CS6843 Slicing & Provenance).
"""

from __future__ import annotations

from enum import Enum
from typing import Any, Dict, List, Optional, Set
from dataclasses import dataclass, field
import uuid

from taintgate.core.lattice import Label


class NodeType(str, Enum):
    USER_INPUT = "user_input"
    TOOL_RESULT = "tool_result"
    MODEL_TURN = "model_turn"
    TOOL_CALL = "tool_call"
    EXTERNAL_SOURCE = "external_source"


@dataclass
class ProvenanceNode:
    node_id: str
    node_type: NodeType
    label: Label
    description: str
    turn: int = 0
    metadata: Dict[str, Any] = field(default_factory=dict)

    def __repr__(self) -> str:
        return f"Node({self.node_id!r}, type={self.node_type.value}, label={self.label}, desc={self.description!r})"


@dataclass
class ProvenanceEdge:
    source_id: str
    target_id: str
    relation: str = "flows_to"


class ProvenanceGraph:
    """Directed Acyclic Graph of session dataflow and taint propagation."""

    def __init__(self) -> None:
        self.nodes: Dict[str, ProvenanceNode] = {}
        self.edges: List[ProvenanceEdge] = []
        self._in_edges: Dict[str, List[ProvenanceEdge]] = {}
        self._out_edges: Dict[str, List[ProvenanceEdge]] = {}

    def add_node(
        self,
        node_type: NodeType,
        label: Label,
        description: str,
        turn: int = 0,
        node_id: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> ProvenanceNode:
        if node_id is None:
            node_id = f"node_{len(self.nodes) + 1}_{uuid.uuid4().hex[:6]}"
        node = ProvenanceNode(
            node_id=node_id,
            node_type=node_type,
            label=label,
            description=description,
            turn=turn,
            metadata=metadata or {},
        )
        self.nodes[node_id] = node
        self._in_edges[node_id] = []
        self._out_edges[node_id] = []
        return node

    def add_edge(self, source_id: str, target_id: str, relation: str = "flows_to") -> None:
        if source_id not in self.nodes:
            raise KeyError(f"Source node not found in graph: {source_id}")
        if target_id not in self.nodes:
            raise KeyError(f"Target node not found in graph: {target_id}")

        edge = ProvenanceEdge(source_id=source_id, target_id=target_id, relation=relation)
        self.edges.append(edge)
        self._in_edges[target_id].append(edge)
        self._out_edges[source_id].append(edge)

    def backward_slice(self, target_node_id: str) -> "ProvenanceGraph":
        """Computes backward slice: minimal sub-DAG reachable via inbound edges from target_node_id."""
        if target_node_id not in self.nodes:
            raise KeyError(f"Target node not found: {target_node_id}")

        slice_graph = ProvenanceGraph()
        visited: Set[str] = set()
        queue: List[str] = [target_node_id]

        while queue:
            curr = queue.pop(0)
            if curr in visited:
                continue
            visited.add(curr)
            orig_node = self.nodes[curr]
            slice_graph.nodes[curr] = orig_node
            slice_graph._in_edges[curr] = []
            slice_graph._out_edges[curr] = []

            for edge in self._in_edges.get(curr, []):
                slice_graph.edges.append(edge)
                slice_graph._in_edges[curr].append(edge)
                if edge.source_id not in slice_graph._out_edges:
                    slice_graph._out_edges[edge.source_id] = []
                slice_graph._out_edges[edge.source_id].append(edge)

                if edge.source_id not in visited:
                    queue.append(edge.source_id)

        return slice_graph

    def format_flow_path(self, target_node_id: str) -> str:
        """Formats a human-readable source -> sink backward explanation trace."""
        if target_node_id not in self.nodes:
            return f"Unknown node {target_node_id}"

        slice_subgraph = self.backward_slice(target_node_id)
        target = self.nodes[target_node_id]

        # Find roots (nodes with no inbound edges in slice)
        roots = [nid for nid, node in slice_subgraph.nodes.items() if not slice_subgraph._in_edges.get(nid)]
        
        lines: List[str] = []
        lines.append(f"Target Sink: {target.description} {target.label}")
        lines.append("Contributing Provenance Slices:")

        for root_id in roots:
            root = slice_subgraph.nodes[root_id]
            lines.append(f"  └─ Source [{root.node_type.value}]: {root.description} {root.label} (turn {root.turn})")
            # Trace path to target
            curr_id = root_id
            indent = "      "
            while True:
                out_edges = [e for e in slice_subgraph._out_edges.get(curr_id, []) if e.target_id in slice_subgraph.nodes]
                if not out_edges:
                    break
                next_id = out_edges[0].target_id
                next_node = slice_subgraph.nodes[next_id]
                lines.append(f"{indent}└─► {next_node.description} {next_node.label}")
                curr_id = next_id
                indent += "    "

        return "\n".join(lines)
