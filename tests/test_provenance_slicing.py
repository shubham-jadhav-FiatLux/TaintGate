"""Tests for ProvenanceGraph and backward program slicing (CS6843 Slicing)."""

from taintgate.core.provenance import ProvenanceGraph, NodeType
from taintgate.core.labels import (
    LABEL_TRUSTED_PUBLIC,
    LABEL_UNTRUSTED_PUBLIC,
    LABEL_TRUSTED_SECRET,
)


def test_provenance_graph_dag_construction():
    graph = ProvenanceGraph()
    n1 = graph.add_node(NodeType.USER_INPUT, LABEL_TRUSTED_PUBLIC, "user prompt", turn=1)
    n2 = graph.add_node(NodeType.TOOL_RESULT, LABEL_UNTRUSTED_PUBLIC, "web page", turn=2)
    n3 = graph.add_node(NodeType.TOOL_CALL, LABEL_UNTRUSTED_PUBLIC, "email.send", turn=3)

    graph.add_edge(n1.node_id, n2.node_id, relation="causes")
    graph.add_edge(n2.node_id, n3.node_id, relation="taints")

    assert len(graph.nodes) == 3
    assert len(graph.edges) == 2


def test_backward_slice_isolation():
    graph = ProvenanceGraph()
    # Path A -> Target
    nA1 = graph.add_node(NodeType.USER_INPUT, LABEL_TRUSTED_PUBLIC, "Prompt A", turn=1)
    nA2 = graph.add_node(NodeType.TOOL_RESULT, LABEL_TRUSTED_SECRET, "Secret Doc", turn=2)
    target = graph.add_node(NodeType.TOOL_CALL, LABEL_TRUSTED_SECRET, "Exfil Call", turn=3)

    graph.add_edge(nA1.node_id, nA2.node_id)
    graph.add_edge(nA2.node_id, target.node_id)

    # Disconnected Path B
    nB1 = graph.add_node(NodeType.TOOL_RESULT, LABEL_UNTRUSTED_PUBLIC, "Irrelevant Web Page", turn=2)

    slice_graph = graph.backward_slice(target.node_id)

    # Slice must contain A1, A2, and target, but NOT B1
    assert target.node_id in slice_graph.nodes
    assert nA2.node_id in slice_graph.nodes
    assert nA1.node_id in slice_graph.nodes
    assert nB1.node_id not in slice_graph.nodes


def test_format_flow_path():
    graph = ProvenanceGraph()
    source = graph.add_node(NodeType.TOOL_RESULT, LABEL_TRUSTED_SECRET, "company_secrets.txt", turn=1)
    target = graph.add_node(NodeType.TOOL_CALL, LABEL_TRUSTED_SECRET, "email.send(to=attacker)", turn=2)
    graph.add_edge(source.node_id, target.node_id, relation="leaks_to")

    formatted = graph.format_flow_path(target.node_id)
    assert "Target Sink:" in formatted
    assert "company_secrets.txt" in formatted
    assert "email.send" in formatted
