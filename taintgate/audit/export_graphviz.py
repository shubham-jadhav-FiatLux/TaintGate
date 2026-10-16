"""Export ProvenanceGraph to Graphviz DOT format."""

from __future__ import annotations

from taintgate.core.provenance import ProvenanceGraph


def to_dot(graph: ProvenanceGraph) -> str:
    """Renders a ProvenanceGraph in Graphviz DOT format with color coding by label."""
    lines = ["digraph Provenance {", "  rankdir=LR;", "  node [shape=box, style=filled, fontname=Helvetica];"]

    for node_id, node in graph.nodes.items():
        # Color coding: untrusted = lightpink, secret = red/salmon, trusted = lightgreen
        color = "white"
        if node.label.integrity.name.lower() == "untrusted":
            color = "#ffcccc"
        elif node.label.confidentiality.name.lower() == "secret":
            color = "#ff9999"
        elif node.label.integrity.name.lower() == "trusted":
            color = "#ccffcc"

        label_txt = f"{node.description}\\n{node.label}\\n(turn {node.turn})"
        escaped_label = label_txt.replace('"', '\\"')
        lines.append(f'  "{node_id}" [label="{escaped_label}", fillcolor="{color}"];')

    for edge in graph.edges:
        lines.append(f'  "{edge.source_id}" -> "{edge.target_id}" [label="{edge.relation}"];')

    lines.append("}")
    return "\n".join(lines)
