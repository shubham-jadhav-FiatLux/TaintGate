"""Replay session events from an audit log."""

from __future__ import annotations

import json
from pathlib import Path
from typing import List

from taintgate.core.events import ProvenanceEvent


def load_audit_events(log_path: Path) -> List[ProvenanceEvent]:
    """Loads and deserializes ProvenanceEvents from an audit log."""
    path = Path(log_path)
    if not path.exists():
        return []

    events: List[ProvenanceEvent] = []
    lines = [l.strip() for l in path.read_text(encoding="utf-8").splitlines() if l.strip()]
    for line in lines:
        record = json.loads(line)
        event_dict = record.get("event")
        if event_dict:
            events.append(ProvenanceEvent.from_dict(event_dict))
    return events


def reconstruct_provenance_graph(events: List[ProvenanceEvent]) -> "ProvenanceGraph":
    """Reconstructs a ProvenanceGraph DAG from an ordered sequence of ProvenanceEvents."""
    from taintgate.core.provenance import ProvenanceGraph, NodeType

    graph = ProvenanceGraph()
    prev_node_id = None

    for idx, ev in enumerate(events):
        if ev.event_type.value == "tool_result":
            ntype = NodeType.TOOL_RESULT
            tool = ev.details.get("tool", "tool_result")
            desc = f"Result: {tool}"
        elif ev.event_type.value == "decision_evaluated":
            ntype = NodeType.TOOL_CALL
            tool = ev.details.get("tool", "tool_call")
            verdict = ev.details.get("verdict", "")
            desc = f"Call: {tool} [{verdict}]"
        elif ev.event_type.value == "context_addition":
            ntype = NodeType.USER_INPUT
            desc = f"Context: {ev.details.get('info', 'addition')}"
        else:
            ntype = NodeType.EXTERNAL_SOURCE
            desc = f"Event: {ev.event_type.value}"

        node = graph.add_node(
            node_type=ntype,
            label=ev.label,
            description=desc,
            turn=idx + 1,
            node_id=ev.event_id,
            metadata=ev.details,
        )
        if prev_node_id is not None:
            graph.add_edge(prev_node_id, node.node_id, relation="propagates_to")
        prev_node_id = node.node_id

    return graph


def replay_audit_log(log_path: Path) -> List[dict]:
    """Replays an audit log, summarizing the timeline of events."""
    events = load_audit_events(log_path)
    summary = []
    for idx, ev in enumerate(events):
        summary.append({
            "step": idx + 1,
            "event_id": ev.event_id,
            "session_id": ev.session_id,
            "timestamp": ev.timestamp,
            "type": ev.event_type.value,
            "label": str(ev.label),
            "details": ev.details,
        })
    return summary

