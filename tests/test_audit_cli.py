"""Tests for audit log replay, Graphviz DOT export, and audit CLI subcommands."""

from pathlib import Path
import pytest
import sys

from taintgate.core.events import ProvenanceEvent, ProvenanceEventType
from taintgate.core.labels import LABEL_TRUSTED_PUBLIC, LABEL_UNTRUSTED_SECRET
from taintgate.audit.log import HashChainLog
from taintgate.audit.replay import (
    load_audit_events,
    reconstruct_provenance_graph,
    replay_audit_log,
)
from taintgate.audit.export_graphviz import to_dot
from taintgate.cli import main


def test_audit_replay_and_graphviz_export(tmp_path: Path):
    log_file = tmp_path / "session_audit.jsonl"
    logger = HashChainLog(log_file)

    ev1 = ProvenanceEvent(
        session_id="sess_replay_1",
        event_type=ProvenanceEventType.CONTEXT_ADDITION,
        label=LABEL_TRUSTED_PUBLIC,
        details={"info": "Initial user task instructions"},
    )
    ev2 = ProvenanceEvent(
        session_id="sess_replay_1",
        event_type=ProvenanceEventType.TOOL_RESULT,
        label=LABEL_UNTRUSTED_SECRET,
        details={"tool": "web.search", "output_summary": "compromised payload"},
    )
    ev3 = ProvenanceEvent(
        session_id="sess_replay_1",
        event_type=ProvenanceEventType.DECISION_EVALUATED,
        label=LABEL_UNTRUSTED_SECRET,
        details={"tool": "email.send", "verdict": "deny", "reason": "Rule of Two violation"},
    )

    logger.append(ev1)
    logger.append(ev2)
    logger.append(ev3)

    # 1. Test load_audit_events
    loaded = load_audit_events(log_file)
    assert len(loaded) == 3
    assert loaded[0].event_type == ProvenanceEventType.CONTEXT_ADDITION
    assert loaded[1].details["tool"] == "web.search"
    assert loaded[2].details["verdict"] == "deny"

    # 2. Test replay_audit_log
    summary = replay_audit_log(log_file)
    assert len(summary) == 3
    assert summary[0]["step"] == 1
    assert summary[2]["details"]["verdict"] == "deny"

    # 3. Test reconstruct_provenance_graph
    graph = reconstruct_provenance_graph(loaded)
    assert len(graph.nodes) == 3
    assert len(graph.edges) == 2

    # 4. Test to_dot
    dot_output = to_dot(graph)
    assert "digraph Provenance {" in dot_output
    assert "web.search" in dot_output
    assert "email.send" in dot_output
    assert "#ffcccc" in dot_output or "#ff9999" in dot_output  # Color highlighting for untrusted/secret


def test_audit_cli_replay_command(tmp_path: Path, monkeypatch, capsys):
    log_file = tmp_path / "test_cli_replay.jsonl"
    logger = HashChainLog(log_file)
    ev = ProvenanceEvent(
        session_id="s1",
        event_type=ProvenanceEventType.TOOL_RESULT,
        label=LABEL_TRUSTED_PUBLIC,
        details={"tool": "file.read", "output_summary": "normal file"},
    )
    logger.append(ev)

    monkeypatch.setattr(sys, "argv", ["taintgate", "audit", "replay", "--log", str(log_file)])
    with pytest.raises(SystemExit) as exc_info:
        main()
    assert exc_info.value.code == 0

    captured = capsys.readouterr()
    assert "Replaying Audit Log" in captured.out
    assert "file.read" in captured.out


def test_audit_cli_export_dot_command(tmp_path: Path, monkeypatch, capsys):
    log_file = tmp_path / "test_cli_dot.jsonl"
    dot_out_file = tmp_path / "graph.dot"
    logger = HashChainLog(log_file)
    ev = ProvenanceEvent(
        session_id="s1",
        event_type=ProvenanceEventType.TOOL_RESULT,
        label=LABEL_UNTRUSTED_SECRET,
        details={"tool": "external_api", "output_summary": "secret data"},
    )
    logger.append(ev)

    # Test file export
    monkeypatch.setattr(sys, "argv", ["taintgate", "audit", "export-dot", "--log", str(log_file), "--output", str(dot_out_file)])
    with pytest.raises(SystemExit) as exc_info:
        main()
    assert exc_info.value.code == 0
    assert dot_out_file.exists()
    assert "digraph Provenance {" in dot_out_file.read_text(encoding="utf-8")
