from __future__ import annotations

import json

from agentguard.audit import AuditLog


def test_chain_appends_and_verifies(tmp_path):
    log = AuditLog(tmp_path / "audit.jsonl")
    for i in range(5):
        log.append("decision", tool="read_file", seq_hint=i, verdict="ALLOWED")
    ok, count, problem = AuditLog.verify(tmp_path / "audit.jsonl")
    assert ok, problem
    assert count == 5


def test_reopen_continues_chain(tmp_path):
    path = tmp_path / "audit.jsonl"
    AuditLog(path).append("decision", tool="a")
    second = AuditLog(path)
    second.append("decision", tool="b")
    ok, count, _ = AuditLog.verify(path)
    assert ok and count == 2


def test_tampering_is_detected(tmp_path):
    path = tmp_path / "audit.jsonl"
    log = AuditLog(path)
    log.append("decision", tool="read_file", verdict="BLOCKED")
    log.append("decision", tool="read_file", verdict="ALLOWED")

    lines = path.read_text(encoding="utf-8").splitlines()
    record = json.loads(lines[0])
    record["verdict"] = "ALLOWED"  # rewrite history: the block never happened
    lines[0] = json.dumps(record, sort_keys=True, ensure_ascii=False)
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    ok, count, problem = AuditLog.verify(path)
    assert not ok
    assert "tampered" in problem or "mismatch" in problem


def test_deleted_record_breaks_chain(tmp_path):
    path = tmp_path / "audit.jsonl"
    log = AuditLog(path)
    for _ in range(3):
        log.append("decision", tool="x")
    lines = path.read_text(encoding="utf-8").splitlines()
    path.write_text("\n".join(lines[1:]) + "\n", encoding="utf-8")
    ok, _, problem = AuditLog.verify(path)
    assert not ok
    assert "chain" in problem
