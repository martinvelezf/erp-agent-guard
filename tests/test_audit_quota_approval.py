import json

import pytest

from erp_agent_guard.approval import issue_token, verify_token
from erp_agent_guard.audit import AuditLog, verify_audit
from erp_agent_guard.errors import ApprovalError, QuotaExceeded
from erp_agent_guard.quota import QuotaTracker

from conftest import Clock


def test_audit_chain_verifies_and_detects_edit(tmp_path):
    path = tmp_path / "audit.jsonl"
    log = AuditLog(path, clock=Clock())
    for i in range(3):
        log.write("read", "a", n=i)
    assert verify_audit(path)[0]
    lines = path.read_text().splitlines()
    e = json.loads(lines[1]); e["n"] = 99
    lines[1] = json.dumps(e, sort_keys=True)
    path.write_text("\n".join(lines) + "\n")
    ok, _, msg = verify_audit(path)
    assert not ok and "line 2" in msg


def test_audit_detects_deleted_line(tmp_path):
    path = tmp_path / "audit.jsonl"
    log = AuditLog(path)
    for i in range(3):
        log.write("read", "a", n=i)
    lines = path.read_text().splitlines()
    path.write_text("\n".join([lines[0], lines[2]]) + "\n")
    ok, _, msg = verify_audit(path)
    assert not ok and "chain broken" in msg


def test_audit_resumes_chain_across_restarts(tmp_path):
    path = tmp_path / "audit.jsonl"
    AuditLog(path).write("x", "a")
    AuditLog(path).write("y", "a")
    ok, n, _ = verify_audit(path)
    assert ok and n == 2


def test_rate_limit_sliding_window():
    clock = Clock(0)
    q = QuotaTracker(clock=clock)
    for _ in range(3):
        q.check_call("a", 3)
    with pytest.raises(QuotaExceeded):
        q.check_call("a", 3)
    q.check_call("b", 3)  # per agent
    clock.t = 60.5
    q.check_call("a", 3)


def test_write_quota():
    q = QuotaTracker(clock=Clock(0))
    q.check_write("a", 3, 2)
    q.record_write("a", 2)
    with pytest.raises(QuotaExceeded):
        q.check_write("a", 3, 2)


SECRET = b"0123456789abcdef0123"


def test_token_roundtrip_and_binding():
    tok = issue_token(SECRET, "p_1", "d" * 64, ttl=60, now=1000)
    verify_token(SECRET, tok, "p_1", "d" * 64, now=1030)
    with pytest.raises(ApprovalError, match="different proposal"):
        verify_token(SECRET, tok, "p_2", "d" * 64, now=1030)
    with pytest.raises(ApprovalError, match="signature"):
        verify_token(SECRET, tok, "p_1", "e" * 64, now=1030)
    with pytest.raises(ApprovalError, match="signature"):
        verify_token(b"another-secret-xxxxxxxx", tok, "p_1", "d" * 64, now=1030)
    with pytest.raises(ApprovalError, match="expired"):
        verify_token(SECRET, tok, "p_1", "d" * 64, now=1061)
    with pytest.raises(ApprovalError, match="malformed"):
        verify_token(SECRET, "garbage", "p_1", "d" * 64)


def test_token_expiry_cannot_be_extended():
    tok = issue_token(SECRET, "p_1", "d" * 64, ttl=60, now=1000)
    pid, exp, mac = tok.split(".")
    forged = f"{pid}.{int(exp) + 3600}.{mac}"
    with pytest.raises(ApprovalError):
        verify_token(SECRET, forged, "p_1", "d" * 64, now=1100)


def test_two_writers_share_one_chain(tmp_path):
    # The gateway and the approve CLI are separate processes writing one log.
    path = tmp_path / "audit.jsonl"
    gw, cli = AuditLog(path), AuditLog(path)
    gw.write("propose", "a")
    cli.write("approve", "a")
    gw.write("commit", "a", pad="x" * 5000)  # longer than one tail-read block
    cli.write("read", "a")
    ok, n, _ = verify_audit(path)
    assert ok and n == 4
