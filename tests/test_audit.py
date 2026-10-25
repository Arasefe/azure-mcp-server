import json
import stat
from concurrent.futures import ThreadPoolExecutor

import pytest

from azsec_mcp.audit import AuditLog, redact


def read_lines(p):
    return p.read_text(encoding="utf-8").splitlines()


def write_lines(p, lines):
    p.write_text("\n".join(lines) + "\n", encoding="utf-8")


def make_log(p, n):
    log = AuditLog(p)
    for i in range(n):
        log.append({"tool": f"t{i}"})
    return log


def test_chain_verifies(tmp_path):
    p = tmp_path / "a.jsonl"
    make_log(p, 3)
    assert AuditLog.verify(p) == (True, None)


def test_edit_detected_at_line(tmp_path):
    p = tmp_path / "a.jsonl"
    make_log(p, 3)
    lines = read_lines(p)
    lines[1] = lines[1].replace('"t1"', '"tX"')
    write_lines(p, lines)
    assert AuditLog.verify(p) == (False, 2)


def test_deleted_middle_line_detected(tmp_path):
    p = tmp_path / "a.jsonl"
    make_log(p, 3)
    lines = read_lines(p)
    del lines[1]
    write_lines(p, lines)
    assert AuditLog.verify(p) == (False, 2)


def test_tail_truncation_needs_offbox_anchor(tmp_path):
    # Documented limitation: dropping the last lines leaves a valid, shorter chain.
    # Detecting this needs the off-box copy shipped to Sentinel (Milestone 4).
    p = tmp_path / "a.jsonl"
    make_log(p, 3)
    write_lines(p, read_lines(p)[:-1])
    assert AuditLog.verify(p) == (True, None)


def test_resume_continues_chain(tmp_path):
    p = tmp_path / "a.jsonl"
    AuditLog(p).append({"tool": "a"})
    AuditLog(p).append({"tool": "b"})
    assert AuditLog.verify(p) == (True, None)
    assert [json.loads(line)["seq"] for line in read_lines(p)] == [1, 2]


def test_event_cannot_override_chain_fields(tmp_path):
    p = tmp_path / "a.jsonl"
    AuditLog(p).append({"seq": 99, "prev": "x", "hash": "y"})
    assert AuditLog.verify(p) == (True, None)
    assert json.loads(read_lines(p)[0])["seq"] == 1


def test_redact_nested_password_and_token():
    out = redact({"upn": "a@b.com", "password": "p", "n": [{"accessToken": "t"}]})
    assert out == {
        "upn": "a@b.com",
        "password": "[redacted]",
        "n": [{"accessToken": "[redacted]"}],
    }


def test_concurrent_appends_keep_chain_valid(tmp_path):
    p = tmp_path / "a.jsonl"
    log = AuditLog(p)
    with ThreadPoolExecutor(max_workers=16) as pool:
        list(pool.map(lambda i: log.append({"i": i}), range(50)))
    assert AuditLog.verify(p) == (True, None)
    assert [json.loads(line)["seq"] for line in read_lines(p)] == list(range(1, 51))


def test_log_file_is_owner_only(tmp_path):
    p = tmp_path / "a.jsonl"
    AuditLog(p).append({"tool": "a"})
    assert stat.S_IMODE(p.stat().st_mode) == 0o600


def test_corrupt_tail_refuses_to_start(tmp_path):
    p = tmp_path / "a.jsonl"
    p.write_text("not json\n", encoding="utf-8")
    with pytest.raises(ValueError, match="corrupt"):
        AuditLog(p)


def test_load_returns_records_split_on_newline_only(tmp_path):
    p = tmp_path / "a.jsonl"
    AuditLog(p).append({"tool": "t", "args": {"q": "a b"}})
    ok, bad, records = AuditLog.load(p)
    assert (ok, bad) == (True, None)
    assert records[0]["args"]["q"] == "a b"


def test_two_writers_on_one_file_keep_the_chain_valid(tmp_path):
    # Two Claude Code sessions = two server processes appending to the same audit.jsonl.
    # Separate AuditLog instances have separate in-memory state, like separate processes.
    p = tmp_path / "a.jsonl"
    first, second = AuditLog(p), AuditLog(p)
    with ThreadPoolExecutor(max_workers=8) as pool:
        list(pool.map(lambda i: (first if i % 2 else second).append({"i": i}), range(40)))
    assert AuditLog.verify(p) == (True, None)
    assert [json.loads(line)["seq"] for line in read_lines(p)] == list(range(1, 41))


def test_resume_after_a_record_larger_than_one_read_chunk(tmp_path):
    p = tmp_path / "a.jsonl"
    log = AuditLog(p)
    log.append({"args": {"query": "x" * 50_000}})
    log.append({"tool": "after"})
    AuditLog(p).append({"tool": "third"})
    assert AuditLog.verify(p) == (True, None)
