"""Append-only, hash-chained audit log of every tool-call decision.

Each JSON line carries `prev` (the previous line's hash) and `hash`
(SHA-256 of the line itself without `hash`). Editing or deleting a line
breaks the chain at that line. Truncating the tail or rewriting the
whole file is NOT detectable locally; that needs the off-box copy
(Milestone 4).
"""

import fcntl
import hashlib
import json
import os
import threading
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

GENESIS = "0" * 64
_SENSITIVE = ("password", "secret", "token", "key", "assertion")
_CHAIN_FIELDS = ("seq", "ts", "prev", "hash")
_TAIL_CHUNK = 8192


def redact(obj: Any) -> Any:
    """Replace the value of any key that looks sensitive, at any depth."""
    if isinstance(obj, dict):
        return {
            k: "[redacted]" if any(s in str(k).lower() for s in _SENSITIVE) else redact(v)
            for k, v in obj.items()
        }
    if isinstance(obj, list):
        return [redact(v) for v in obj]
    return obj


def _canonical(record: dict[str, Any]) -> str:
    return json.dumps(
        record, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str
    )


def _digest(record: dict[str, Any]) -> str:
    return hashlib.sha256(_canonical(record).encode("utf-8")).hexdigest()


class AuditLog:
    """Several processes may append to one file (one server per Claude Code session), so each
    append takes an exclusive flock and re-reads the chain head from the file under it; the
    in-memory head is never trusted across appends."""

    def __init__(self, path: Path) -> None:
        self._path = path
        self._lock = threading.Lock()
        if path.exists() and path.stat().st_size:
            with path.open("rb") as f:
                self._head(f.fileno())  # a corrupt tail stops startup

    def _head(self, fd: int) -> tuple[str, int]:
        """(hash, seq) of the last record, read backwards from the end of the open file."""
        end = os.lseek(fd, 0, os.SEEK_END)
        if end == 0:
            return GENESIS, 0
        buf, pos = b"", end
        while pos > 0:
            step = min(_TAIL_CHUNK, pos)
            pos -= step
            buf = os.pread(fd, step, pos) + buf
            body = buf.rstrip(b"\n")
            if b"\n" in body or pos == 0:
                break
        last = buf.rstrip(b"\n").rsplit(b"\n", 1)[-1]
        try:
            record = json.loads(last.decode("utf-8"))
            return record["hash"], record["seq"]
        except (ValueError, KeyError) as exc:
            raise ValueError(f"Audit log tail is corrupt; run verify on {self._path}") from exc

    def append(self, event: dict[str, Any]) -> str:
        """Write one record durably and return its hash."""
        # An event key named like a chain field (e.g. "hash") would be hashed into the
        # record and break verify(), so those names are dropped from the event.
        fields = {k: v for k, v in redact(event).items() if k not in _CHAIN_FIELDS}
        with self._lock:
            fd = os.open(self._path, os.O_RDWR | os.O_APPEND | os.O_CREAT, 0o600)
            try:
                fcntl.flock(fd, fcntl.LOCK_EX)  # held across read-head -> write -> fsync
                prev, seq = self._head(fd)
                record = {
                    **fields,
                    "seq": seq + 1,
                    "ts": datetime.now(UTC).isoformat(),
                    "prev": prev,
                }
                record["hash"] = _digest(record)
                data = (_canonical(record) + "\n").encode("utf-8")
                start = os.lseek(fd, 0, os.SEEK_END)
                try:
                    written = 0
                    while written < len(data):  # os.write may accept only part of a buffer
                        written += os.write(fd, data[written:])
                    os.fsync(fd)
                except OSError:
                    os.ftruncate(fd, start)  # never leave a partial record behind
                    raise
                return record["hash"]
            finally:
                os.close(fd)  # closing releases the flock

    @staticmethod
    def load(path: Path) -> tuple[bool, int | None, list[dict[str, Any]]]:
        """Parse and verify the log: (ok, first bad line number, records).

        The single parser for every reader (verify, azsec-mcp-ship). Lines are split on
        "\n" only: records may contain U+2028/U+2029 and other characters that
        str.splitlines() would treat as line breaks.
        """
        prev, seq = GENESIS, 1
        records: list[dict[str, Any]] = []
        lines = path.read_text(encoding="utf-8").split("\n")
        if lines and lines[-1] == "":
            lines.pop()
        for lineno, line in enumerate(lines, start=1):
            try:
                record = json.loads(line)
                claimed = record.pop("hash")
            except (ValueError, KeyError, AttributeError):
                return False, lineno, records
            if record.get("prev") != prev or record.get("seq") != seq:
                return False, lineno, records
            if claimed != _digest(record):
                return False, lineno, records
            records.append({**record, "hash": claimed})
            prev, seq = claimed, seq + 1
        return True, None, records

    @staticmethod
    def verify(path: Path) -> tuple[bool, int | None]:
        """Return (True, None) if the chain is intact, else (False, first bad line number)."""
        ok, bad_line, _ = AuditLog.load(path)
        return ok, bad_line
