"""Append-only, hash-chained audit log of every tool-call decision.

Each JSON line carries `prev` (the previous line's hash) and `hash`
(SHA-256 of the line itself without `hash`). Editing or deleting a line
breaks the chain at that line. Truncating the tail or rewriting the
whole file is NOT detectable locally; that needs the off-box copy
(Milestone 4).
"""

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
    def __init__(self, path: Path) -> None:
        self._path = path
        self._lock = threading.Lock()
        self._prev, self._seq = self._read_tail()

    def _read_tail(self) -> tuple[str, int]:
        """Resume the chain from the last line, or start at genesis."""
        if not self._path.exists() or self._path.stat().st_size == 0:
            return GENESIS, 0
        last = self._path.read_text(encoding="utf-8").rstrip("\n").rsplit("\n", 1)[-1]
        try:
            record = json.loads(last)
            return record["hash"], record["seq"]
        except (ValueError, KeyError) as exc:
            raise ValueError(f"Audit log tail is corrupt; run verify on {self._path}") from exc

    def append(self, event: dict[str, Any]) -> str:
        """Write one record durably and return its hash."""
        # An event key named like a chain field (e.g. "hash") would be hashed into the
        # record and break verify(), so those names are dropped from the event.
        fields = {k: v for k, v in redact(event).items() if k not in _CHAIN_FIELDS}
        with self._lock:
            record = {
                **fields,
                "seq": self._seq + 1,
                "ts": datetime.now(UTC).isoformat(),
                "prev": self._prev,
            }
            record["hash"] = _digest(record)
            fd = os.open(self._path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
            with os.fdopen(fd, "a", encoding="utf-8") as f:
                f.write(_canonical(record) + "\n")
                f.flush()
                os.fsync(f.fileno())
            self._prev, self._seq = record["hash"], record["seq"]
            return record["hash"]

    @staticmethod
    def verify(path: Path) -> tuple[bool, int | None]:
        """Return (True, None) if the chain is intact, else (False, first bad line number)."""
        prev, seq = GENESIS, 1
        with path.open(encoding="utf-8") as f:
            for lineno, line in enumerate(f, start=1):
                try:
                    record = json.loads(line)
                    claimed = record.pop("hash")
                except (ValueError, KeyError):
                    return False, lineno
                if record.get("prev") != prev or record.get("seq") != seq:
                    return False, lineno
                if claimed != _digest(record):
                    return False, lineno
                prev, seq = claimed, seq + 1
        return True, None
