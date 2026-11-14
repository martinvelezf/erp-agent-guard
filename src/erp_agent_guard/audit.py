"""Append-only, hash-chained JSONL audit log.

Each line carries ``prev`` (hash of the previous line) and ``hash``
(sha256 of the canonical line without ``hash``). Editing, deleting or
reordering a line breaks the chain, which ``verify_audit`` reports.
This is tamper-*evident*, not tamper-proof: ship the file to WORM storage
or a SIEM if you need the latter.
"""

from __future__ import annotations

import hashlib
import json
import os
import threading
import time
from pathlib import Path
from typing import Any

GENESIS = "0" * 64


def _canonical(obj: dict) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str).encode()


def _hash(entry: dict) -> str:
    body = {k: v for k, v in entry.items() if k != "hash"}
    return hashlib.sha256(_canonical(body)).hexdigest()


class AuditLog:
    def __init__(self, path: str | Path | None, clock=time.time):
        self.path = Path(path) if path else None
        self._clock = clock
        self._lock = threading.Lock()
        self._prev = GENESIS
        self.memory: list[dict] = []  # used when path is None (tests, dry demos)
        if self.path and self.path.exists():
            last = None
            with self.path.open("rb") as fh:
                for line in fh:
                    if line.strip():
                        last = line
            if last:
                self._prev = json.loads(last)["hash"]

    def write(self, event: str, agent: str, **fields: Any) -> dict:
        with self._lock:
            entry = {
                "ts": round(self._clock(), 3),
                "event": event,
                "agent": agent,
                **fields,
                "prev": self._prev,
            }
            entry["hash"] = _hash(entry)
            line = json.dumps(entry, sort_keys=True, ensure_ascii=False, default=str)
            if self.path:
                self.path.parent.mkdir(parents=True, exist_ok=True)
                # O_APPEND: the OS never overwrites existing bytes.
                fd = os.open(self.path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
                try:
                    os.write(fd, (line + "\n").encode())
                    os.fsync(fd)
                finally:
                    os.close(fd)
            else:
                self.memory.append(entry)
            self._prev = entry["hash"]
            return entry


def verify_audit(path: str | Path) -> tuple[bool, int, str]:
    """Return (ok, lines_checked, message)."""
    prev = GENESIS
    n = 0
    with Path(path).open("r", encoding="utf-8") as fh:
        for lineno, line in enumerate(fh, 1):
            if not line.strip():
                continue
            try:
                entry = json.loads(line)
            except json.JSONDecodeError:
                return False, n, f"line {lineno}: not valid JSON"
            if entry.get("prev") != prev:
                return False, n, f"line {lineno}: chain broken (prev does not match previous hash)"
            if entry.get("hash") != _hash(entry):
                return False, n, f"line {lineno}: content hash mismatch (line was edited)"
            prev = entry["hash"]
            n += 1
    return True, n, f"{n} entries, chain intact, head={prev[:16]}"
