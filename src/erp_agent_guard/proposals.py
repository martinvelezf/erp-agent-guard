"""Pending write proposals (dry-runs) awaiting commit.

Stored as one JSON file so the human approving from another terminal
(``erp-agent-guard approve``) sees exactly what the gateway will commit.
"""

from __future__ import annotations

import json
import os
import tempfile
import threading
from pathlib import Path


class ProposalStore:
    def __init__(self, path: str | Path | None = None):
        self.path = Path(path) if path else None
        self._lock = threading.Lock()
        self._mem: dict[str, dict] = {}

    def _load(self) -> dict[str, dict]:
        if self.path is None:
            return self._mem
        if not self.path.exists():
            return {}
        return json.loads(self.path.read_text(encoding="utf-8") or "{}")

    def _save(self, data: dict[str, dict]) -> None:
        if self.path is None:
            self._mem = data
            return
        self.path.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp = tempfile.mkstemp(dir=self.path.parent, prefix=".proposals.")
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(data, fh, indent=2, sort_keys=True, default=str)
        os.chmod(tmp, 0o600)
        os.replace(tmp, self.path)

    def put(self, proposal: dict) -> None:
        with self._lock:
            data = self._load()
            data[proposal["id"]] = proposal
            self._save(data)

    def get(self, proposal_id: str) -> dict | None:
        with self._lock:
            return self._load().get(proposal_id)

    def update(self, proposal_id: str, **fields) -> dict:
        with self._lock:
            data = self._load()
            data[proposal_id].update(fields)
            self._save(data)
            return data[proposal_id]

    def all(self) -> list[dict]:
        with self._lock:
            return sorted(self._load().values(), key=lambda p: p.get("created", 0))
