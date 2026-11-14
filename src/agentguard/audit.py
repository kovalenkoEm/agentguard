"""Append-only, tamper-evident audit log.

Each record carries the hash of the previous record, so deleting, reordering or
editing a line is detectable after the fact without a trusted timestamp server.
That is cheap (one SHA-256 per event) and turns "we log everything" from a claim
into something a reviewer can check::

    python -m agentguard.cli verify-audit .audit/audit.jsonl
"""

from __future__ import annotations

import hashlib
import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

__all__ = ["AuditLog", "GENESIS"]

GENESIS = "0" * 64


def _canonical(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str)


class AuditLog:
    def __init__(self, path: os.PathLike[str] | str):
        self.path = Path(path)
        if self.path.parent and not self.path.parent.exists():
            self.path.parent.mkdir(parents=True, exist_ok=True)
        self._seq, self._prev = self._tail()

    def _tail(self) -> tuple[int, str]:
        if not self.path.exists() or self.path.stat().st_size == 0:
            return 0, GENESIS
        last = ""
        with self.path.open("r", encoding="utf-8") as fh:
            for line in fh:
                if line.strip():
                    last = line
        if not last:
            return 0, GENESIS
        try:
            record = json.loads(last)
        except json.JSONDecodeError:  # truncated tail: keep appending, chain verifies False
            return 0, GENESIS
        return int(record.get("seq", 0)), str(record.get("hash", GENESIS))

    def append(self, event: str, **fields: Any) -> dict[str, Any]:
        self._seq += 1
        record: dict[str, Any] = {
            "seq": self._seq,
            "ts": datetime.now(timezone.utc).isoformat(timespec="milliseconds"),
            "event": event,
            **{k: v for k, v in fields.items() if v not in (None, "", (), [], {})},
            "prev": self._prev,
        }
        digest = hashlib.sha256((self._prev + _canonical(record)).encode("utf-8")).hexdigest()
        record["hash"] = digest
        with self.path.open("a", encoding="utf-8") as fh:
            fh.write(_canonical(record) + "\n")
        self._prev = digest
        return record

    @property
    def last_hash(self) -> str:
        return self._prev

    @staticmethod
    def verify(path: os.PathLike[str] | str) -> tuple[bool, int, str]:
        """Return ``(ok, records_checked, problem)``."""
        p = Path(path)
        if not p.exists():
            return False, 0, "log does not exist"
        prev = GENESIS
        n = 0
        with p.open("r", encoding="utf-8") as fh:
            for lineno, line in enumerate(fh, start=1):
                line = line.strip()
                if not line:
                    continue
                try:
                    record = json.loads(line)
                except json.JSONDecodeError:
                    return False, n, f"line {lineno}: not valid JSON"
                claimed = record.pop("hash", None)
                if record.get("prev") != prev:
                    return False, n, f"line {lineno}: chain link mismatch"
                digest = hashlib.sha256((prev + _canonical(record)).encode("utf-8")).hexdigest()
                if claimed != digest:
                    return False, n, f"line {lineno}: record hash mismatch (tampered)"
                prev = digest
                n += 1
        return True, n, ""
