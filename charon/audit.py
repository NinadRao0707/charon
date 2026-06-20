"""Append-only, hash-chained audit log.

Each entry stores the SHA-256 hash of the previous entry, so any modification or
deletion of a historical record breaks the chain and is detectable. This gives
tamper-evidence without external infrastructure and is a core part of the
"identity depth" story: every issuance, authorization decision, and lifecycle
transition is recorded here.
"""
from __future__ import annotations

import hashlib
import json
import time
from dataclasses import dataclass, field

GENESIS_HASH = "0" * 64


@dataclass(frozen=True)
class AuditEntry:
    seq: int
    timestamp: float
    event: str
    subject: str  # the agent id (or "system")
    details: dict
    prev_hash: str
    entry_hash: str

    def to_row(self) -> dict:
        return {
            "seq": self.seq,
            "timestamp": self.timestamp,
            "event": self.event,
            "subject": self.subject,
            "details": json.dumps(self.details, sort_keys=True),
            "prev_hash": self.prev_hash,
            "entry_hash": self.entry_hash,
        }


def _compute_hash(
    seq: int, timestamp: float, event: str, subject: str, details: dict, prev_hash: str
) -> str:
    payload = json.dumps(
        {
            "seq": seq,
            "timestamp": timestamp,
            "event": event,
            "subject": subject,
            "details": details,
            "prev_hash": prev_hash,
        },
        sort_keys=True,
        separators=(",", ":"),
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


class AuditLog:
    """In-memory hash chain. The repository persists entries; this class owns
    the chaining and verification logic so it can be tested standalone."""

    def __init__(self) -> None:
        self._entries: list[AuditEntry] = []

    @property
    def head_hash(self) -> str:
        return self._entries[-1].entry_hash if self._entries else GENESIS_HASH

    def append(self, event: str, subject: str, details: dict | None = None) -> AuditEntry:
        seq = len(self._entries)
        timestamp = time.time()
        prev_hash = self.head_hash
        details = details or {}
        entry_hash = _compute_hash(seq, timestamp, event, subject, details, prev_hash)
        entry = AuditEntry(
            seq=seq,
            timestamp=timestamp,
            event=event,
            subject=subject,
            details=details,
            prev_hash=prev_hash,
            entry_hash=entry_hash,
        )
        self._entries.append(entry)
        return entry

    def entries(self) -> list[AuditEntry]:
        return list(self._entries)

    def verify(self) -> bool:
        """Re-walk the chain and confirm no entry has been altered."""
        prev = GENESIS_HASH
        for i, e in enumerate(self._entries):
            if e.seq != i or e.prev_hash != prev:
                return False
            expected = _compute_hash(
                e.seq, e.timestamp, e.event, e.subject, e.details, e.prev_hash
            )
            if expected != e.entry_hash:
                return False
            prev = e.entry_hash
        return True
