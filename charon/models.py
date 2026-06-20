"""Domain models.

Plain dataclasses, deliberately independent of any ORM or web framework. The
repository layer is responsible for mapping these to and from storage, which
keeps the security logic free of database concerns and makes a future swap from
SQLite to Postgres a localized change.
"""
from __future__ import annotations

import time
import uuid
from dataclasses import dataclass, field

from .lifecycle import LifecycleState


def _now() -> float:
    return time.time()


def _new_id() -> str:
    return uuid.uuid4().hex


@dataclass
class Agent:
    """A non-human identity (AI agent, workload, or automated process)."""

    name: str
    owner: str  # the human accountable for this identity
    purpose: str
    scopes: list[str] = field(default_factory=list)
    parent_id: str | None = None  # set when this identity was delegated by another
    id: str = field(default_factory=_new_id)
    spiffe_id: str | None = None  # assigned at registration time
    state: LifecycleState = LifecycleState.PROVISIONED
    attested: bool = False
    # Verified attestation metadata (method, selectors, attested_at, expires_at).
    # Empty until the agent has successfully attested (Phase 3).
    attestation: dict = field(default_factory=dict)
    created_at: float = field(default_factory=_now)
    last_seen: float | None = None

    def touch(self) -> None:
        """Record activity; used by the reaper to detect idle identities."""
        self.last_seen = _now()

    def attestation_valid(self, now: float | None = None) -> bool:
        """True if the agent has a fresh (non-expired) attestation on record."""
        if not self.attested or not self.attestation:
            return False
        now = now if now is not None else _now()
        return float(self.attestation.get("expires_at", 0.0)) > now


@dataclass
class RevokedCredential:
    """An entry in the credential revocation list, keyed by JWT id (jti)."""

    jti: str
    agent_id: str
    revoked_at: float = field(default_factory=_now)
    expires_at: float = 0.0  # original token exp; lets us prune the list safely
    reason: str | None = None
