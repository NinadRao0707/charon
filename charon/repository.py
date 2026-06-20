"""Persistence layer.

A narrow Repository interface plus a stdlib-`sqlite3` implementation. Nothing in
the domain logic imports a database driver directly; everything goes through this
interface, so swapping in a Postgres/SQLAlchemy implementation later (design doc
Phase 7) is a localized change with no impact on the security code.
"""
from __future__ import annotations

import json
import sqlite3
from typing import Protocol

from .audit import AuditEntry
from .lifecycle import LifecycleState
from .models import Agent, RevokedCredential


class Repository(Protocol):
    # agents
    def add_agent(self, agent: Agent) -> None: ...
    def get_agent(self, agent_id: str) -> Agent | None: ...
    def update_agent(self, agent: Agent) -> None: ...
    def list_agents(self) -> list[Agent]: ...

    # audit
    def append_audit(self, entry: AuditEntry) -> None: ...
    def load_audit(self) -> list[AuditEntry]: ...

    # revocation
    def add_revocation(self, rev: RevokedCredential) -> None: ...
    def list_revocations(self) -> list[RevokedCredential]: ...


class SQLiteRepository:
    def __init__(self, path: str = ":memory:"):
        # check_same_thread=False keeps the in-memory DB usable from the test
        # harness; production Postgres would use a connection pool instead.
        self._conn = sqlite3.connect(path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._init_schema()

    def _init_schema(self) -> None:
        self._conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS agents (
                id          TEXT PRIMARY KEY,
                name        TEXT NOT NULL,
                owner       TEXT NOT NULL,
                purpose     TEXT NOT NULL,
                scopes      TEXT NOT NULL,
                parent_id   TEXT,
                spiffe_id   TEXT,
                state       TEXT NOT NULL,
                attested    INTEGER NOT NULL,
                created_at  REAL NOT NULL,
                last_seen   REAL
            );

            CREATE TABLE IF NOT EXISTS audit (
                seq        INTEGER PRIMARY KEY,
                timestamp  REAL NOT NULL,
                event      TEXT NOT NULL,
                subject    TEXT NOT NULL,
                details    TEXT NOT NULL,
                prev_hash  TEXT NOT NULL,
                entry_hash TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS revocations (
                jti        TEXT PRIMARY KEY,
                agent_id   TEXT NOT NULL,
                revoked_at REAL NOT NULL,
                expires_at REAL NOT NULL,
                reason     TEXT
            );
            """
        )
        self._conn.commit()

    # ---- agents -----------------------------------------------------------

    def add_agent(self, agent: Agent) -> None:
        self._conn.execute(
            """INSERT INTO agents
               (id, name, owner, purpose, scopes, parent_id, spiffe_id,
                state, attested, created_at, last_seen)
               VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
            (
                agent.id,
                agent.name,
                agent.owner,
                agent.purpose,
                json.dumps(agent.scopes),
                agent.parent_id,
                agent.spiffe_id,
                agent.state.value,
                int(agent.attested),
                agent.created_at,
                agent.last_seen,
            ),
        )
        self._conn.commit()

    def get_agent(self, agent_id: str) -> Agent | None:
        row = self._conn.execute(
            "SELECT * FROM agents WHERE id = ?", (agent_id,)
        ).fetchone()
        return self._row_to_agent(row) if row else None

    def update_agent(self, agent: Agent) -> None:
        self._conn.execute(
            """UPDATE agents SET name=?, owner=?, purpose=?, scopes=?, parent_id=?,
               spiffe_id=?, state=?, attested=?, last_seen=? WHERE id=?""",
            (
                agent.name,
                agent.owner,
                agent.purpose,
                json.dumps(agent.scopes),
                agent.parent_id,
                agent.spiffe_id,
                agent.state.value,
                int(agent.attested),
                agent.last_seen,
                agent.id,
            ),
        )
        self._conn.commit()

    def list_agents(self) -> list[Agent]:
        rows = self._conn.execute("SELECT * FROM agents ORDER BY created_at").fetchall()
        return [self._row_to_agent(r) for r in rows]

    @staticmethod
    def _row_to_agent(row: sqlite3.Row) -> Agent:
        return Agent(
            id=row["id"],
            name=row["name"],
            owner=row["owner"],
            purpose=row["purpose"],
            scopes=json.loads(row["scopes"]),
            parent_id=row["parent_id"],
            spiffe_id=row["spiffe_id"],
            state=LifecycleState(row["state"]),
            attested=bool(row["attested"]),
            created_at=row["created_at"],
            last_seen=row["last_seen"],
        )

    # ---- audit ------------------------------------------------------------

    def append_audit(self, entry: AuditEntry) -> None:
        r = entry.to_row()
        self._conn.execute(
            """INSERT INTO audit
               (seq, timestamp, event, subject, details, prev_hash, entry_hash)
               VALUES (?,?,?,?,?,?,?)""",
            (
                r["seq"],
                r["timestamp"],
                r["event"],
                r["subject"],
                r["details"],
                r["prev_hash"],
                r["entry_hash"],
            ),
        )
        self._conn.commit()

    def load_audit(self) -> list[AuditEntry]:
        rows = self._conn.execute("SELECT * FROM audit ORDER BY seq").fetchall()
        return [
            AuditEntry(
                seq=r["seq"],
                timestamp=r["timestamp"],
                event=r["event"],
                subject=r["subject"],
                details=json.loads(r["details"]),
                prev_hash=r["prev_hash"],
                entry_hash=r["entry_hash"],
            )
            for r in rows
        ]

    # ---- revocation -------------------------------------------------------

    def add_revocation(self, rev: RevokedCredential) -> None:
        self._conn.execute(
            """INSERT OR REPLACE INTO revocations
               (jti, agent_id, revoked_at, expires_at, reason) VALUES (?,?,?,?,?)""",
            (rev.jti, rev.agent_id, rev.revoked_at, rev.expires_at, rev.reason),
        )
        self._conn.commit()

    def list_revocations(self) -> list[RevokedCredential]:
        rows = self._conn.execute("SELECT * FROM revocations").fetchall()
        return [
            RevokedCredential(
                jti=r["jti"],
                agent_id=r["agent_id"],
                revoked_at=r["revoked_at"],
                expires_at=r["expires_at"],
                reason=r["reason"],
            )
            for r in rows
        ]
