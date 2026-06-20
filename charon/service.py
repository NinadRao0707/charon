"""The Registry service — the orchestration layer that ties Phases 1 and 2
together.

It is the single entry point for: registering an identity, attesting it,
performing *gated* lifecycle transitions, recording activity, and issuing /
rotating / revoking credentials. Every state-changing operation is written to
the hash-chained audit log.
"""
from __future__ import annotations

from . import spiffe
from .audit import AuditLog
from .credentials import CredentialAuthority
from .lifecycle import (
    LifecycleState,
    TransitionContext,
    check_transition,
)
from .models import Agent, RevokedCredential
from .repository import Repository


class RegistryError(Exception):
    pass


class UnknownAgent(RegistryError):
    pass


class Registry:
    def __init__(
        self,
        repo: Repository,
        credential_authority: CredentialAuthority,
        trust_domain: str,
    ):
        self._repo = repo
        self._ca = credential_authority
        self._trust_domain = trust_domain
        # Rehydrate the audit chain from storage so head_hash stays correct
        # across restarts.
        self._audit = AuditLog()
        for entry in repo.load_audit():
            # Re-append by replaying; we trust persisted entries but verify below.
            self._audit._entries.append(entry)  # noqa: SLF001 (intentional rehydrate)
        if not self._audit.verify():
            raise RegistryError("audit log failed integrity check on load")

    # ---- registration -----------------------------------------------------

    def register(
        self,
        name: str,
        owner: str,
        purpose: str,
        scopes: list[str] | None = None,
        parent_id: str | None = None,
    ) -> Agent:
        agent = Agent(
            name=name,
            owner=owner,
            purpose=purpose,
            scopes=scopes or [],
            parent_id=parent_id,
        )
        agent.spiffe_id = str(spiffe.for_agent(self._trust_domain, agent.id))
        self._repo.add_agent(agent)
        self._record("agent.registered", agent.id, {"name": name, "owner": owner})
        return agent

    def get(self, agent_id: str) -> Agent:
        agent = self._repo.get_agent(agent_id)
        if agent is None:
            raise UnknownAgent(agent_id)
        return agent

    def list(self) -> list[Agent]:
        return self._repo.list_agents()

    # ---- attestation -------------------------------------------------------

    def attest(self, agent_id: str, method: str = "join-token") -> Agent:
        """Mark an agent as attested.

        In a real system this verifies an attestation document (k8s SA token, a
        one-time join token, TPM quote, etc.). Here we record the method and set
        the flag; issuance and activation are gated on it.
        """
        agent = self.get(agent_id)
        agent.attested = True
        self._repo.update_agent(agent)
        self._record("agent.attested", agent.id, {"method": method})
        return agent

    # ---- gated lifecycle transitions --------------------------------------

    def transition(
        self, agent_id: str, target: LifecycleState, reason: str | None = None
    ) -> Agent:
        agent = self.get(agent_id)
        ctx = TransitionContext(attested=agent.attested, reason=reason)
        # Raises IllegalTransition / TransitionGuardFailed on violation.
        check_transition(agent.state, target, ctx)
        previous = agent.state
        agent.state = target
        self._repo.update_agent(agent)
        self._record(
            "agent.transition",
            agent.id,
            {"from": previous.value, "to": target.value, "reason": reason},
        )
        return agent

    def record_activity(self, agent_id: str) -> Agent:
        agent = self.get(agent_id)
        agent.touch()
        self._repo.update_agent(agent)
        return agent

    # ---- credentials -------------------------------------------------------

    def issue_credential(self, agent_id: str) -> str:
        agent = self.get(agent_id)
        token = self._ca.issue(agent)
        # First credential activates a freshly provisioned (attested) agent.
        if agent.state == LifecycleState.PROVISIONED:
            self.transition(agent_id, LifecycleState.ACTIVE, reason="first-credential")
        self._record("credential.issued", agent.id, {"ttl": self._ca._ttl})  # noqa: SLF001
        return token

    def rotate_credential(self, agent_id: str, previous_token: str | None = None) -> str:
        agent = self.get(agent_id)
        token = self._ca.rotate(agent, previous_token)
        self._record("credential.rotated", agent.id, {})
        return token

    def revoke_credential(
        self, agent_id: str, token: str, reason: str | None = None
    ) -> None:
        self._ca.revoke(token, reason=reason)
        # Persist the revocation so it survives restarts.
        import jwt as _jwt

        claims = _jwt.decode(token, options={"verify_signature": False})
        self._repo.add_revocation(
            RevokedCredential(
                jti=claims.get("jti", ""),
                agent_id=agent_id,
                expires_at=int(claims.get("exp", 0)),
                reason=reason,
            )
        )
        self._record("credential.revoked", agent_id, {"reason": reason})

    def verify_credential(self, token: str) -> dict:
        return self._ca.verify(token)

    # ---- audit -------------------------------------------------------------

    def audit_entries(self):
        return self._audit.entries()

    def audit_ok(self) -> bool:
        return self._audit.verify()

    def _record(self, event: str, subject: str, details: dict) -> None:
        entry = self._audit.append(event, subject, details)
        self._repo.append_audit(entry)
