"""The Credential Authority — Phase 2 core.

Issues short-lived SPIFFE JWT-SVIDs in place of static API keys. A JWT-SVID is a
JWT whose `sub` is a SPIFFE ID; we add a `scope` claim carrying the agent's
granted capabilities and a unique `jti` so individual credentials can be revoked.

Key properties this enforces:
  * short TTL (default 5 minutes) — limits blast radius and kills "zombie" creds
  * issuance is gated on lifecycle state and attestation (no secret-zero handout)
  * a revocation list keyed by `jti` is checked on every verification
  * rotation issues a fresh credential and revokes the prior one
"""
from __future__ import annotations

import time

import jwt

from . import spiffe
from .ca import CertificateAuthority
from .lifecycle import LifecycleState
from .models import Agent, RevokedCredential

DEFAULT_TTL_SECONDS = 300
_ALG = "EdDSA"


class CredentialError(Exception):
    pass


class NotIssuable(CredentialError):
    """Raised when an agent is in a state that forbids credential issuance."""


class CredentialRevoked(CredentialError):
    pass


class CredentialExpired(CredentialError):
    pass


class InvalidCredential(CredentialError):
    pass


class CredentialAuthority:
    def __init__(
        self,
        ca: CertificateAuthority,
        trust_domain: str,
        audience: str = "charon-gateway",
        ttl_seconds: int = DEFAULT_TTL_SECONDS,
    ):
        self._ca = ca
        self._trust_domain = trust_domain
        self._audience = audience
        self._ttl = ttl_seconds
        # jti -> RevokedCredential
        self._revoked: dict[str, RevokedCredential] = {}

    # ---- accessors (reused by the delegation authority) -------------------

    @property
    def audience(self) -> str:
        return self._audience

    @property
    def trust_domain(self) -> str:
        return self._trust_domain

    @property
    def ttl(self) -> int:
        return self._ttl

    def sign_claims(self, claims: dict) -> str:
        """Sign an arbitrary claim set with the active key (used for RFC 8693
        token exchange). Temporal/jti claims are filled in if absent."""
        now = int(time.time())
        claims.setdefault("iat", now)
        claims.setdefault("nbf", now)
        claims.setdefault("exp", now + self._ttl)
        claims.setdefault("aud", self._audience)
        return jwt.encode(
            claims,
            self._ca.active.private_pem,
            algorithm=_ALG,
            headers={"kid": self._ca.active.kid},
        )

    # ---- issuance ---------------------------------------------------------

    def issue(self, agent: Agent, dpop_jkt: str | None = None) -> str:
        """Mint a short-lived JWT-SVID for an agent.

        Issuance is only permitted for PROVISIONED (first credential) or ACTIVE
        identities, and only if the agent has been attested. This is what stops
        Charon from handing credentials to an unverified workload.

        If ``dpop_jkt`` is given, the credential is bound to that key via a
        ``cnf`` claim (RFC 9449), so it can only be used by a client that proves
        possession of the matching private key.
        """
        if agent.state not in (LifecycleState.PROVISIONED, LifecycleState.ACTIVE):
            raise NotIssuable(
                f"cannot issue credential for agent in state {agent.state.value}"
            )
        if not agent.attested:
            raise NotIssuable("cannot issue credential for an un-attested agent")

        spiffe_id = agent.spiffe_id or str(
            spiffe.for_agent(self._trust_domain, agent.id)
        )
        now = int(time.time())
        jti = f"{agent.id}-{now}-{self._ca.active.kid[:6]}"
        claims = {
            "sub": spiffe_id,
            "aud": self._audience,
            "iat": now,
            "nbf": now,
            "exp": now + self._ttl,
            "jti": jti,
            "scope": " ".join(sorted(agent.scopes)),
        }
        if dpop_jkt:
            claims["cnf"] = {"jkt": dpop_jkt}
        token = jwt.encode(
            claims,
            self._ca.active.private_pem,
            algorithm=_ALG,
            headers={"kid": self._ca.active.kid},
        )
        return token

    # ---- verification -----------------------------------------------------

    def verify(self, token: str) -> dict:
        """Validate a JWT-SVID and return its claims, or raise.

        Checks signature against the trust bundle (by `kid`), standard temporal
        claims, audience, and the revocation list.
        """
        try:
            header = jwt.get_unverified_header(token)
        except jwt.PyJWTError as exc:
            raise InvalidCredential(f"malformed token: {exc}") from exc

        kid = header.get("kid")
        public_pem = self._ca.public_pem_for(kid) if kid else None
        if public_pem is None:
            raise InvalidCredential(f"unknown signing key kid={kid!r}")

        try:
            claims = jwt.decode(
                token,
                public_pem,
                algorithms=[_ALG],
                audience=self._audience,
            )
        except jwt.ExpiredSignatureError as exc:
            raise CredentialExpired("credential has expired") from exc
        except jwt.PyJWTError as exc:
            raise InvalidCredential(f"invalid token: {exc}") from exc

        jti = claims.get("jti")
        if jti in self._revoked:
            raise CredentialRevoked(f"credential {jti} is revoked")
        return claims

    # ---- rotation & revocation -------------------------------------------

    def rotate(self, agent: Agent, previous_token: str | None = None) -> str:
        """Issue a fresh credential and revoke the previous one if supplied."""
        if previous_token is not None:
            try:
                prev_claims = jwt.decode(
                    previous_token, options={"verify_signature": False}
                )
                self._revoke_jti(
                    prev_claims.get("jti", ""),
                    agent.id,
                    int(prev_claims.get("exp", 0)),
                    reason="rotated",
                )
            except jwt.PyJWTError:
                pass  # an unparseable previous token simply isn't revoked
        return self.issue(agent)

    def revoke(self, token: str, reason: str | None = None) -> None:
        """Add a credential's jti to the revocation list."""
        claims = jwt.decode(token, options={"verify_signature": False})
        self._revoke_jti(
            claims.get("jti", ""),
            claims.get("sub", ""),
            int(claims.get("exp", 0)),
            reason=reason,
        )

    def _revoke_jti(
        self, jti: str, agent_id: str, expires_at: int, reason: str | None
    ) -> None:
        if not jti:
            return
        self._revoked[jti] = RevokedCredential(
            jti=jti, agent_id=agent_id, expires_at=expires_at, reason=reason
        )

    def is_revoked(self, jti: str) -> bool:
        return jti in self._revoked

    def prune_revocation_list(self, now: float | None = None) -> int:
        """Drop revocation entries whose tokens have already expired (they can no
        longer be accepted anyway). Returns the number pruned."""
        now = now if now is not None else time.time()
        stale = [jti for jti, r in self._revoked.items() if r.expires_at <= now]
        for jti in stale:
            del self._revoked[jti]
        return len(stale)
