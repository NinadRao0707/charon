"""Phase 5 — Delegation & provenance (RFC 8693 OAuth 2.0 Token Exchange).

When one agent hands work to another, the resulting credential must answer two
questions at any later point: *on whose behalf is this action ultimately taken?*
and *through which chain of agents did the authority flow?* RFC 8693 answers both
with two claims:

  * ``sub`` — the originating principal (the human). It does **not** change as the
    work is delegated down a chain; it always names the party on whose behalf the
    action is performed.
  * ``act`` — the *actor* claim, a JSON object naming the current immediate actor.
    A delegation chain is expressed by nesting: the outermost ``act`` is the most
    recent actor, and each nested ``act`` is the actor that delegated to it. Per
    the RFC, "the least recent actor is the most deeply nested."

So for ``human -> A -> B -> C`` (C currently acting), the token C presents is:

    { "sub": "user:alice",
      "act": { "sub": "<C>", "act": { "sub": "<B>", "act": { "sub": "<A>" } } } }

``trace()`` walks that structure to reconstruct the full path back to the human.

Least privilege is enforced on every hop: the scope of a delegated token can only
ever be a subset of the scope it was derived from — authority narrows as it flows
down the chain, never widens.
"""
from __future__ import annotations

from dataclasses import dataclass

from .credentials import CredentialAuthority, CredentialError

TOKEN_EXCHANGE_GRANT = "urn:ietf:params:oauth:grant-type:token-exchange"
JWT_TOKEN_TYPE = "urn:ietf:params:oauth:token-type:jwt"


class DelegationError(Exception):
    pass


@dataclass
class Provenance:
    """The reconstructed authority path for an action."""

    principal: str  # the originating human (sub)
    actors: list[str]  # ordered first-delegate ... current-actor

    @property
    def path(self) -> list[str]:
        return [self.principal, *self.actors]

    def __str__(self) -> str:
        return " -> ".join(self.path)


class DelegationAuthority:
    """Implements the token-exchange grant on top of the Credential Authority."""

    def __init__(self, credential_authority: CredentialAuthority):
        self._ca = credential_authority

    # ---- starting a chain: human -> first agent (OBO) ---------------------

    def begin_on_behalf_of(
        self,
        human_principal: str,
        actor_token: str,
        scope: list[str],
    ) -> str:
        """Mint the first on-behalf-of token: an agent acting for a human.

        ``actor_token`` is the acting agent's own verified JWT-SVID. The new
        token names the human as ``sub`` and the agent as the (sole) actor. The
        requested scope must be within the agent's own granted scope.
        """
        actor_claims = self._verify(actor_token, "actor")
        actor_scopes = set(actor_claims.get("scope", "").split())
        granted = self._downscope(set(scope), actor_scopes, "actor")
        return self._ca.sign_claims(
            {
                "sub": human_principal,
                "scope": " ".join(sorted(granted)),
                "act": {"sub": actor_claims["sub"]},
            }
        )

    # ---- continuing a chain: agent -> agent (RFC 8693) --------------------

    def exchange(
        self,
        subject_token: str,
        actor_token: str,
        scope: list[str] | None = None,
    ) -> str:
        """RFC 8693 token exchange for hop N>1.

        ``subject_token`` is the inbound delegated credential (carrying the
        principal + existing act chain); ``actor_token`` is the next agent's own
        credential. Returns a new token preserving ``sub`` and nesting the prior
        act chain beneath the new actor. Requested scope must be a subset of the
        subject token's scope (authority only narrows).
        """
        subject_claims = self._verify(subject_token, "subject")
        actor_claims = self._verify(actor_token, "actor")

        subject_scopes = set(subject_claims.get("scope", "").split())
        requested = set(scope) if scope is not None else subject_scopes
        granted = self._downscope(requested, subject_scopes, "subject")

        new_act = {"sub": actor_claims["sub"]}
        if "act" in subject_claims:  # nest the prior chain beneath the new actor
            new_act["act"] = subject_claims["act"]

        return self._ca.sign_claims(
            {
                "sub": subject_claims["sub"],
                "scope": " ".join(sorted(granted)),
                "act": new_act,
            }
        )

    # ---- provenance -------------------------------------------------------

    @staticmethod
    def trace(claims: dict) -> Provenance:
        """Reconstruct the authority path from a token's claims.

        Returns principal (sub) plus actors ordered first-delegate -> current.
        """
        principal = claims.get("sub", "unknown")
        actors_recent_first: list[str] = []
        act = claims.get("act")
        while isinstance(act, dict):
            if "sub" in act:
                actors_recent_first.append(act["sub"])
            act = act.get("act")
        # outermost == most recent; reverse so the list reads first -> current
        return Provenance(principal=principal, actors=list(reversed(actors_recent_first)))

    # ---- helpers ----------------------------------------------------------

    def _verify(self, token: str, role: str) -> dict:
        try:
            return self._ca.verify(token)
        except CredentialError as exc:
            raise DelegationError(f"invalid {role} token: {exc}") from exc

    @staticmethod
    def _downscope(requested: set[str], allowed: set[str], source: str) -> set[str]:
        excess = requested - allowed
        if excess:
            raise DelegationError(
                f"requested scope {sorted(excess)} exceeds {source} scope "
                f"{sorted(allowed)} (delegated authority may only narrow)"
            )
        return requested
