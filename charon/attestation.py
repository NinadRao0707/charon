"""Phase 3 — Attestation.

Before Charon issues a credential, the workload must prove it is what it claims
to be. This is the "secret zero" / bottom-turtle problem: if you hand out a
credential to anything that asks, the credential is worthless. Attestation is
the root of trust that everything else hangs from.

This module provides a small pluggable framework plus three attestors:

  * ``JoinTokenAttestor``    — the control plane mints a single-use, expiring
                               token out-of-band; the workload presents it once.
                               Fully self-contained (mirrors SPIRE's join_token
                               node attestor).
  * ``K8sServiceAccountAttestor`` — verifies a projected Kubernetes
                               ServiceAccount JWT against the cluster's public
                               keys (JWKS), checking issuer, audience and
                               expiry, and extracting namespace / SA selectors.
  * ``DevAttestor``          — an explicitly-named INSECURE attestor for local
                               development. It always succeeds, but it records
                               ``method="dev-insecure"`` so the audit log makes
                               clear no real evidence was checked.

An attestor returns an ``AttestationResult`` carrying *selectors* — verified
facts about the workload (e.g. its k8s namespace and service account). These can
later be required to match the agent's expected identity, so a credential for
``ns=payments/sa=charger`` cannot be obtained by a workload attesting as
``ns=marketing/sa=mailer``.
"""
from __future__ import annotations

import secrets
import time
from dataclasses import dataclass, field
from typing import Protocol

import jwt

DEFAULT_ATTESTATION_TTL = 3600  # re-attest hourly by default


class AttestationError(Exception):
    """Raised when evidence cannot be verified."""


@dataclass
class AttestationResult:
    method: str
    selectors: dict[str, str] = field(default_factory=dict)
    attested_at: float = field(default_factory=time.time)
    expires_at: float = 0.0

    def is_valid(self, now: float | None = None) -> bool:
        now = now if now is not None else time.time()
        return self.expires_at > now

    def to_dict(self) -> dict:
        return {
            "method": self.method,
            "selectors": self.selectors,
            "attested_at": self.attested_at,
            "expires_at": self.expires_at,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "AttestationResult":
        return cls(
            method=d["method"],
            selectors=d.get("selectors", {}),
            attested_at=d.get("attested_at", 0.0),
            expires_at=d.get("expires_at", 0.0),
        )


class Attestor(Protocol):
    name: str

    def attest(self, evidence) -> AttestationResult: ...


class DevAttestor:
    """INSECURE: accepts anything. For local development only."""

    name = "dev-insecure"

    def __init__(self, ttl: int = DEFAULT_ATTESTATION_TTL):
        self._ttl = ttl

    def attest(self, evidence=None) -> AttestationResult:
        now = time.time()
        return AttestationResult(
            method=self.name,
            selectors={"note": "no evidence verified"},
            attested_at=now,
            expires_at=now + self._ttl,
        )


class JoinTokenAttestor:
    """Single-use, expiring join tokens minted by the control plane.

    Workflow: an operator (or the registration step) calls ``mint()`` to get a
    one-time token, delivers it to the workload out-of-band, and the workload
    presents it to ``attest()``. The token is consumed on first use and cannot
    be replayed.
    """

    name = "join-token"

    def __init__(self, ttl: int = 600, attestation_ttl: int = DEFAULT_ATTESTATION_TTL):
        self._ttl = ttl
        self._attestation_ttl = attestation_ttl
        # token -> (expires_at, selectors)
        self._outstanding: dict[str, tuple[float, dict[str, str]]] = {}

    def mint(self, selectors: dict[str, str] | None = None) -> str:
        token = secrets.token_urlsafe(32)
        self._outstanding[token] = (time.time() + self._ttl, selectors or {})
        return token

    def attest(self, evidence: str) -> AttestationResult:
        entry = self._outstanding.pop(evidence, None)  # single-use: pop on read
        if entry is None:
            raise AttestationError("unknown or already-used join token")
        expires_at, selectors = entry
        if time.time() > expires_at:
            raise AttestationError("join token expired")
        now = time.time()
        return AttestationResult(
            method=self.name,
            selectors=selectors,
            attested_at=now,
            expires_at=now + self._attestation_ttl,
        )


class K8sServiceAccountAttestor:
    """Verifies a Kubernetes projected ServiceAccount JWT.

    In a real cluster the workload mounts a projected SA token and presents it
    here. We verify the signature against the cluster's JWKS public keys, check
    the issuer and audience, and extract the namespace / service-account name as
    selectors. (The JWKS is normally fetched from the API server's
    ``/.well-known/openid-configuration``; here it is supplied at construction so
    the attestor is testable without a live cluster.)
    """

    name = "k8s-sa"

    def __init__(
        self,
        public_keys_pem: dict[str, bytes],
        issuer: str,
        audience: str,
        algorithms: list[str] | None = None,
        attestation_ttl: int = DEFAULT_ATTESTATION_TTL,
    ):
        self._keys = public_keys_pem  # kid -> PEM
        self._issuer = issuer
        self._audience = audience
        self._algorithms = algorithms or ["RS256", "ES256", "EdDSA"]
        self._attestation_ttl = attestation_ttl

    def attest(self, evidence: str) -> AttestationResult:
        try:
            header = jwt.get_unverified_header(evidence)
        except jwt.PyJWTError as exc:
            raise AttestationError(f"malformed SA token: {exc}") from exc

        kid = header.get("kid")
        pem = self._keys.get(kid) if kid else None
        # If a single unkeyed cluster key is configured, fall back to it.
        if pem is None and len(self._keys) == 1:
            pem = next(iter(self._keys.values()))
        if pem is None:
            raise AttestationError(f"no cluster key for kid={kid!r}")

        try:
            claims = jwt.decode(
                evidence,
                pem,
                algorithms=self._algorithms,
                audience=self._audience,
                issuer=self._issuer,
            )
        except jwt.PyJWTError as exc:
            raise AttestationError(f"SA token verification failed: {exc}") from exc

        # Kubernetes encodes SA identity under this claim namespace.
        k8s = claims.get("kubernetes.io", {})
        namespace = k8s.get("namespace", "")
        sa = (k8s.get("serviceaccount") or {}).get("name", "")
        if not namespace or not sa:
            # Fall back to parsing the conventional sub:
            # system:serviceaccount:<ns>:<sa>
            parts = claims.get("sub", "").split(":")
            if len(parts) == 4 and parts[0:2] == ["system", "serviceaccount"]:
                namespace, sa = parts[2], parts[3]
        now = time.time()
        return AttestationResult(
            method=self.name,
            selectors={"k8s_namespace": namespace, "k8s_serviceaccount": sa},
            attested_at=now,
            expires_at=now + self._attestation_ttl,
        )
