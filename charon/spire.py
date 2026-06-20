"""Phase 7 — SPIRE integration (the production swap for the self-signed CA).

For Phases 2-6 Charon mints and signs its own JWT-SVIDs with a local Ed25519 key
(``charon.ca.CertificateAuthority``). That single key is a single point of trust.
In production the right answer is to let **SPIRE** be the identity provider: each
workload obtains a JWT-SVID from its local SPIRE agent via the Workload API, and
Charon's gateway verifies those SVIDs against the SPIRE trust bundle. Charon then
focuses on what it adds *on top* of SPIRE — lifecycle, per-tool authorization,
delegation, and the reaper.

This module provides two adapters built on the official ``spiffe`` (py-spiffe)
SDK:

  * ``SpireJwtSource``    — workload side: fetch a JWT-SVID for an audience.
  * ``SpireJwtVerifier``  — gateway side: validate a JWT-SVID against the SPIRE
                            JWT bundle. It is callable and raises
                            ``charon.credentials.CredentialError`` on failure, so
                            it drops straight into the gateway's verifier seam:

        from charon.spire import SpireJwtVerifier
        verifier = SpireJwtVerifier(audience="charon-gateway")
        gateway = MCPGateway(registry, servers, credential_verifier=verifier)

Requires a running SPIRE server + agent and ``pip install spiffe``. The import is
guarded so the rest of Charon runs without SPIRE installed.
"""
from __future__ import annotations

from charon.credentials import CredentialError

try:  # pragma: no cover - exercised only in a real SPIRE deployment
    from spiffe import JwtSvid, WorkloadApiClient

    _SPIFFE_AVAILABLE = True
except ImportError:  # pragma: no cover
    _SPIFFE_AVAILABLE = False


def _require_spiffe() -> None:
    if not _SPIFFE_AVAILABLE:
        raise RuntimeError(
            "SPIRE integration requires the 'spiffe' package: pip install spiffe"
        )


class SpireJwtSource:
    """Workload-side helper: fetch a JWT-SVID from the local SPIRE agent.

    ``socket_path`` defaults to the SPIFFE_ENDPOINT_SOCKET environment variable.
    """

    def __init__(self, audience: str, socket_path: str | None = None):
        _require_spiffe()
        self._audience = audience
        self._client = WorkloadApiClient(socket_path) if socket_path else WorkloadApiClient()

    def fetch_token(self) -> str:
        svid = self._client.fetch_jwt_svid(audiences={self._audience})
        return svid.token

    def close(self) -> None:
        self._client.close()


class SpireJwtVerifier:
    """Gateway-side verifier. Callable: ``verifier(token) -> claims``.

    Validates the JWT-SVID signature against the SPIRE JWT bundle and the
    expected audience, then returns a claims dict shaped like the local
    authority's output (``sub``, ``scope``, ``cnf``, ...). DPoP enforcement in
    the gateway is unchanged: it reads ``cnf.jkt`` from these claims.
    """

    def __init__(self, audience: str, socket_path: str | None = None):
        _require_spiffe()
        self._audience = audience
        self._client = WorkloadApiClient(socket_path) if socket_path else WorkloadApiClient()

    def __call__(self, token: str) -> dict:
        try:
            bundle_set = self._client.fetch_jwt_bundles()
            svid = JwtSvid.parse_and_validate(
                token, bundle_set, audience={self._audience}
            )
        except Exception as exc:  # normalize to Charon's error type for the seam
            raise CredentialError(f"SPIRE JWT-SVID validation failed: {exc}") from exc
        claims = dict(svid.claims)
        claims.setdefault("sub", str(svid.spiffe_id))
        return claims

    def close(self) -> None:
        self._client.close()
