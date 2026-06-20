"""Phase 7 — DPoP proof-of-possession (RFC 9449).

Plain bearer tokens have a fatal weakness: anyone who steals one can use it. DPoP
(Demonstrating Proof-of-Possession) binds a credential to a key the legitimate
client holds. At issuance, the credential carries a ``cnf`` (confirmation) claim
with ``jkt`` — the SHA-256 thumbprint (RFC 7638) of the client's public key. On
every request the client must attach a fresh **DPoP proof**: a short JWT signed
by its private key, naming the HTTP method (``htm``) and URL (``htu``) and a
unique ``jti``. The server checks that the proof is signed by the key whose
thumbprint matches the token's ``cnf.jkt``.

Result: a stolen access token is useless without the matching private key, and a
captured proof cannot be replayed (the ``jti`` is single-use and the proof is
bound to one method+URL with a short freshness window).

Keys are EC P-256 / ES256, the conventional DPoP algorithm.
"""
from __future__ import annotations

import base64
import hashlib
import json
import secrets
import time

import jwt
from cryptography.hazmat.primitives.asymmetric.ec import (
    SECP256R1,
    EllipticCurvePublicNumbers,
    generate_private_key,
)

_ALG = "ES256"
_TYP = "dpop+jwt"


class DpopError(Exception):
    pass


def _b64u(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode().rstrip("=")


def _b64u_decode(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def jwk_thumbprint(jwk: dict) -> str:
    """RFC 7638 JWK thumbprint over the canonical required members."""
    canonical = json.dumps(
        {"crv": jwk["crv"], "kty": jwk["kty"], "x": jwk["x"], "y": jwk["y"]},
        separators=(",", ":"),
        sort_keys=True,
    )
    return _b64u(hashlib.sha256(canonical.encode()).digest())


class DpopKey:
    """Client-side DPoP key. The holder of this proves possession."""

    def __init__(self, private_key=None):
        self._sk = private_key or generate_private_key(SECP256R1())

    def public_jwk(self) -> dict:
        nums = self._sk.public_key().public_numbers()
        return {
            "kty": "EC",
            "crv": "P-256",
            "x": _b64u(nums.x.to_bytes(32, "big")),
            "y": _b64u(nums.y.to_bytes(32, "big")),
        }

    def thumbprint(self) -> str:
        return jwk_thumbprint(self.public_jwk())

    def proof(self, htm: str, htu: str) -> str:
        """Create a DPoP proof JWT bound to one HTTP method + URL."""
        now = int(time.time())
        return jwt.encode(
            {"jti": secrets.token_urlsafe(16), "htm": htm.upper(), "htu": htu, "iat": now},
            self._sk,
            algorithm=_ALG,
            headers={"typ": _TYP, "jwk": self.public_jwk()},
        )


class ReplayCache:
    """Single-use jti store with TTL-based pruning."""

    def __init__(self, ttl: int = 120):
        self._ttl = ttl
        self._seen: dict[str, float] = {}

    def check_and_add(self, jti: str, now: float) -> bool:
        self._prune(now)
        if jti in self._seen:
            return False
        self._seen[jti] = now + self._ttl
        return True

    def _prune(self, now: float) -> None:
        for k in [k for k, exp in self._seen.items() if exp <= now]:
            del self._seen[k]


def verify_proof(
    proof: str,
    htm: str,
    htu: str,
    expected_jkt: str,
    replay_cache: ReplayCache,
    max_age: int = 60,
    now: float | None = None,
) -> dict:
    """Verify a DPoP proof against the thumbprint bound to the access token.

    Raises DpopError on any failure (bad signature, key/thumbprint mismatch,
    method/URL mismatch, stale proof, or replay).
    """
    now = now if now is not None else time.time()
    try:
        header = jwt.get_unverified_header(proof)
    except jwt.PyJWTError as exc:
        raise DpopError(f"malformed proof: {exc}") from exc

    if header.get("typ") != _TYP:
        raise DpopError("proof has wrong typ")
    jwk = header.get("jwk")
    if not jwk:
        raise DpopError("proof missing embedded jwk")

    # The proof must be signed by the key bound to the token (cnf.jkt).
    if jwk_thumbprint(jwk) != expected_jkt:
        raise DpopError("proof key does not match the token's bound key (cnf.jkt)")

    public_key = _public_key_from_jwk(jwk)
    try:
        claims = jwt.decode(proof, public_key, algorithms=[_ALG])
    except jwt.PyJWTError as exc:
        raise DpopError(f"proof signature invalid: {exc}") from exc

    if claims.get("htm", "").upper() != htm.upper():
        raise DpopError("proof htm does not match request method")
    if claims.get("htu") != htu:
        raise DpopError("proof htu does not match request URL")
    iat = claims.get("iat", 0)
    if abs(now - iat) > max_age:
        raise DpopError("proof is stale")
    if not replay_cache.check_and_add(claims.get("jti", ""), now):
        raise DpopError("proof replay detected")
    return claims


def _public_key_from_jwk(jwk: dict):
    if jwk.get("kty") != "EC" or jwk.get("crv") != "P-256":
        raise DpopError("unsupported DPoP key type")
    x = int.from_bytes(_b64u_decode(jwk["x"]), "big")
    y = int.from_bytes(_b64u_decode(jwk["y"]), "big")
    return EllipticCurvePublicNumbers(x, y, SECP256R1()).public_key()
