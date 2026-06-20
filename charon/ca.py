"""The signing authority for JWT-SVIDs.

Charon issues SPIFFE JWT-SVIDs signed with an Ed25519 key (EdDSA). In a real
deployment this responsibility moves to SPIRE (see the design doc, Phase 7); for
Phases 2-6 we run a self-contained authority so the system works end-to-end with
no external dependencies.

The public half is exposed as a minimal "trust bundle" (JWKS-like) keyed by
`kid`, which the gateway and any verifier use to validate tokens. Key rotation
is supported by adding a new active key while keeping old public keys in the
bundle until their tokens expire.
"""
from __future__ import annotations

import base64
import hashlib

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)


def _kid_for(public_key: Ed25519PublicKey) -> str:
    raw = public_key.public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    return base64.urlsafe_b64encode(hashlib.sha256(raw).digest()[:12]).decode().rstrip("=")


class SigningKey:
    def __init__(self, private_key: Ed25519PrivateKey):
        self._private_key = private_key
        self.public_key = private_key.public_key()
        self.kid = _kid_for(self.public_key)

    @classmethod
    def generate(cls) -> "SigningKey":
        return cls(Ed25519PrivateKey.generate())

    @property
    def private_pem(self) -> bytes:
        return self._private_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )

    @property
    def public_pem(self) -> bytes:
        return self.public_key.public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )


class CertificateAuthority:
    """Holds the active signing key plus retired public keys for verification."""

    def __init__(self, active: SigningKey | None = None):
        self._active = active or SigningKey.generate()
        # kid -> public PEM, including the active key and any rotated-out keys.
        self._bundle: dict[str, bytes] = {self._active.kid: self._active.public_pem}

    @property
    def active(self) -> SigningKey:
        return self._active

    def rotate(self) -> SigningKey:
        """Generate a new active signing key, retaining the old public key in the
        trust bundle so already-issued tokens remain verifiable until they expire."""
        new_key = SigningKey.generate()
        self._bundle[new_key.kid] = new_key.public_pem
        self._active = new_key
        return new_key

    def public_pem_for(self, kid: str) -> bytes | None:
        return self._bundle.get(kid)

    def trust_bundle(self) -> dict[str, str]:
        """Return {kid: public_pem_str} — the set of keys a verifier should trust."""
        return {kid: pem.decode() for kid, pem in self._bundle.items()}
