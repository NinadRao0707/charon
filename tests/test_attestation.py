import time
import unittest

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from charon.attestation import (
    AttestationError,
    DevAttestor,
    JoinTokenAttestor,
    K8sServiceAccountAttestor,
)
from charon.ca import CertificateAuthority
from charon.credentials import CredentialAuthority, NotIssuable
from charon.repository import SQLiteRepository
from charon.service import Registry

TRUST_DOMAIN = "charon.test"


def _registry():
    repo = SQLiteRepository(":memory:")
    ca = CertificateAuthority()
    return Registry(repo, CredentialAuthority(ca, TRUST_DOMAIN), TRUST_DOMAIN)


def _make_cluster():
    sk = Ed25519PrivateKey.generate()
    pub_pem = sk.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    priv_pem = sk.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    return priv_pem, pub_pem


def _sa_token(priv_pem, *, iss, aud, ns, sa, kid="cluster-key", exp_in=300):
    now = int(time.time())
    return jwt.encode(
        {
            "iss": iss,
            "aud": aud,
            "sub": f"system:serviceaccount:{ns}:{sa}",
            "iat": now,
            "exp": now + exp_in,
            "kubernetes.io": {"namespace": ns, "serviceaccount": {"name": sa}},
        },
        priv_pem,
        algorithm="EdDSA",
        headers={"kid": kid},
    )


class JoinTokenTests(unittest.TestCase):
    def test_mint_then_attest(self):
        att = JoinTokenAttestor()
        token = att.mint(selectors={"team": "payments"})
        result = att.attest(token)
        self.assertEqual(result.method, "join-token")
        self.assertEqual(result.selectors["team"], "payments")
        self.assertTrue(result.is_valid())

    def test_single_use(self):
        att = JoinTokenAttestor()
        token = att.mint()
        att.attest(token)
        with self.assertRaises(AttestationError):
            att.attest(token)  # replay rejected

    def test_unknown_token(self):
        with self.assertRaises(AttestationError):
            JoinTokenAttestor().attest("not-a-real-token")

    def test_expired_token(self):
        att = JoinTokenAttestor(ttl=1)
        token = att.mint()
        time.sleep(2)
        with self.assertRaises(AttestationError):
            att.attest(token)


class K8sAttestorTests(unittest.TestCase):
    def setUp(self):
        self.priv, self.pub = _make_cluster()
        self.att = K8sServiceAccountAttestor(
            public_keys_pem={"cluster-key": self.pub},
            issuer="https://kubernetes.default.svc",
            audience="charon",
        )

    def test_valid_token_extracts_selectors(self):
        token = _sa_token(
            self.priv,
            iss="https://kubernetes.default.svc",
            aud="charon",
            ns="payments",
            sa="charger",
        )
        result = self.att.attest(token)
        self.assertEqual(result.selectors["k8s_namespace"], "payments")
        self.assertEqual(result.selectors["k8s_serviceaccount"], "charger")

    def test_wrong_audience_rejected(self):
        token = _sa_token(
            self.priv,
            iss="https://kubernetes.default.svc",
            aud="some-other-service",
            ns="payments",
            sa="charger",
        )
        with self.assertRaises(AttestationError):
            self.att.attest(token)

    def test_wrong_issuer_rejected(self):
        token = _sa_token(
            self.priv, iss="https://evil.example", aud="charon", ns="x", sa="y"
        )
        with self.assertRaises(AttestationError):
            self.att.attest(token)

    def test_forged_signature_rejected(self):
        other_priv, _ = _make_cluster()
        token = _sa_token(
            other_priv,
            iss="https://kubernetes.default.svc",
            aud="charon",
            ns="x",
            sa="y",
        )
        with self.assertRaises(AttestationError):
            self.att.attest(token)


class RegistryAttestationTests(unittest.TestCase):
    def setUp(self):
        self.reg = _registry()

    def test_issuance_refused_without_attestation(self):
        a = self.reg.register("bot", "alice", "x", scopes=["read"])
        with self.assertRaises(NotIssuable):
            self.reg.issue_credential(a.id)

    def test_join_token_attest_then_issue(self):
        att = JoinTokenAttestor()
        a = self.reg.register("bot", "alice", "x", scopes=["read"])
        token = att.mint(selectors={"team": "ci"})
        self.reg.attest(a.id, attestor=att, evidence=token)
        cred = self.reg.issue_credential(a.id)
        self.assertEqual(self.reg.verify_credential(cred)["scope"], "read")

    def test_selector_binding_mismatch_fails(self):
        att = JoinTokenAttestor()
        a = self.reg.register("bot", "alice", "x")
        token = att.mint(selectors={"team": "marketing"})
        with self.assertRaises(AttestationError):
            self.reg.attest(
                a.id,
                attestor=att,
                evidence=token,
                require_selectors={"team": "payments"},
            )

    def test_dev_attestor_records_insecure_method(self):
        a = self.reg.register("bot", "alice", "x")
        self.reg.attest(a.id)  # default DevAttestor
        agent = self.reg.get(a.id)
        self.assertEqual(agent.attestation["method"], "dev-insecure")

    def test_expired_attestation_blocks_issuance(self):
        a = self.reg.register("bot", "alice", "x", scopes=["read"])
        # DevAttestor with a 0s TTL -> attestation immediately stale.
        self.reg.attest(a.id, attestor=DevAttestor(ttl=0))
        with self.assertRaises(NotIssuable):
            self.reg.issue_credential(a.id)


if __name__ == "__main__":
    unittest.main()
