"""Adversarial test suite (Phase 7).

These tests assert that the controls *resist attack*, not merely that the happy
path works. Each maps to a documented threat:

  * token theft           -> DPoP proof-of-possession
  * proof replay          -> single-use jti replay cache
  * scope escalation      -> delegation downscoping + signature integrity
  * confused deputy       -> sub/act integrity + DPoP key binding
  * audit tampering       -> hash-chain integrity check on load
"""
import os
import tempfile
import unittest

import jwt

from charon.attestation import DevAttestor
from charon.ca import CertificateAuthority
from charon.credentials import CredentialAuthority
from charon.delegation import DelegationError
from charon.dpop import DpopKey
from charon.mcp import FilesystemServer, MCPGateway, PaymentsServer
from charon.mcp.gateway import ERR_FORBIDDEN, ERR_UNAUTHENTICATED
from charon.repository import SQLiteRepository
from charon.service import Registry, RegistryError

TRUST_DOMAIN = "charon.test"
RESOURCE = "https://charon.gateway/mcp"
HUMAN = "user:alice@corp.example"


def _registry(repo=None):
    repo = repo or SQLiteRepository(":memory:")
    ca = CertificateAuthority()
    return Registry(repo, CredentialAuthority(ca, TRUST_DOMAIN), TRUST_DOMAIN)


def _agent(reg, name, scopes, dpop_jkt=None):
    a = reg.register(name, HUMAN, "x", scopes=scopes)
    reg.attest(a.id, attestor=DevAttestor())
    return a, reg.issue_credential(a.id, dpop_jkt=dpop_jkt)


def _call(gateway, token, name, args=None, proof=None):
    req = {
        "jsonrpc": "2.0", "id": 1, "method": "tools/call",
        "params": {"name": name, "arguments": args or {}},
        "credential": token,
    }
    if proof:
        req["dpop"] = proof
    return gateway.handle(req)


class TokenTheftTests(unittest.TestCase):
    def setUp(self):
        self.reg = _registry()
        self.gateway = MCPGateway(self.reg, [FilesystemServer()], resource_url=RESOURCE)
        self.key = DpopKey()
        _, self.token = _agent(self.reg, "bot", ["fs:read"], dpop_jkt=self.key.thumbprint())

    def test_legit_holder_with_proof_succeeds(self):
        proof = self.key.proof("POST", RESOURCE)
        resp = _call(self.gateway, self.token, "filesystem.read_file",
                     {"path": "/data/a"}, proof=proof)
        self.assertIn("result", resp)

    def test_stolen_token_without_proof_rejected(self):
        # Attacker has the token but presents no DPoP proof.
        resp = _call(self.gateway, self.token, "filesystem.read_file", {"path": "/data/a"})
        self.assertEqual(resp["error"]["code"], ERR_UNAUTHENTICATED)

    def test_stolen_token_with_attacker_key_rejected(self):
        # Attacker has the token and forges a proof with their OWN key.
        attacker = DpopKey()
        proof = attacker.proof("POST", RESOURCE)
        resp = _call(self.gateway, self.token, "filesystem.read_file",
                     {"path": "/data/a"}, proof=proof)
        self.assertEqual(resp["error"]["code"], ERR_UNAUTHENTICATED)


class ReplayTests(unittest.TestCase):
    def test_proof_replay_through_gateway_rejected(self):
        reg = _registry()
        gateway = MCPGateway(reg, [FilesystemServer()], resource_url=RESOURCE)
        key = DpopKey()
        _, token = _agent(reg, "bot", ["fs:read"], dpop_jkt=key.thumbprint())
        proof = key.proof("POST", RESOURCE)
        first = _call(gateway, token, "filesystem.read_file", {"path": "/data/a"}, proof=proof)
        self.assertIn("result", first)
        # Replaying the captured proof must fail.
        second = _call(gateway, token, "filesystem.read_file", {"path": "/data/a"}, proof=proof)
        self.assertEqual(second["error"]["code"], ERR_UNAUTHENTICATED)


class ScopeEscalationTests(unittest.TestCase):
    def setUp(self):
        self.reg = _registry()
        self.gateway = MCPGateway(self.reg, [FilesystemServer(), PaymentsServer()])

    def test_out_of_scope_tool_denied(self):
        _, token = _agent(self.reg, "reader", ["fs:read"])
        resp = _call(self.gateway, token, "payments.charge", {"amount": 1})
        self.assertEqual(resp["error"]["code"], ERR_FORBIDDEN)

    def test_delegation_cannot_widen_scope(self):
        _, a_tok = _agent(self.reg, "A", ["fs:read"])
        with self.assertRaises(DelegationError):
            self.reg.begin_on_behalf_of(HUMAN, a_tok, ["pay:charge"])

    def test_forged_scope_claim_breaks_signature(self):
        _, token = _agent(self.reg, "reader", ["fs:read"])
        # Attacker rewrites the scope claim and re-signs with their own key.
        payload = jwt.decode(token, options={"verify_signature": False})
        payload["scope"] = "fs:read pay:charge"
        forged = jwt.encode(payload, DpopKey()._sk, algorithm="ES256")  # wrong key/alg
        resp = _call(self.gateway, forged, "payments.charge", {"amount": 1})
        self.assertEqual(resp["error"]["code"], ERR_UNAUTHENTICATED)


class ConfusedDeputyTests(unittest.TestCase):
    def test_cannot_forge_on_behalf_of_human(self):
        """An agent cannot fabricate a token claiming sub=human without the CA key."""
        reg = _registry()
        gateway = MCPGateway(reg, [PaymentsServer()])
        _, _ = _agent(reg, "deputy", ["pay:charge"])
        forged = jwt.encode(
            {"sub": HUMAN, "scope": "pay:charge", "aud": "charon-gateway",
             "act": {"sub": "spiffe://charon.test/agent/deputy"}},
            DpopKey()._sk, algorithm="ES256",
        )
        resp = _call(gateway, forged, "payments.charge", {"amount": 1})
        self.assertEqual(resp["error"]["code"], ERR_UNAUTHENTICATED)

    def test_delegated_token_tamper_detected(self):
        reg = _registry()
        gateway = MCPGateway(reg, [PaymentsServer()])
        a, a_tok = _agent(reg, "A", ["pay:charge"])
        c, c_tok = _agent(reg, "C", ["pay:charge"])
        obo = reg.begin_on_behalf_of(HUMAN, a_tok, ["pay:charge"])
        delegated = reg.delegate(obo, c_tok, ["pay:charge"])
        tampered = delegated[:-6] + ("AAAAAA" if not delegated.endswith("AAAAAA") else "BBBBBB")
        resp = _call(gateway, tampered, "payments.charge", {"amount": 1})
        self.assertEqual(resp["error"]["code"], ERR_UNAUTHENTICATED)


class AuditTamperTests(unittest.TestCase):
    def test_tampering_persisted_audit_is_detected_on_load(self):
        path = tempfile.mktemp(suffix=".db")
        try:
            repo = SQLiteRepository(path)
            reg = _registry(repo)
            a = reg.register("bot", HUMAN, "x")
            reg.attest(a.id)
            reg.issue_credential(a.id)
            self.assertTrue(reg.audit_ok())
            # Attacker rewrites a historical audit row directly in storage.
            repo._conn.execute(  # noqa: SLF001
                "UPDATE audit SET details = ? WHERE seq = 0",
                ('{"name": "rogue", "owner": "attacker"}',),
            )
            repo._conn.commit()  # noqa: SLF001
            # A fresh load must reject the broken chain.
            repo2 = SQLiteRepository(path)
            with self.assertRaises(RegistryError):
                _registry(repo2)
        finally:
            if os.path.exists(path):
                os.remove(path)


if __name__ == "__main__":
    unittest.main()
