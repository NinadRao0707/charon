import unittest

from charon.attestation import DevAttestor
from charon.ca import CertificateAuthority
from charon.credentials import CredentialAuthority
from charon.delegation import DelegationError
from charon.mcp import MCPGateway, PaymentsServer
from charon.repository import SQLiteRepository
from charon.service import Registry

TRUST_DOMAIN = "charon.test"
HUMAN = "user:alice@corp.example"


def _registry():
    repo = SQLiteRepository(":memory:")
    ca = CertificateAuthority()
    return Registry(repo, CredentialAuthority(ca, TRUST_DOMAIN), TRUST_DOMAIN)


def _agent_with_token(reg, name, scopes):
    a = reg.register(name, HUMAN, "x", scopes=scopes)
    reg.attest(a.id, attestor=DevAttestor())
    return a, reg.issue_credential(a.id)


class DelegationTests(unittest.TestCase):
    def setUp(self):
        self.reg = _registry()

    def test_begin_on_behalf_of_sets_principal_and_actor(self):
        a, a_tok = _agent_with_token(self.reg, "A", ["pay:charge", "fs:read"])
        obo = self.reg.begin_on_behalf_of(HUMAN, a_tok, ["pay:charge"])
        claims = self.reg.verify_credential(obo)
        self.assertEqual(claims["sub"], HUMAN)
        self.assertEqual(claims["act"]["sub"], a.spiffe_id)
        self.assertEqual(claims["scope"], "pay:charge")

    def test_downscope_cannot_widen(self):
        _, a_tok = _agent_with_token(self.reg, "A", ["fs:read"])
        with self.assertRaises(DelegationError):
            self.reg.begin_on_behalf_of(HUMAN, a_tok, ["pay:charge"])  # not granted

    def test_three_hop_trace_back_to_human(self):
        """The Phase 5 milestone: human -> A -> B -> C, traced from C's token."""
        a, a_tok = _agent_with_token(self.reg, "A", ["pay:charge"])
        b, b_tok = _agent_with_token(self.reg, "B", ["pay:charge"])
        c, c_tok = _agent_with_token(self.reg, "C", ["pay:charge"])

        obo = self.reg.begin_on_behalf_of(HUMAN, a_tok, ["pay:charge"])
        hop2 = self.reg.delegate(obo, b_tok, ["pay:charge"])
        hop3 = self.reg.delegate(hop2, c_tok, ["pay:charge"])

        prov = self.reg.trace(hop3)
        self.assertEqual(prov.principal, HUMAN)
        self.assertEqual(prov.actors, [a.spiffe_id, b.spiffe_id, c.spiffe_id])
        self.assertEqual(
            str(prov),
            f"{HUMAN} -> {a.spiffe_id} -> {b.spiffe_id} -> {c.spiffe_id}",
        )

    def test_chain_narrows_scope_each_hop(self):
        _, a_tok = _agent_with_token(self.reg, "A", ["pay:charge", "fs:read"])
        _, b_tok = _agent_with_token(self.reg, "B", ["pay:charge", "fs:read"])
        obo = self.reg.begin_on_behalf_of(HUMAN, a_tok, ["pay:charge", "fs:read"])
        narrowed = self.reg.delegate(obo, b_tok, ["fs:read"])
        self.assertEqual(self.reg.verify_credential(narrowed)["scope"], "fs:read")
        # cannot re-widen on a later hop
        _, c_tok = _agent_with_token(self.reg, "C", ["pay:charge", "fs:read"])
        with self.assertRaises(DelegationError):
            self.reg.delegate(narrowed, c_tok, ["pay:charge"])

    def test_delegation_edges_recorded(self):
        _, a_tok = _agent_with_token(self.reg, "A", ["pay:charge"])
        _, b_tok = _agent_with_token(self.reg, "B", ["pay:charge"])
        obo = self.reg.begin_on_behalf_of(HUMAN, a_tok, ["pay:charge"])
        self.reg.delegate(obo, b_tok, ["pay:charge"])
        edges = self.reg.list_delegations()
        self.assertEqual(len(edges), 2)
        self.assertEqual(edges[0].delegator, HUMAN)

    def test_delegated_call_through_gateway_records_provenance(self):
        gateway = MCPGateway(self.reg, [PaymentsServer()])
        a, a_tok = _agent_with_token(self.reg, "A", ["pay:charge"])
        c, c_tok = _agent_with_token(self.reg, "C", ["pay:charge"])
        obo = self.reg.begin_on_behalf_of(HUMAN, a_tok, ["pay:charge"])
        delegated = self.reg.delegate(obo, c_tok, ["pay:charge"])

        resp = gateway.handle(
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {"name": "payments.charge", "arguments": {"amount": 10}},
                "credential": delegated,
            }
        )
        self.assertIn("result", resp)
        # the authz audit entry should be attributed to the acting agent (C) and
        # carry the provenance back to the human
        authz = [e for e in self.reg.audit_entries() if e.event == "authz.allowed"]
        self.assertTrue(authz)
        last = authz[-1]
        self.assertEqual(last.subject, c.spiffe_id)
        self.assertIn(HUMAN, last.details["provenance"])


if __name__ == "__main__":
    unittest.main()
