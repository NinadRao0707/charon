import unittest

from charon.ca import CertificateAuthority
from charon.credentials import CredentialAuthority, NotIssuable
from charon.lifecycle import IllegalTransition, LifecycleState, TransitionGuardFailed
from charon.repository import SQLiteRepository
from charon.service import Registry, UnknownAgent

TRUST_DOMAIN = "charon.test"


def _registry():
    repo = SQLiteRepository(":memory:")
    ca = CertificateAuthority()
    authority = CredentialAuthority(ca, TRUST_DOMAIN)
    return Registry(repo, authority, TRUST_DOMAIN), repo


class RegistryTests(unittest.TestCase):
    def setUp(self):
        self.reg, self.repo = _registry()

    def test_register_assigns_spiffe_id_and_state(self):
        a = self.reg.register("ci-bot", "alice", "run CI", scopes=["read:repo"])
        self.assertEqual(a.state, LifecycleState.PROVISIONED)
        self.assertTrue(a.spiffe_id.startswith("spiffe://charon.test/agent/"))
        self.assertIsNotNone(self.repo.get_agent(a.id))

    def test_unknown_agent_raises(self):
        with self.assertRaises(UnknownAgent):
            self.reg.get("does-not-exist")

    def test_cannot_activate_without_attestation(self):
        a = self.reg.register("bot", "bob", "x")
        with self.assertRaises(TransitionGuardFailed):
            self.reg.transition(a.id, LifecycleState.ACTIVE)

    def test_issue_requires_attestation(self):
        a = self.reg.register("bot", "bob", "x")
        with self.assertRaises(NotIssuable):
            self.reg.issue_credential(a.id)

    def test_full_happy_path(self):
        a = self.reg.register("bot", "carol", "deploy", scopes=["deploy:prod"])
        self.reg.attest(a.id, method="k8s-sa")
        token = self.reg.issue_credential(a.id)
        # first credential should have activated the agent
        self.assertEqual(self.reg.get(a.id).state, LifecycleState.ACTIVE)
        claims = self.reg.verify_credential(token)
        self.assertEqual(claims["scope"], "deploy:prod")

    def test_illegal_transition_rejected(self):
        a = self.reg.register("bot", "dan", "x")
        with self.assertRaises(IllegalTransition):
            self.reg.transition(a.id, LifecycleState.IDLE)

    def test_audit_log_records_and_verifies(self):
        a = self.reg.register("bot", "erin", "x")
        self.reg.attest(a.id)
        self.reg.issue_credential(a.id)
        events = [e.event for e in self.reg.audit_entries()]
        self.assertIn("agent.registered", events)
        self.assertIn("agent.attested", events)
        self.assertIn("credential.issued", events)
        self.assertIn("agent.transition", events)
        self.assertTrue(self.reg.audit_ok())

    def test_audit_persists_and_rehydrates(self):
        a = self.reg.register("bot", "frank", "x")
        self.reg.attest(a.id)
        self.reg.issue_credential(a.id)
        n_before = len(self.reg.audit_entries())
        # New Registry instance over the same repo should rehydrate the chain.
        ca = CertificateAuthority()
        reg2 = Registry(self.repo, CredentialAuthority(ca, TRUST_DOMAIN), TRUST_DOMAIN)
        self.assertEqual(len(reg2.audit_entries()), n_before)
        self.assertTrue(reg2.audit_ok())

    def test_revocation_persisted(self):
        a = self.reg.register("bot", "gina", "x", scopes=["read"])
        self.reg.attest(a.id)
        token = self.reg.issue_credential(a.id)
        self.reg.revoke_credential(a.id, token, reason="leaked")
        self.assertEqual(len(self.repo.list_revocations()), 1)


if __name__ == "__main__":
    unittest.main()
