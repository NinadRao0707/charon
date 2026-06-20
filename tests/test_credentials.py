import time
import unittest

import jwt

from charon import spiffe
from charon.ca import CertificateAuthority
from charon.credentials import (
    CredentialAuthority,
    CredentialExpired,
    CredentialRevoked,
    InvalidCredential,
    NotIssuable,
)
from charon.lifecycle import LifecycleState
from charon.models import Agent

TRUST_DOMAIN = "charon.test"


def _active_agent(scopes=None):
    a = Agent(name="bot", owner="alice", purpose="ci", scopes=scopes or ["read:files"])
    a.spiffe_id = str(spiffe.for_agent(TRUST_DOMAIN, a.id))
    a.attested = True
    a.state = LifecycleState.ACTIVE
    return a


class CredentialTests(unittest.TestCase):
    def setUp(self):
        self.ca = CertificateAuthority()
        self.authority = CredentialAuthority(self.ca, TRUST_DOMAIN, ttl_seconds=300)

    def test_issue_and_verify(self):
        agent = _active_agent(["read:files", "list:dirs"])
        token = self.authority.issue(agent)
        claims = self.authority.verify(token)
        self.assertEqual(claims["sub"], agent.spiffe_id)
        self.assertEqual(claims["scope"], "list:dirs read:files")  # sorted
        self.assertTrue(claims["sub"].startswith("spiffe://charon.test/agent/"))

    def test_unattested_agent_cannot_get_credential(self):
        agent = _active_agent()
        agent.attested = False
        with self.assertRaises(NotIssuable):
            self.authority.issue(agent)

    def test_revoked_agent_cannot_get_credential(self):
        agent = _active_agent()
        agent.state = LifecycleState.REVOKED
        with self.assertRaises(NotIssuable):
            self.authority.issue(agent)

    def test_revocation_blocks_verification(self):
        agent = _active_agent()
        token = self.authority.issue(agent)
        self.authority.verify(token)  # ok before revocation
        self.authority.revoke(token, reason="compromised")
        with self.assertRaises(CredentialRevoked):
            self.authority.verify(token)

    def test_rotation_revokes_previous(self):
        agent = _active_agent()
        first = self.authority.issue(agent)
        time.sleep(1)  # ensure a distinct jti (jti embeds the issue second)
        second = self.authority.rotate(agent, previous_token=first)
        with self.assertRaises(CredentialRevoked):
            self.authority.verify(first)
        self.assertEqual(self.authority.verify(second)["sub"], agent.spiffe_id)

    def test_expired_credential_rejected(self):
        authority = CredentialAuthority(self.ca, TRUST_DOMAIN, ttl_seconds=1)
        agent = _active_agent()
        token = authority.issue(agent)
        time.sleep(2)
        with self.assertRaises(CredentialExpired):
            authority.verify(token)

    def test_tampered_token_rejected(self):
        agent = _active_agent()
        token = self.authority.issue(agent)
        tampered = token[:-4] + ("AAAA" if not token.endswith("AAAA") else "BBBB")
        with self.assertRaises(InvalidCredential):
            self.authority.verify(tampered)

    def test_key_rotation_keeps_old_tokens_valid(self):
        agent = _active_agent()
        old_token = self.authority.issue(agent)
        self.ca.rotate()  # new active signing key
        # Old token signed by retired key still verifies (key kept in bundle).
        self.assertEqual(self.authority.verify(old_token)["sub"], agent.spiffe_id)
        # New issuance uses the new key.
        new_token = self.authority.issue(agent)
        new_kid = jwt.get_unverified_header(new_token)["kid"]
        self.assertEqual(new_kid, self.ca.active.kid)

    def test_prune_revocation_list(self):
        agent = _active_agent()
        token = self.authority.issue(agent)
        self.authority.revoke(token)
        self.assertEqual(self.authority.prune_revocation_list(now=0), 0)  # not expired
        pruned = self.authority.prune_revocation_list(now=time.time() + 10_000)
        self.assertEqual(pruned, 1)


if __name__ == "__main__":
    unittest.main()
