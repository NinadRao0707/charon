import unittest

from charon.attestation import JoinTokenAttestor
from charon.ca import CertificateAuthority
from charon.credentials import CredentialAuthority
from charon.mcp import EmailServer, FilesystemServer, MCPGateway, PaymentsServer
from charon.mcp.gateway import ERR_FORBIDDEN, ERR_UNAUTHENTICATED
from charon.repository import SQLiteRepository
from charon.service import Registry

TRUST_DOMAIN = "charon.test"


def _setup(scopes):
    repo = SQLiteRepository(":memory:")
    ca = CertificateAuthority()
    registry = Registry(repo, CredentialAuthority(ca, TRUST_DOMAIN), TRUST_DOMAIN)
    gateway = MCPGateway(
        registry, [FilesystemServer(), PaymentsServer(), EmailServer()]
    )
    att = JoinTokenAttestor()
    agent = registry.register("bot", "alice", "x", scopes=scopes)
    registry.attest(agent.id, attestor=att, evidence=att.mint())
    token = registry.issue_credential(agent.id)
    return registry, gateway, agent, token


def _call(gateway, token, name, args=None, credential_present=True):
    req = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {"name": name, "arguments": args or {}},
    }
    if credential_present:
        req["credential"] = token
    return gateway.handle(req)


class GatewayTests(unittest.TestCase):
    def test_milestone_read_files_blocked_from_payment(self):
        """The Phase 4 milestone: an fs:read-only agent cannot charge a card."""
        _, gateway, _, token = _setup(["fs:read"])

        allowed = _call(gateway, token, "filesystem.read_file", {"path": "/data/a"})
        self.assertIn("result", allowed)

        denied = _call(gateway, token, "payments.charge", {"amount": 10})
        self.assertIn("error", denied)
        self.assertEqual(denied["error"]["code"], ERR_FORBIDDEN)
        self.assertIn("pay:charge", denied["error"]["message"])

    def test_missing_credential_unauthenticated(self):
        _, gateway, _, token = _setup(["fs:read"])
        resp = _call(gateway, token, "filesystem.read_file", credential_present=False)
        self.assertEqual(resp["error"]["code"], ERR_UNAUTHENTICATED)

    def test_revoked_credential_blocked_at_gateway(self):
        registry, gateway, agent, token = _setup(["fs:read"])
        registry.revoke_credential(agent.id, token, reason="leaked")
        resp = _call(gateway, token, "filesystem.read_file", {"path": "/data/a"})
        self.assertEqual(resp["error"]["code"], ERR_UNAUTHENTICATED)

    def test_path_escape_denied(self):
        _, gateway, _, token = _setup(["fs:read"])
        resp = _call(gateway, token, "filesystem.read_file", {"path": "/etc/shadow"})
        self.assertEqual(resp["error"]["code"], ERR_FORBIDDEN)

    def test_amount_cap_denied(self):
        _, gateway, _, token = _setup(["pay:charge"])
        resp = _call(gateway, token, "payments.charge", {"amount": 999999})
        self.assertEqual(resp["error"]["code"], ERR_FORBIDDEN)
        ok = _call(gateway, token, "payments.charge", {"amount": 50})
        self.assertIn("result", ok)

    def test_tools_list_filtered_by_scope(self):
        _, gateway, _, token = _setup(["fs:read"])
        resp = gateway.handle(
            {"jsonrpc": "2.0", "id": 9, "method": "tools/list", "credential": token}
        )
        names = {t["name"] for t in resp["result"]["tools"]}
        self.assertIn("filesystem.read_file", names)
        self.assertNotIn("payments.charge", names)
        self.assertNotIn("filesystem.write_file", names)

    def test_decisions_are_audited(self):
        registry, gateway, _, token = _setup(["fs:read"])
        _call(gateway, token, "filesystem.read_file", {"path": "/data/a"})
        _call(gateway, token, "payments.charge", {"amount": 10})
        events = [e.event for e in registry.audit_entries()]
        self.assertIn("authz.allowed", events)
        self.assertIn("authz.denied", events)
        self.assertTrue(registry.audit_ok())

    def test_allowed_call_records_activity(self):
        registry, gateway, agent, token = _setup(["fs:read"])
        self.assertIsNone(registry.get(agent.id).last_seen)
        _call(gateway, token, "filesystem.read_file", {"path": "/data/a"})
        self.assertIsNotNone(registry.get(agent.id).last_seen)


if __name__ == "__main__":
    unittest.main()
