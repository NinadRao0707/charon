import time
import unittest

from charon.attestation import DevAttestor
from charon.ca import CertificateAuthority
from charon.credentials import CredentialAuthority
from charon.lifecycle import LifecycleState
from charon.mcp import FilesystemServer, MCPGateway, PaymentsServer
from charon.reaper import Reaper
from charon.repository import SQLiteRepository
from charon.service import Registry

TRUST_DOMAIN = "charon.test"
DAY = 86_400


def _registry():
    repo = SQLiteRepository(":memory:")
    ca = CertificateAuthority()
    return Registry(repo, CredentialAuthority(ca, TRUST_DOMAIN), TRUST_DOMAIN)


def _active_agent(reg, name="bot", owner="alice", scopes=None):
    a = reg.register(name, owner, "x", scopes=scopes or ["fs:read"])
    reg.attest(a.id, attestor=DevAttestor())
    reg.issue_credential(a.id)
    return a


class ReaperTests(unittest.TestCase):
    def setUp(self):
        self.reg = _registry()

    def test_idle_detection(self):
        a = _active_agent(self.reg)
        future = time.time() + 2 * DAY
        actions = Reaper(self.reg, idle_after=DAY).run_once(now=future)
        self.assertTrue(any(x.action == "idled" for x in actions))
        self.assertEqual(self.reg.get(a.id).state, LifecycleState.IDLE)

    def test_decommission_after_idle(self):
        a = _active_agent(self.reg)
        reaper = Reaper(self.reg, idle_after=DAY, decommission_after_idle=7 * DAY)
        reaper.run_once(now=time.time() + 2 * DAY)  # -> IDLE
        actions = reaper.run_once(now=time.time() + 10 * DAY)  # -> DECOMMISSIONED
        self.assertTrue(any(x.action == "decommissioned-idle" for x in actions))
        self.assertEqual(self.reg.get(a.id).state, LifecycleState.DECOMMISSIONED)

    def test_orphan_decommissioned(self):
        a = _active_agent(self.reg, owner="bob@corp.example")
        actions = Reaper(self.reg, departed_owners={"bob@corp.example"}).run_once()
        self.assertTrue(any(x.action == "decommissioned-orphan" for x in actions))
        self.assertEqual(self.reg.get(a.id).state, LifecycleState.DECOMMISSIONED)

    def test_drift_flagged(self):
        a = _active_agent(self.reg, scopes=["fs:read", "pay:charge"])
        gateway = MCPGateway(self.reg, [FilesystemServer(), PaymentsServer()])
        # exercise only fs:read
        gateway.handle(
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {"name": "filesystem.read_file",
                           "arguments": {"path": "/data/a"}},
                "credential": self.reg.issue_credential(a.id),
            }
        )
        actions = Reaper(self.reg).run_once()  # now ~= real, so not idle
        drift = [x for x in actions if x.action == "drift-flagged"]
        self.assertTrue(drift)
        self.assertIn("pay:charge", drift[0].detail)

    def test_dry_run_changes_nothing(self):
        a = _active_agent(self.reg)
        future = time.time() + 2 * DAY
        actions = Reaper(self.reg, idle_after=DAY).run_once(now=future, apply=False)
        self.assertTrue(actions)  # it reports what it *would* do
        self.assertEqual(self.reg.get(a.id).state, LifecycleState.ACTIVE)  # unchanged


if __name__ == "__main__":
    unittest.main()
