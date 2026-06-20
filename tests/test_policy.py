import unittest

from charon.policy import EmbeddedPolicyEngine


class PolicyTests(unittest.TestCase):
    def setUp(self):
        self.engine = EmbeddedPolicyEngine()

    def _eval(self, **kw):
        base = {
            "scopes": [],
            "server": "s",
            "tool": "t",
            "args": {},
            "required_scope": None,
            "constraints": {},
        }
        base.update(kw)
        return self.engine.evaluate(base)

    def test_allows_with_required_scope(self):
        d = self._eval(scopes=["fs:read"], required_scope="fs:read")
        self.assertTrue(d.allow)

    def test_denies_without_required_scope(self):
        d = self._eval(scopes=["fs:read"], required_scope="pay:charge")
        self.assertFalse(d.allow)
        self.assertIn("pay:charge", d.reason)

    def test_path_confinement(self):
        ok = self._eval(
            scopes=["fs:read"],
            required_scope="fs:read",
            args={"path": "/data/x.txt"},
            constraints={"allowed_root": "/data"},
        )
        self.assertTrue(ok.allow)
        escape = self._eval(
            scopes=["fs:read"],
            required_scope="fs:read",
            args={"path": "/etc/shadow"},
            constraints={"allowed_root": "/data"},
        )
        self.assertFalse(escape.allow)

    def test_path_traversal_blocked(self):
        d = self._eval(
            scopes=["fs:read"],
            required_scope="fs:read",
            args={"path": "/data/../etc/shadow"},
            constraints={"allowed_root": "/data"},
        )
        self.assertFalse(d.allow)

    def test_amount_cap(self):
        within = self._eval(
            scopes=["pay:charge"],
            required_scope="pay:charge",
            args={"amount": 500},
            constraints={"max_amount": 1000},
        )
        self.assertTrue(within.allow)
        over = self._eval(
            scopes=["pay:charge"],
            required_scope="pay:charge",
            args={"amount": 5000},
            constraints={"max_amount": 1000},
        )
        self.assertFalse(over.allow)

    def test_no_required_scope_allows(self):
        d = self._eval(required_scope="")
        self.assertTrue(d.allow)


if __name__ == "__main__":
    unittest.main()
