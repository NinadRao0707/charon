import unittest
from dataclasses import replace

from charon.audit import AuditLog


class AuditTests(unittest.TestCase):
    def test_chain_verifies(self):
        log = AuditLog()
        log.append("a", "agent-1", {"x": 1})
        log.append("b", "agent-1", {"y": 2})
        log.append("c", "agent-2", {})
        self.assertTrue(log.verify())

    def test_each_entry_links_to_previous(self):
        log = AuditLog()
        e1 = log.append("a", "s", {})
        e2 = log.append("b", "s", {})
        self.assertEqual(e2.prev_hash, e1.entry_hash)

    def test_tamper_breaks_chain(self):
        log = AuditLog()
        log.append("a", "agent-1", {"amount": 10})
        log.append("b", "agent-1", {"amount": 20})
        # Forge the details of the first entry, keeping its stored hash.
        forged = replace(log._entries[0], details={"amount": 9999})  # noqa: SLF001
        log._entries[0] = forged  # noqa: SLF001
        self.assertFalse(log.verify())


if __name__ == "__main__":
    unittest.main()
