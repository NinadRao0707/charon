import os
import tempfile
import unittest

from charon.attestation import DevAttestor
from charon.ca import CertificateAuthority, SigningKey
from charon.credentials import CredentialAuthority, CredentialRevoked
from charon.repository import SQLiteRepository
from charon.service import Registry

TRUST_DOMAIN = "charon.test"


class SigningKeyPersistenceTests(unittest.TestCase):
    def test_pem_round_trip_preserves_identity(self):
        original = SigningKey.generate()
        loaded = SigningKey.from_private_pem(original.private_pem)
        self.assertEqual(original.kid, loaded.kid)

    def test_token_survives_key_reload(self):
        ca1 = CertificateAuthority()
        pem = ca1.active.private_pem
        authority1 = CredentialAuthority(ca1, TRUST_DOMAIN)
        reg1 = Registry(SQLiteRepository(":memory:"), authority1, TRUST_DOMAIN)
        a = reg1.register("bot", "alice", "x", scopes=["fs:read"])
        reg1.attest(a.id, attestor=DevAttestor())
        token = reg1.issue_credential(a.id)

        # Simulate a restart: rebuild the CA from the persisted PEM.
        ca2 = CertificateAuthority(active=SigningKey.from_private_pem(pem))
        authority2 = CredentialAuthority(ca2, TRUST_DOMAIN)
        # The token issued before the "restart" still verifies.
        self.assertEqual(authority2.verify(token)["sub"], a.spiffe_id)


class RevocationReloadTests(unittest.TestCase):
    def test_revocation_survives_restart(self):
        path = os.path.join(tempfile.mkdtemp(), "reload.db")
        repo = repo2 = None
        try:
            ca = CertificateAuthority()
            pem = ca.active.private_pem
            repo = SQLiteRepository(path)
            reg = Registry(repo, CredentialAuthority(ca, TRUST_DOMAIN), TRUST_DOMAIN)
            a = reg.register("bot", "alice", "x", scopes=["fs:read"])
            reg.attest(a.id, attestor=DevAttestor())
            token = reg.issue_credential(a.id)
            reg.revoke_credential(a.id, token, reason="leaked")
            repo.close()

            # Restart: same persisted key, fresh registry over the same DB.
            repo2 = SQLiteRepository(path)
            ca2 = CertificateAuthority(active=SigningKey.from_private_pem(pem))
            reg2 = Registry(repo2, CredentialAuthority(ca2, TRUST_DOMAIN), TRUST_DOMAIN)
            # The revocation must still be in force after the restart.
            with self.assertRaises(CredentialRevoked):
                reg2.verify_credential(token)
        finally:
            if repo is not None:
                repo.close()
            if repo2 is not None:
                repo2.close()
            if os.path.exists(path):
                os.remove(path)
            os.rmdir(os.path.dirname(path))


if __name__ == "__main__":
    unittest.main()
