import time
import unittest

from charon.dpop import DpopError, DpopKey, ReplayCache, jwk_thumbprint, verify_proof

RESOURCE = "https://charon.gateway/mcp"


class DpopUnitTests(unittest.TestCase):
    def setUp(self):
        self.key = DpopKey()
        self.cache = ReplayCache()

    def test_valid_proof_accepted(self):
        proof = self.key.proof("POST", RESOURCE)
        claims = verify_proof(proof, "POST", RESOURCE, self.key.thumbprint(), self.cache)
        self.assertEqual(claims["htu"], RESOURCE)

    def test_thumbprint_matches_jwk(self):
        self.assertEqual(self.key.thumbprint(), jwk_thumbprint(self.key.public_jwk()))

    def test_replay_rejected(self):
        proof = self.key.proof("POST", RESOURCE)
        verify_proof(proof, "POST", RESOURCE, self.key.thumbprint(), self.cache)
        with self.assertRaises(DpopError):
            verify_proof(proof, "POST", RESOURCE, self.key.thumbprint(), self.cache)

    def test_wrong_key_thumbprint_rejected(self):
        proof = self.key.proof("POST", RESOURCE)
        other = DpopKey()
        with self.assertRaises(DpopError):
            verify_proof(proof, "POST", RESOURCE, other.thumbprint(), self.cache)

    def test_method_binding(self):
        proof = self.key.proof("GET", RESOURCE)
        with self.assertRaises(DpopError):
            verify_proof(proof, "POST", RESOURCE, self.key.thumbprint(), self.cache)

    def test_url_binding(self):
        proof = self.key.proof("POST", "https://evil.example/mcp")
        with self.assertRaises(DpopError):
            verify_proof(proof, "POST", RESOURCE, self.key.thumbprint(), self.cache)

    def test_stale_proof_rejected(self):
        proof = self.key.proof("POST", RESOURCE)
        future = time.time() + 3600
        with self.assertRaises(DpopError):
            verify_proof(
                proof, "POST", RESOURCE, self.key.thumbprint(), self.cache, now=future
            )


if __name__ == "__main__":
    unittest.main()
