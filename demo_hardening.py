"""Phase 7 demo — proof-of-possession in action.

Run:  python demo_hardening.py

Shows that a DPoP-bound credential is useless to an attacker who steals the
token but not the private key, and that a captured proof cannot be replayed.
"""
from charon.attestation import DevAttestor
from charon.ca import CertificateAuthority
from charon.credentials import CredentialAuthority
from charon.dpop import DpopKey
from charon.mcp import FilesystemServer, MCPGateway
from charon.repository import SQLiteRepository
from charon.service import Registry

TRUST_DOMAIN = "charon.demo"
RESOURCE = "https://charon.gateway/mcp"


def call(gateway, token, proof=None):
    req = {
        "jsonrpc": "2.0", "id": 1, "method": "tools/call",
        "params": {"name": "filesystem.read_file", "arguments": {"path": "/data/report.txt"}},
        "credential": token,
    }
    if proof:
        req["dpop"] = proof
    r = gateway.handle(req)
    return "ALLOWED" if "result" in r else f"DENIED ({r['error']['message']})"


def main():
    reg = Registry(SQLiteRepository(":memory:"),
                   CredentialAuthority(CertificateAuthority(), TRUST_DOMAIN),
                   TRUST_DOMAIN)
    gateway = MCPGateway(reg, [FilesystemServer()], resource_url=RESOURCE)

    # The legitimate client holds a DPoP key; the token is bound to it.
    key = DpopKey()
    a = reg.register("reporter", "alice@corp.example", "read reports", scopes=["fs:read"])
    reg.attest(a.id, attestor=DevAttestor())
    token = reg.issue_credential(a.id, dpop_jkt=key.thumbprint())
    print(f"Issued a DPoP-bound credential (cnf.jkt = {key.thumbprint()[:16]}...)\n")

    print("1. Legitimate client (holds the key), valid proof:")
    print("   ", call(gateway, token, key.proof("POST", RESOURCE)))

    print("2. Attacker steals the token, presents NO proof:")
    print("   ", call(gateway, token))

    print("3. Attacker steals the token, forges a proof with their OWN key:")
    print("   ", call(gateway, token, DpopKey().proof("POST", RESOURCE)))

    print("4. Attacker replays a previously-captured valid proof:")
    captured = key.proof("POST", RESOURCE)
    call(gateway, token, captured)  # first use (legit)
    print("   ", call(gateway, token, captured))  # replay


if __name__ == "__main__":
    main()
