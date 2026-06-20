"""Phase 4 demo — the milestone: an agent scoped to read files is blocked from
calling a payment tool, while its permitted calls go through.

Run:  python demo_gateway.py
"""
from charon.attestation import JoinTokenAttestor
from charon.ca import CertificateAuthority
from charon.credentials import CredentialAuthority
from charon.mcp import EmailServer, FilesystemServer, MCPGateway, PaymentsServer
from charon.repository import SQLiteRepository
from charon.service import Registry

TRUST_DOMAIN = "charon.demo"


def call(gateway, token, name, args):
    return gateway.handle(
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {"name": name, "arguments": args},
            "credential": token,
        }
    )


def show(label, resp):
    if "error" in resp:
        print(f"  DENIED  {label}\n          -> {resp['error']['message']}")
    else:
        print(f"  ALLOWED {label}\n          -> {resp['result']}")


def main():
    repo = SQLiteRepository(":memory:")
    ca = CertificateAuthority()
    registry = Registry(repo, CredentialAuthority(ca, TRUST_DOMAIN), TRUST_DOMAIN)
    gateway = MCPGateway(
        registry, [FilesystemServer(), PaymentsServer(), EmailServer()]
    )

    # A least-privilege agent: it may read files and nothing else.
    attestor = JoinTokenAttestor()
    agent = registry.register(
        "report-reader",
        owner="alice@corp.example",
        purpose="summarize nightly reports",
        scopes=["fs:read"],
    )
    registry.attest(agent.id, attestor=attestor, evidence=attestor.mint())
    token = registry.issue_credential(agent.id)

    print(f"\nAgent {agent.spiffe_id}")
    print(f"  scopes = {agent.scopes}\n")

    print("Tool calls through the gateway:")
    show("filesystem.read_file /data/report.txt",
         call(gateway, token, "filesystem.read_file", {"path": "/data/report.txt"}))
    show("filesystem.read_file /etc/shadow (path escape)",
         call(gateway, token, "filesystem.read_file", {"path": "/etc/shadow"}))
    show("payments.charge $999  <-- the milestone",
         call(gateway, token, "payments.charge", {"amount": 999, "currency": "usd"}))
    show("email.send_email",
         call(gateway, token, "email.send_email", {"to": "x@y.com"}))

    print("\ntools/list only advertises tools this credential can use:")
    listing = gateway.handle(
        {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "credential": token}
    )
    print(f"  {[t['name'] for t in listing['result']['tools']]}")

    print("\nEvery decision is in the tamper-evident audit log:")
    for e in registry.audit_entries():
        if e.event.startswith("authz."):
            d = e.details
            print(f"  {e.event:<14} {d['server']}.{d['tool']:<12} {d['reason']}")
    print(f"\n  audit chain intact = {registry.audit_ok()}")


if __name__ == "__main__":
    main()
