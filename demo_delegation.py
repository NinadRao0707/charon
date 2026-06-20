"""Phase 5 + 6 demo.

Run:  python demo_delegation.py

Part 1 builds a human -> A -> B -> C delegation chain via RFC 8693 token
exchange, runs a delegated action through the gateway, and traces it back to the
originating human. Part 2 runs the reaper over a population of identities.
"""
from charon.attestation import DevAttestor
from charon.ca import CertificateAuthority
from charon.credentials import CredentialAuthority
from charon.mcp import FilesystemServer, MCPGateway, PaymentsServer
from charon.reaper import Reaper
from charon.repository import SQLiteRepository
from charon.service import Registry

TRUST_DOMAIN = "charon.demo"
HUMAN = "user:alice@corp.example"


def setup():
    repo = SQLiteRepository(":memory:")
    ca = CertificateAuthority()
    return Registry(repo, CredentialAuthority(ca, TRUST_DOMAIN), TRUST_DOMAIN)


def agent(reg, name, scopes):
    a = reg.register(name, HUMAN, "demo", scopes=scopes)
    reg.attest(a.id, attestor=DevAttestor())
    return a, reg.issue_credential(a.id)


def part1_delegation():
    print("\n=== Phase 5: delegation + provenance ===")
    reg = setup()
    gateway = MCPGateway(reg, [PaymentsServer()])

    a, a_tok = agent(reg, "orchestrator", ["pay:charge", "fs:read"])
    b, b_tok = agent(reg, "planner", ["pay:charge"])
    c, c_tok = agent(reg, "executor", ["pay:charge"])

    # human authorizes A; A -> B -> C, narrowing scope to just pay:charge
    obo = reg.begin_on_behalf_of(HUMAN, a_tok, ["pay:charge"])
    hop2 = reg.delegate(obo, b_tok, ["pay:charge"])
    hop3 = reg.delegate(hop2, c_tok, ["pay:charge"])

    print(f"  chain: {reg.trace(hop3)}")

    resp = gateway.handle({
        "jsonrpc": "2.0", "id": 1, "method": "tools/call",
        "params": {"name": "payments.charge", "arguments": {"amount": 42}},
        "credential": hop3,
    })
    print(f"  executor's charge call -> {'ALLOWED' if 'result' in resp else 'DENIED'}")

    authz = [e for e in reg.audit_entries() if e.event == "authz.allowed"][-1]
    print(f"  audited actor    : {authz.subject}")
    print(f"  audited provenance: {authz.details['provenance']}")

    print("\n  delegation edges (for the dashboard graph):")
    for d in reg.list_delegations():
        print(f"    {d.delegator}  ->  {d.delegate}   [{d.scope}]")


def part2_reaper():
    print("\n=== Phase 6: reaper sweep ===")
    import time
    reg = setup()
    gateway = MCPGateway(reg, [FilesystemServer(), PaymentsServer()])

    quiet, _ = agent(reg, "forgotten-bot", ["fs:read"])
    orphan, _ = agent(reg, "ex-employee-bot", ["fs:read"])
    # reassign owner to simulate departure
    o = reg.get(orphan.id); o.owner = "bob@corp.example"; reg._repo.update_agent(o)  # noqa: SLF001
    drifter, d_tok = agent(reg, "over-scoped-bot", ["fs:read", "pay:charge"])
    gateway.handle({
        "jsonrpc": "2.0", "id": 1, "method": "tools/call",
        "params": {"name": "filesystem.read_file", "arguments": {"path": "/data/x"}},
        "credential": d_tok,
    })  # uses only fs:read -> pay:charge is drift

    reaper = Reaper(reg, idle_after=86_400, departed_owners={"bob@corp.example"})
    actions = reaper.run_once(now=time.time() + 2 * 86_400)
    for a in actions:
        print(f"  {a.action:<22} {a.name:<18} {a.detail}")

    print("\n  states after reaping:")
    for ag in reg.list():
        print(f"    {ag.name:<18} {ag.state.value}")
    print(f"\n  audit chain intact = {reg.audit_ok()}")


if __name__ == "__main__":
    part1_delegation()
    part2_reaper()
