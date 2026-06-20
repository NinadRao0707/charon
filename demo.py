"""End-to-end walkthrough of Phases 1-2.

Run with:  python demo.py

Exercises: register -> attest -> issue -> verify -> rotate -> revoke ->
lifecycle transitions -> tamper-evident audit. No external services required.
"""
from charon import CertificateAuthority, CredentialAuthority, LifecycleState, Registry
from charon.credentials import CredentialRevoked, NotIssuable
from charon.lifecycle import TransitionGuardFailed
from charon.repository import SQLiteRepository

TRUST_DOMAIN = "charon.demo"


def line(title):
    print(f"\n=== {title} ===")


def main():
    repo = SQLiteRepository(":memory:")
    ca = CertificateAuthority()
    authority = CredentialAuthority(ca, TRUST_DOMAIN, ttl_seconds=300)
    reg = Registry(repo, authority, TRUST_DOMAIN)

    line("1. Register a non-human identity")
    agent = reg.register(
        name="invoice-reconciler",
        owner="alice@corp.example",
        purpose="reconcile invoices nightly",
        scopes=["read:invoices", "list:vendors"],
    )
    print(f"  id        = {agent.id}")
    print(f"  spiffe_id = {agent.spiffe_id}")
    print(f"  state     = {agent.state.value}")

    line("2. Attempt to issue a credential BEFORE attestation (should fail)")
    try:
        reg.issue_credential(agent.id)
    except NotIssuable as e:
        print(f"  blocked as expected: {e}")

    line("3. Attempt to activate BEFORE attestation (gated transition, should fail)")
    try:
        reg.transition(agent.id, LifecycleState.ACTIVE)
    except TransitionGuardFailed as e:
        print(f"  blocked as expected: {e}")

    line("4. Attest the workload, then issue a short-lived JWT-SVID")
    reg.attest(agent.id, method="k8s-service-account")
    token = reg.issue_credential(agent.id)
    print(f"  state now = {reg.get(agent.id).state.value}  (activated by first credential)")
    claims = reg.verify_credential(token)
    print(f"  verified sub   = {claims['sub']}")
    print(f"  verified scope = {claims['scope']}")
    print(f"  jti            = {claims['jti']}")

    line("5. Rotate the credential (old one is revoked)")
    import time

    time.sleep(1)
    new_token = reg.rotate_credential(agent.id, previous_token=token)
    try:
        reg.verify_credential(token)
    except CredentialRevoked as e:
        print(f"  old credential rejected: {e}")
    print(f"  new credential sub = {reg.verify_credential(new_token)['sub']}")

    line("6. Revoke on suspected compromise")
    reg.revoke_credential(agent.id, new_token, reason="leaked in logs")
    try:
        reg.verify_credential(new_token)
    except CredentialRevoked as e:
        print(f"  revoked credential rejected: {e}")

    line("7. Lifecycle: ACTIVE -> IDLE -> REVOKED -> DECOMMISSIONED")
    reg.transition(agent.id, LifecycleState.IDLE, reason="no activity 24h")
    reg.transition(agent.id, LifecycleState.REVOKED, reason="owner offboarded")
    reg.transition(agent.id, LifecycleState.DECOMMISSIONED, reason="cleanup")
    print(f"  final state = {reg.get(agent.id).state.value}")

    line("8. Tamper-evident audit trail")
    for e in reg.audit_entries():
        print(f"  #{e.seq} {e.event:<22} {e.subject[:8]}  {e.details}")
    print(f"  audit chain intact = {reg.audit_ok()}")


if __name__ == "__main__":
    main()
