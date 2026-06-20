# Charon — NHI Lifecycle Engine for AI Agents

A self-hostable control plane that manages the full lifecycle of **non-human
identities** (AI agents, workloads, automated processes): attestation,
short-lived credential issuance, gated lifecycle transitions, rotation,
revocation, and a tamper-evident audit trail — built on SPIFFE naming and JWT
SVIDs.

> Most enterprise tooling for this (Astrix, Oasis, Token Security, Akeyless) is
> closed and priced for enterprises; the open-source layer (SPIFFE/SPIRE, Vault,
> Teleport) gives you identity *plumbing* but leaves the lifecycle/governance
> layer to you. Charon is that layer, focused on the still-unsolved AI-agent
> frontier. See `docs/DESIGN.md` for the full landscape analysis and roadmap,
> and `docs/THREAT_MODEL.md` for the security framing.

## Status

| Phase | Scope | State |
|---|---|---|
| **0 — Foundations** | Repo, design doc, threat model mapped to OWASP MCP Top 10 + NIST questions | ✅ done |
| **1 — Identity Registry + Lifecycle** | Agent objects, persistence, CRUD, gated state machine, hash-chained audit | ✅ done |
| **2 — Credential Authority** | Short-lived JWT-SVIDs, SPIFFE naming, scope claims, rotation, revocation, key rotation | ✅ done |
| 3 — Attestation | Real attestor (k8s SA / join token / TPM) | next |
| 4 — MCP Gateway + Policy | per-tool authorization | planned |
| 5 — Delegation + Provenance | RFC 8693 token exchange, `act` chains | planned |
| 6 — Reaper + Dashboard | idle/orphan/drift auto-decommission | planned |
| 7 — Hardening | DPoP, SPIRE, adversarial tests | planned |

## Architecture (layered for testability)

```
charon/
  spiffe.py        SPIFFE ID construction / parsing
  lifecycle.py     state machine + gated transitions (pure, no I/O)
  models.py        domain dataclasses (persistence-independent)
  audit.py         hash-chained, tamper-evident audit log
  ca.py            Ed25519 signing authority + trust bundle (key rotation)
  credentials.py   Credential Authority: issue / verify / rotate / revoke JWT-SVIDs
  repository.py    Repository interface + stdlib-sqlite3 implementation (Postgres-ready)
  service.py       Registry: orchestrates lifecycle + attestation + audit + credentials
  api/main.py      FastAPI HTTP layer (thin adapter over service.py)
```

The security-critical logic (lifecycle, credentials, audit) depends only on
`PyJWT` + `cryptography` and is fully unit-tested. The web framework and database
are adapters at the edges, so they can be swapped (e.g. SQLite → Postgres, or the
self-signed CA → SPIRE in Phase 7) without touching the security core.

## Quick start

```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

# Run the end-to-end walkthrough (no DB or network needed):
python demo.py

# Run the tests:
python -m unittest discover -s tests        # or: pytest

# Run the HTTP API:
uvicorn charon.api.main:app --reload
# then open http://127.0.0.1:8000/docs
```

> The core (`demo.py`, all tests) runs with just `PyJWT` and `cryptography`.
> `fastapi`/`uvicorn` are only needed for the HTTP layer.

## What it does today (Phases 1–2)

1. **Register** a non-human identity with an owner, purpose, and scopes; it is
   assigned a SPIFFE ID (`spiffe://<trust-domain>/agent/<id>`) and starts
   `PROVISIONED`.
2. **Attest** the workload. Credentials and activation are *gated* on this — an
   un-attested identity gets nothing.
3. **Issue** a short-lived JWT-SVID carrying the agent's scopes; the first
   issuance activates the agent.
4. **Verify** credentials against the trust bundle, with audience, expiry, and
   revocation checks.
5. **Rotate** (issues fresh, revokes prior) and **revoke** credentials; **rotate
   the signing key** while keeping older tokens verifiable until they expire.
6. **Transition** through `PROVISIONED → ACTIVE → IDLE → REVOKED →
   DECOMMISSIONED`, with illegal transitions rejected.
7. Every operation is recorded in a **hash-chained audit log** whose integrity
   can be verified (`GET /audit` returns `intact: true/false`).

## HTTP endpoints

| Method | Path | Purpose |
|---|---|---|
| POST | `/agents` | register an identity |
| GET | `/agents` / `/agents/{id}` | inventory |
| POST | `/agents/{id}/attest` | attest a workload |
| POST | `/agents/{id}/transition` | gated lifecycle transition |
| POST | `/agents/{id}/credentials` | issue a JWT-SVID |
| POST | `/agents/{id}/credentials/rotate` | rotate |
| POST | `/agents/{id}/credentials/revoke` | revoke |
| POST | `/credentials/verify` | verify a token |
| GET | `/.well-known/charon/trust-bundle` | public keys for verifiers |
| GET | `/audit` | audit trail + integrity status |

## License

MIT (suggested). The OWASP MCP Top 10 material referenced in `docs/THREAT_MODEL.md`
is CC BY-NC-SA 4.0 and is only cited, not reproduced.
