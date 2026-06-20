# Charon — NHI Lifecycle Engine for AI Agents

A self-hostable control plane that manages the full lifecycle of **non-human
identities** (AI agents, workloads, automated processes): attestation,
short-lived credential issuance, gated lifecycle transitions, per-tool
authorization for the Model Context Protocol (MCP), delegation with provenance,
proof-of-possession, automated decommissioning, and a tamper-evident audit
trail — built on SPIFFE naming, JWT-SVIDs, and established OAuth RFCs.

> Human identity management is a mature, solved market. Non-human identity — the
> API keys, service accounts, and AI agents that act without a person in the loop
> — is not. Enterprise NHI products are closed and priced for enterprises, and the
> open-source layer (SPIFFE/SPIRE, Vault, Teleport) provides excellent identity
> *plumbing* but leaves the lifecycle and governance layer to you. Charon is that
> layer, focused on the AI-agent frontier, and it builds *on* the plumbing rather
> than reinventing it.

Built on real standards: **SPIFFE** naming and **JWT-SVIDs**, **RFC 8693** (OAuth
2.0 Token Exchange) for multi-hop delegation, **RFC 9449** (DPoP) for
proof-of-possession, and **RFC 7638** for key thumbprints. **84 tests passing**,
including an adversarial suite; four runnable demos and a live dashboard.

## Capabilities

**Attested issuance, not bearer secrets.** A workload must prove itself before it
gets a credential. `JoinTokenAttestor` issues single-use, expiring tokens;
`K8sServiceAccountAttestor` verifies a projected Kubernetes service-account JWT
against the cluster's keys and extracts namespace/service-account selectors.
Attestation carries a TTL, so identities must periodically re-prove themselves,
and issuance is refused without a fresh attestation on record. Selectors can be
*bound* so a credential for one workload identity can't be obtained by another.

**Short-lived, scoped credentials.** Every credential is a SPIFFE JWT-SVID
(`spiffe://<trust-domain>/agent/<id>`) with an explicit scope claim and a short
TTL — no static, long-lived API keys. Rotation issues a fresh credential and
revokes the prior one; the signing key can be rotated while older tokens remain
verifiable until they expire; revoked credentials are rejected at verification.

**A real lifecycle.** Identities move through
`PROVISIONED → ACTIVE → IDLE → REVOKED → DECOMMISSIONED` via a state machine that
rejects illegal transitions and gates activation on attestation.

**Per-tool authorization for MCP.** The gateway fronts MCP servers and authorizes
every individual `tools/call` against the credential's scopes and argument-level
constraints (path confinement, amount caps) — closing MCP's structural
all-or-nothing access gap. `tools/list` advertises only the tools a credential
can actually invoke. Policy runs in a dependency-free embedded engine by default,
or in [OPA](https://www.openpolicyagent.org) via `policies/authz.rego`.

**Delegation with provenance.** Using RFC 8693 token exchange, one agent can act
on behalf of another while preserving the originating human as `sub` and nesting
each actor in the `act` claim. Authority only ever *narrows* down a chain. Any
action — even three hops deep — can be traced back to the human who authorized it.

**Proof-of-possession (DPoP).** Credentials can be bound to a client key via a
`cnf.jkt` claim; the gateway then requires a fresh, method- and URL-bound,
single-use DPoP proof on every call. A stolen token is useless without the key,
and a captured proof cannot be replayed.

**Automated cleanup.** The reaper moves inactive agents to `IDLE`, decommissions
long-idle ones, revokes-and-decommissions orphaned agents whose owner has
departed, and flags privilege drift (granted scopes never exercised).

**Tamper-evident auditing.** Every registration, attestation, transition,
issuance, rotation, revocation, and authorization decision is written to a
hash-chained audit log that detects any modification of historical records.

**Dashboard.** A single page showing lifecycle counts, the identity inventory,
the delegation graph, a reaper preview, and the live audit feed with
chain-integrity status.

## Architecture

```mermaid
flowchart LR
    H([human owner]) -->|registers / authorizes| CP
    subgraph CP[Charon control plane]
        REG[Registry + lifecycle state machine]
        ATT[Attestation: join-token / k8s SA]
        CA[Credential Authority - JWT-SVIDs + DPoP cnf]
        DEL[Delegation - RFC 8693 act-chains]
        REAP[Reaper - idle / orphan / drift]
        AUD[(Hash-chained audit log)]
        REG --- ATT --- CA --- DEL --- REAP
        REG -.writes.-> AUD
    end
    CA -->|short-lived JWT-SVID| AG([AI agent / workload])
    AG -->|JWT-SVID + DPoP proof| GW
    subgraph GWX[ ]
        GW[MCP Authorization Gateway] -->|per-tool decision| POL[Policy engine - embedded / OPA]
    end
    GW -->|allowed calls only| MCP[(MCP servers: filesystem / payments / email)]
    GW -.authz decisions.-> AUD
    DASH[Dashboard at /] -.reads.-> CP
    SPIRE[[SPIRE - production CA swap]] -.verifies SVIDs.-> GW
```

The security-critical logic depends only on `PyJWT` and `cryptography` and is
fully unit-tested in isolation. The web framework and database sit at the edges as
thin adapters, so they can be swapped (SQLite → Postgres, or the self-signed CA →
SPIRE) without touching the security core.

```
charon/
  spiffe.py        SPIFFE ID construction / parsing
  lifecycle.py     state machine + gated transitions (pure, no I/O)
  models.py        domain dataclasses (persistence-independent)
  audit.py         hash-chained, tamper-evident audit log
  ca.py            Ed25519 signing authority + trust bundle (persistable, rotatable)
  credentials.py   Credential Authority: issue / verify / rotate / revoke JWT-SVIDs
  attestation.py   pluggable attestors: join-token, k8s SA JWT, dev
  delegation.py    RFC 8693 token exchange + act-claim chains + provenance
  dpop.py          DPoP proof-of-possession: RFC 9449 + RFC 7638 thumbprints
  spire.py         SPIRE integration adapter (py-spiffe) — production CA swap
  reaper.py        idle / orphan / drift detection + auto-decommission
  policy.py        authorization engines: embedded (default) + OPA-backed
  repository.py    Repository interface + stdlib-sqlite3 implementation (Postgres-ready)
  service.py       Registry: orchestrates lifecycle + attestation + delegation + audit
  mcp/servers.py   example MCP servers: filesystem, payments, email
  mcp/gateway.py   MCP authorization gateway: per-tool authz enforcement point
  mcp/stdio_server.py  real MCP-SDK entrypoint wrapping the gateway
  api/main.py      FastAPI HTTP layer (thin adapter over service.py)
  api/dashboard.py single-page dashboard: inventory + lifecycle + delegation graph
  policies/authz.rego  Rego policy mirroring the embedded engine (for OPA)
```

## Quick start

```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

# Run the tests:
python -m unittest discover -s tests        # or: pytest

# Self-contained walkthroughs (no DB or network needed):
python demo.py            # lifecycle: attest, issue, rotate, revoke, audit
python demo_gateway.py    # per-tool authorization (read-only agent blocked from payments)
python demo_delegation.py # delegation provenance (human -> A -> B -> C) + reaper sweep
python demo_hardening.py  # DPoP defeats token theft + replay

# Run the HTTP control-plane API + dashboard:
uvicorn charon.api.main:app --reload
# then open http://127.0.0.1:8000/        (dashboard)
#       and http://127.0.0.1:8000/docs    (interactive API)
```

State persists in `charon.db` and the signing key in `charon_signing_key.pem`
(override paths with `CHARON_DB` / `CHARON_SIGNING_KEY`), so issued credentials
survive a restart. The core (tests and all four demos) runs with only `PyJWT` and
`cryptography`; `fastapi`/`uvicorn` are needed only for the HTTP layer.

**Optional integrations:** install `mcp` and run `python -m charon.mcp.stdio_server`
to expose the gateway as a real MCP server; run `opa run --server policies/` and
construct `MCPGateway(..., policy=OpaPolicyEngine())` to use OPA; run SPIRE and pass
`charon.spire.SpireJwtVerifier` as the gateway's verifier to make SPIRE the issuer.

## Highlighted demos

- **Least privilege** (`demo_gateway.py`): an agent scoped to `fs:read` reads files
  under `/data` but is denied `payments.charge` (missing scope), denied
  `/etc/shadow` (path escape), and never even sees the tools it can't call.
- **Provenance** (`demo_delegation.py`): a `human -> A -> B -> C` chain, traced from
  the final agent's credential all the way back to the originating human.
- **Proof-of-possession** (`demo_hardening.py`): the same stolen token is allowed
  for the key-holder and denied for everyone else (no proof / wrong key / replay).

## HTTP API

| Method | Path | Purpose |
|---|---|---|
| POST | `/agents` | register an identity |
| GET | `/agents` / `/agents/{id}` | inventory |
| POST | `/agents/{id}/attest` | attest a workload |
| POST | `/agents/{id}/transition` | gated lifecycle transition |
| POST | `/agents/{id}/credentials` | issue a JWT-SVID (optionally DPoP-bound) |
| POST | `/agents/{id}/credentials/rotate` | rotate |
| POST | `/agents/{id}/credentials/revoke` | revoke |
| POST | `/credentials/verify` | verify a token |
| POST | `/delegation/begin` | start a chain (agent on behalf of a human) |
| POST | `/delegation/exchange` | RFC 8693 token exchange (further hops) |
| POST | `/delegation/trace` | reconstruct a credential's provenance path |
| GET | `/delegations` | delegation edges (for the graph) |
| POST | `/reaper/run` | run the reaper (apply or dry-run) |
| POST | `/mcp/tools` | list tools the credential may call (via the gateway) |
| POST | `/mcp/call` | authorize + forward a single tool call |
| GET | `/` | dashboard |
| GET | `/.well-known/charon/trust-bundle` | public keys for verifiers |
| GET | `/audit` | audit trail + integrity status |

## Security model

Charon assumes the control plane is trusted and treats everything outside it —
agents, networks, MCP servers — as potentially hostile. Nothing crosses the trust
boundary without attestation plus a valid, unrevoked, unexpired credential whose
scope permits the action. It deliberately does **not** address risks that live at
the model and tool layer rather than the identity layer (tool-description
poisoning, prompt injection, context over-sharing) or runtime behavioral
monitoring of a compromised agent — those pair with an identity engine rather than
belonging inside it. See `docs/THREAT_MODEL.md` for the full analysis, including a
mapping to the OWASP MCP Top 10.

## Documentation

- `docs/DESIGN.md` — design and landscape analysis
- `docs/THREAT_MODEL.md` — assets, adversaries, and the OWASP MCP Top 10 / NIST mapping
- `docs/BLOG.md` — where Charon fits against the emerging agent-identity standards

## License

MIT — see the `LICENSE` file. The OWASP MCP Top 10 material referenced in
`docs/THREAT_MODEL.md` is CC BY-NC-SA 4.0 and is only cited, not reproduced.
