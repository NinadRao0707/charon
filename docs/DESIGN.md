# NHI Lifecycle Engine for AI Agents

**Working codename:** Charon — the ferryman that carries every non-human identity from
creation to decommissioning. (Rename freely.)

> A self-hostable control plane that manages the full lifecycle of AI-agent and machine
> identities: attestation, short-lived credential issuance, per-tool authorization for MCP,
> multi-hop delegation with provenance, proof-of-possession, and automated decommissioning.

---

## 1. Why this project exists (the gap)

Employee identity is a solved, mature market. **Non-human identity (NHI)** — the API keys,
service accounts, workloads, and now AI agents that act without a human in the loop — is not.
2025 was the year NHI became a named security category; AI-agent identity specifically is still
an open research and standards problem as of 2026.

Where the existing landscape sits:

| Layer | Examples | What they cover | What they leave open |
|---|---|---|---|
| Commercial SaaS | Astrix, Oasis, Token Security, Akeyless, Saviynt, ManageEngine PAM360 | Discovery, posture, rotation, decommissioning across cloud/SaaS/CI-CD | Closed-source, enterprise-priced; AI-agent + MCP support still maturing |
| OSS plumbing | SPIFFE/SPIRE, HashiCorp Vault, Teleport | Workload identity issuance & attestation; secrets; RBAC | The *governance/lifecycle* layer above the plumbing is left to you |
| Standards (forming) | NIST AI Agent Standards Initiative, IETF WIMSE/AIMS, MCP-I, OWASP MCP Top 10 | Defining what agent identity *should* be | Not yet implemented or operationalized |

**Documented, still-unsolved technical gaps this project targets:**

1. **No per-tool authentication in MCP** — once an agent authenticates to an MCP server it
   implicitly gets *every* tool that server exposes. Confused-deputy risk follows.
2. **One-hop-only delegation** — OAuth 2.0 handles single delegation but lacks multi-hop
   chaining and any mapping between scopes and agent capabilities.
3. **Zombie / orphan identities** — agents spin up and vanish; un-decommissioned identities
   become permanent backdoors.
4. **No provenance** — when an agent acts, there's often no verifiable trail back to the human
   who authorized it.

This project is *not* "another NHI platform." It is a focused, buildable **lifecycle engine for
AI-agent identities** that fills those four gaps using real, current standards.

---

## 2. Architecture

```
                            ┌─────────────────────────────────────┐
                            │        Control Plane (FastAPI)       │
                            │                                      │
   register / rotate /      │  ┌────────────┐   ┌───────────────┐  │
   revoke  ───────────────► │  │  Identity  │   │   Lifecycle   │  │
                            │  │  Registry  │◄─►│ State Machine  │  │
                            │  └────────────┘   └───────────────┘  │
                            │  ┌────────────┐   ┌───────────────┐  │
   attest + request cred ──►│  │ Attestation│──►│  Credential   │  │──► short-lived
                            │  │   layer    │   │   Authority   │  │    JWT-SVID
                            │  └────────────┘   └───────────────┘  │
                            │  ┌────────────┐   ┌───────────────┐  │
                            │  │  Reaper    │   │  Audit Log     │  │  (hash-chained)
                            │  │ (scheduler)│   │  (append-only) │  │
                            │  └────────────┘   └───────────────┘  │
                            └───────────────┬─────────────────────┘
                                            │ /authorize (per tool call)
                                            ▼
   AI agent ──► MCP Authorization Gateway ──► Policy Engine (OPA / Rego) ──► allow/deny
                  (speaks MCP protocol)                                       │
                       │ allowed calls forwarded                              │
                       ▼                                                      │
                  Toy MCP servers (filesystem, payments, email)               │
                                                                              │
   agent A ──calls──► agent B : RFC 8693 token exchange adds `act` claim ─────┘
                                (delegation chain / provenance)
```

### Components

1. **Identity Registry** — every agent is a first-class object: `id`, `spiffe_id`, human
   `owner`, `purpose`, granted `scopes`, `parent_identity` (for delegation), `created_at`,
   `last_seen`, `state`. Backed by Postgres (SQLite for local dev).

2. **Lifecycle State Machine** — `PROVISIONED → ACTIVE → IDLE → REVOKED → DECOMMISSIONED`.
   Every transition is logged and policy-gated. This *is* the "lifecycle engine."

3. **Attestation layer** — verify the workload **before** issuing a credential (solves the
   "secret zero" problem). Implement at least one real attestor: Kubernetes ServiceAccount
   token, a one-time join token, or process attestation. Never issue to an un-attested caller.

4. **Credential Authority** — issues **short-lived, scoped** credentials. Use SPIFFE naming
   (`spiffe://your-trust-domain/agent/<uuid>`) and JWT-SVIDs with a `scope`/capability claim,
   signed by a local CA key. Supports rotation and revocation. *Stretch:* replace the
   hand-rolled issuer with real **SPIRE** via the `py-spiffe` SDK.

5. **MCP Authorization Gateway** — an MCP proxy that intercepts each `tools/call`, extracts the
   presented credential, and calls the policy engine **per tool**. Allowed calls forwarded to
   the real MCP server; denied calls rejected and logged. This closes the all-or-nothing gap.

6. **Policy Engine** — Open Policy Agent (OPA) with Rego policies mapping
   `scope → capability → specific MCP tool`. Enforces least privilege. *(Cedar via `cedarpy`
   is a strong alternative and a nice differentiator if you want to show range.)*

7. **Delegation / Token Exchange** — implement **RFC 8693 OAuth 2.0 Token Exchange**. When
   agent A delegates to agent B, B's token carries a nested `act` (actor) claim chain so any
   multi-hop workflow traces back to the originating human. This is your provenance story.

8. **DPoP (RFC 9449)** — bind issued tokens to a client key (proof-of-possession) so a stolen
   token cannot be replayed. High-value depth signal.

9. **Reaper** — APScheduler/async job that detects **idle** (no `last_seen` within TTL),
   **orphaned** (owner gone), and **drifted** (granted scope >> used scope) identities, then
   transitions them toward decommission automatically.

10. **Audit log** — append-only, **hash-chained** (each entry includes the hash of the prior
    entry) for tamper evidence. Every issuance, authz decision, and lifecycle transition.

11. **Dashboard** — minimal (FastAPI + HTMX/Jinja, or a small React page). Show the live
    identity inventory, lifecycle timeline, and a delegation graph (vis.js/D3). Keep it lean —
    your signal is identity, not front-end.

---

## 3. Tech stack (Python)

| Concern | Choice |
|---|---|
| API / gateway | FastAPI + Uvicorn |
| Workload identity | `py-spiffe` (official SPIFFE SDK) + SPIRE server/agent |
| MCP | official `mcp` Python SDK (gateway proxy + toy servers) |
| Tokens / OAuth / DPoP | `authlib`, `pyjwt`, `cryptography` |
| Policy | Open Policy Agent (OPA) sidecar with Rego (or `cedarpy`) |
| Storage | SQLModel/SQLAlchemy + Postgres (SQLite for dev) |
| Scheduling | APScheduler |
| Orchestration | Docker Compose (SPIRE + control plane + gateway + toy MCP servers + Postgres) |
| Tests | pytest, plus a small adversarial/abuse-case suite |

---

## 4. Semester roadmap (~14 weeks)

**Phase 0 — Foundations (Week 1)**
Repo, README, this design doc. Write a short **threat model** and map it to the **OWASP MCP
Top 10** and the open questions in NIST's AI Agent Standards Initiative. This framing is what
makes the project read as security work rather than a CRUD app.

**Phase 1 — Identity Registry + Lifecycle (Weeks 2–3)**
Agent objects, Postgres schema, CRUD, and the lifecycle state machine with gated transitions.

**Phase 2 — Credential Authority (Weeks 4–5)**
Short-lived JWT-SVIDs, SPIFFE naming, scope claims, rotation, revocation list.

**Phase 3 — Attestation (Weeks 6–7)**
At least one real attestor. Refuse issuance without successful attestation. Document why.

**Phase 4 — MCP Gateway + Policy (Weeks 8–9)**
Build 2–3 toy MCP servers (filesystem, payments, email). Gateway authorizes each tool call via
OPA. **Demo milestone:** an agent scoped to "read files" is *blocked* from calling a payment tool.

**Phase 5 — Delegation + Provenance (Weeks 10–11)**
RFC 8693 token exchange, `act` claim chains, delegation graph in the dashboard.
**Demo milestone:** trace a 3-hop agent action back to the originating human.

**Phase 6 — Reaper + Dashboard (Week 12)**
Idle/orphan/drift detection and auto-decommission. Inventory + lifecycle + delegation views.

**Phase 7 — Hardening (Weeks 13–14)**
DPoP proof-of-possession; swap hand-rolled issuer for real SPIRE; hash-chained audit log;
adversarial test suite (replay, token theft, scope escalation, confused-deputy).

**Phase 8 — Polish & writeup (ongoing / final)**
README with architecture diagram, 3-minute demo video (the two blocked-call and provenance
demos are the money shots), and a short post positioning the work against the NIST/OWASP gaps.

---

## 5. What makes this read as "identity depth"

- Real standards, not approximations: **SPIFFE/SPIRE, OAuth 2.0 Token Exchange (RFC 8693),
  DPoP (RFC 9449), OAuth 2.1, RFC 9728** protected-resource metadata.
- **Attestation before issuance** — you understand the secret-zero / bottom-turtle problem.
- **Least privilege** via scope→capability→tool mapping, enforced at runtime.
- **Non-repudiation / provenance** via delegation chains.
- **Tamper-evident auditing** via a hash-chained log.
- A written **threat model** mapped to OWASP MCP Top 10.

---

## 6. Resume framing

Pick 2–3 bullets; lead with the gap and the standards:

- *Designed and built an open-source lifecycle engine for AI-agent / non-human identities in
  Python (FastAPI, SPIFFE/SPIRE), issuing short-lived attested credentials in place of static
  API keys to eliminate orphaned "zombie" identities.*
- *Implemented per-tool authorization for Model Context Protocol (MCP) via an OPA-backed
  gateway, closing the all-or-nothing access gap and enforcing least privilege on autonomous
  agent tool calls.*
- *Built multi-hop delegation using OAuth 2.0 Token Exchange (RFC 8693) with DPoP
  proof-of-possession (RFC 9449), producing a verifiable provenance chain from any agent action
  back to the authorizing human.*
- *Authored a threat model mapped to the OWASP MCP Top 10 and an adversarial test suite
  covering token replay, scope escalation, and confused-deputy attacks.*

---

## 7. Key references

- arXiv 2026, "AI Identity: Standards, Gaps, and ..." — survey of the exact landscape
  (WIMSE/SPIFFE, IETF AIMS, MCP-I, OAuth limitations). Read this first.
- SPIFFE/SPIRE docs (spiffe.io) + `py-spiffe` SDK.
- RFC 8693 (OAuth 2.0 Token Exchange), RFC 9449 (DPoP), RFC 9728 (Protected Resource Metadata).
- OWASP MCP Top 10.
- NIST AI Agent Standards Initiative (2026).
- Model Context Protocol spec + official Python `mcp` SDK.
