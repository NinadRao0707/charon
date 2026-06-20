# Threat Model — Charon NHI Lifecycle Engine

*Phase 0 deliverable. This is what reframes the project from "a CRUD app with
JWTs" into security engineering: a stated set of assets, adversaries, trust
boundaries, and a mapping to the OWASP MCP Top 10 and the open questions in
NIST's AI Agent Standards work.*

> Numbering for the OWASP MCP Top 10 follows the beta living document
> (categories MCP01:2025–MCP10:2025, project lead Vandana Verma Sehgal). It is a
> community framework in beta; re-verify category numbers against
> `owasp.org/www-project-mcp-top-10` before citing them externally.

## 1. What we are protecting (assets)

- **The agent identities themselves** — the registry of who/what may act, who
  owns them, and what they are allowed to do.
- **Issued credentials** (JWT-SVIDs) and the **signing key** behind them. The
  signing key is the crown jewel: anyone holding it can mint any identity.
- **The authorization decision** — the mapping from a credential's scopes to the
  specific actions/tools it may invoke.
- **The audit trail** — the record of who did what, used for incident response,
  non-repudiation, and compliance.

## 2. Who we are defending against (adversaries)

- **A leaked or stolen credential.** An API key in a log, a token in a prompt,
  an env var exfiltrated by a compromised dependency.
- **A compromised or misbehaving agent.** The agent runs, but an attacker (via
  prompt injection or a hijacked tool) is steering it.
- **An over-privileged agent that drifts.** No attacker required — scope granted
  "just in case" months ago is now a standing liability.
- **An insider tampering with history** to hide an action after the fact.
- **An unattested impostor** trying to obtain a credential it should never get.

## 3. Trust boundaries

```
   human owner ──┐                          (Phase 4)
                 │ registers / authorizes      ▼
                 ▼                        MCP gateway ── tool calls ──> MCP servers
   [ Charon control plane ] ── issues ──> agent ──────┘
        │  signing key                    presents JWT-SVID
        │  registry + audit
        └─ trust boundary: nothing crosses without attestation + a valid,
           unrevoked, unexpired credential whose scope permits the action.
```

The control plane is trusted. Everything outside it — agents, networks, MCP
servers — is treated as potentially hostile.

## 4. Mapping to the OWASP MCP Top 10

| OWASP MCP risk | How Charon addresses it | Phase |
|---|---|---|
| **MCP01 — Token Mismanagement & Secret Exposure** | This is the project's center of gravity. No static, long-lived API keys: every credential is a short-lived (default 5 min) JWT-SVID with a unique `jti`, and a leaked token expires on its own and can be revoked immediately. | 2 ✅ |
| **Excessive Permissions / Privilege Escalation** | Scopes are explicit on the identity and embedded in the credential; the (Phase 4) gateway enforces scope→capability→tool least privilege. The reaper flags scope that exceeds observed usage (drift). | 2 (scopes) / 4 (enforcement) / 6 (drift) |
| **Authentication & Identity** | Workloads must pass **attestation** before any credential is issued; credentials are cryptographically verifiable SPIFFE JWT-SVIDs rather than bearer secrets. DPoP (Phase 7) binds tokens to a key to defeat replay. | 2/3 ✅, 7 (DPoP) |
| **Insufficient Logging & Monitoring** | Every registration, attestation, transition, issuance, rotation, and revocation is written to a **hash-chained, tamper-evident** audit log that can be independently verified. | 1/2 ✅ |
| **Shadow / Rogue identities & servers** | Identities are first-class registry objects with a known owner; orphaned identities (owner gone, no recent activity) are detected and auto-decommissioned by the reaper. | 1 (registry) / 6 (reaper) |
| **MCP03 — Tool Poisoning** | *Not mitigated by identity alone.* Out of scope for the credential engine; belongs to the Phase 4 gateway's tool-description inspection. Documented here as a known gap. | gap |
| **MCP05 — Injection (shell/SQL/command)** | *Out of scope.* Server-side input handling, not an identity control. Noted as a gap. | gap |
| **MCP06 — Intent Flow Subversion / confused deputy** | Partially: the Phase 5 delegation chain (`act` claims) makes the *authorizing* principal explicit and traceable, which constrains confused-deputy abuse, but does not stop prompt injection itself. | 5 (partial) |
| **MCP10 — Context Over-Sharing** | *Out of scope* for identity; a data-handling concern at the gateway/model layer. | gap |

Being explicit about what the project **does not** cover is itself part of the
security story — it shows you understand the boundary between identity controls
and the rest of the stack.

## 5. Mapping to NIST's open questions

NIST's AI Agent Standards Initiative (launched Feb 2026) asks, among other
things, whether existing standards (OAuth, SPIFFE, OpenID Connect) are
sufficient for agents or need extension. Charon takes a concrete position on
several of these:

- **"Are existing identity standards enough?"** — Charon *reuses* SPIFFE naming
  and JWT-SVIDs (proving they're a workable base) but *adds* a lifecycle state
  machine and scope-to-capability authorization that the base specs leave open.
- **"How should delegation work for agents?"** — Charon's Phase 5 answer is
  OAuth 2.0 Token Exchange (RFC 8693) with nested `act` claims for verifiable
  multi-hop provenance.
- **"How do agent identities get decommissioned?"** — the lifecycle state machine
  plus the reaper give an explicit, audited answer (no zombie identities).
- **Open question Charon does *not* answer:** behavioral runtime monitoring
  (detecting an agent that has "gone rogue" mid-session). Documented as future
  work; pairs with this engine rather than replacing it.

## 6. Residual risks (honest gaps)

- The signing key is a single point of compromise until SPIRE integration
  (Phase 7) distributes trust; protect it accordingly.
- Attestation in Phases 1–3 is a recorded flag, not a verified attestation
  document — strengthen in Phase 3 with a real attestor.
- Revocation is checked at verification time; an already-validated, still-valid
  token cannot be retracted mid-flight (mitigated by short TTLs).
