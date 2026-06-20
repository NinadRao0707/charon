# Building an NHI Lifecycle Engine for AI Agents

*A writeup of Charon — what it is, why the problem matters, and where it sits
against the standards that are still being written.*

## The problem

Human identity management is a solved, mature market: you have an IdP, SSO, MFA,
joiner-mover-leaver workflows, and audits. Non-human identity is not. The API
keys, service accounts, workloads, and — increasingly — AI agents that act
without a person in the loop now vastly outnumber human accounts in most
environments, and the tooling for managing *their* whole lifecycle is young.

2025 was the year non-human identity (NHI) became a named security category.
Agentic AI made it urgent: agents authenticate to tools, call other agents, and
take actions on a human's behalf, often through the Model Context Protocol (MCP).
That introduces failure modes traditional IAM was never designed for — static
keys that never rotate, "zombie" identities that outlive their purpose, and
delegation chains with no record of who ultimately authorized an action.

Charon is a self-hostable control plane that manages that lifecycle end to end:
attestation, short-lived credentials, per-tool authorization for MCP, delegation
with provenance, proof-of-possession, automated decommissioning, and a
tamper-evident audit trail.

## Why not just use an existing product?

The enterprise market is real and crowded — Astrix, Oasis, Token Security,
Akeyless, and the large PAM/IAM vendors all play here. But those are closed and
priced for enterprises. The open-source layer (SPIFFE/SPIRE, Vault, Teleport)
gives you excellent identity *plumbing* — cryptographic workload identity,
secrets, attestation — but deliberately leaves the governance and lifecycle layer
above it to you. Charon is built to be that layer, and it builds *on* the
plumbing rather than reinventing it: it uses SPIFFE naming and JWT-SVIDs, and
ships a SPIRE adapter so SPIRE can be the production issuer.

## Where it sits against the standards being written

The standards for agent identity are actively in flux, which is exactly why this
was worth building. A few reference points:

**NIST's AI Agent Standards Initiative** (launched early 2026) asks whether
existing standards — OAuth, SPIFFE, OpenID Connect — are sufficient for agents,
or whether new ones are needed. Charon takes a concrete position: reuse SPIFFE
JWT-SVIDs for identity (they work), but add the things the base specs leave open
— a lifecycle state machine, scope-to-capability authorization, and a delegation
model. It also leaves one of NIST's questions explicitly unanswered: runtime
behavioral monitoring of an agent that has "gone rogue" mid-session is out of
scope and pairs with this engine rather than living inside it.

**The OWASP MCP Top 10** catalogs the failure modes of MCP deployments. Charon
maps cleanly onto several:

- *Token mismanagement and secret exposure* — addressed head-on: no static keys,
  only short-lived JWT-SVIDs, optionally bound to a client key via DPoP so theft
  doesn't help an attacker.
- *Excessive permissions / privilege escalation* — least-privilege scopes
  enforced per tool call at the gateway, with the reaper flagging drift.
- *Authentication and identity* — attestation before issuance; cryptographically
  verifiable credentials rather than bearer secrets.
- *Insufficient logging* — a hash-chained audit log that detects tampering.

And it is honest about what it does **not** cover. Tool poisoning, prompt
injection, and context over-sharing are real MCP risks that live at the model and
tool-description layer, not the identity layer. Charon's gateway authorizes
*calls*, not the trustworthiness of a tool's description or the content of its
responses. Saying so is part of the design.

**RFC building blocks.** Rather than invent a token format, Charon uses
established specs where they fit: SPIFFE for naming, JWT-SVIDs for the credential,
RFC 8693 (OAuth 2.0 Token Exchange) for multi-hop delegation with `act`-claim
chains, RFC 9449 (DPoP) for proof-of-possession, and RFC 7638 for key
thumbprints. The interesting work was composing them into a coherent lifecycle.

## What the demos show

Two moments capture the whole thing. First, an agent scoped only to read files is
*blocked* at the gateway from calling a payment tool — least privilege enforced
per call, not per server. Second, a three-hop agent chain
(`human -> A -> B -> C`) is traced from the final agent's credential all the way
back to the originating human — provenance that survives delegation. A third
shows a stolen, DPoP-bound token being rejected for everyone but the key-holder.

## What I'd build next

The natural extensions are runtime behavioral monitoring (the half Charon
deliberately doesn't do), a Postgres-backed repository for scale, and richer
attestation (TPM, cloud instance identity). But the core thesis stands: the
agent-identity frontier needs a lifecycle layer, the cryptographic primitives to
build it already exist, and the work is in composing them with honest boundaries.
