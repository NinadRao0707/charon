# 3-Minute Demo Script

A storyboard for recording a short walkthrough. The two "money shots" are the
**blocked payment call** (least privilege) and the **3-hop provenance trace**.
Keep terminal font large; pre-run `pip install -r requirements.txt`.

---

### 0:00 – 0:25 · The problem (talking head or title card)
> "Human identity is solved. Non-human identity — the API keys and AI agents
> acting on their own — isn't. This is Charon: a lifecycle engine that manages
> AI-agent identities from attestation to decommissioning. Everything you'll see
> runs locally with no external services."

Show the README architecture diagram on screen.

### 0:25 – 1:05 · Lifecycle + credentials  (`python demo.py`)
Run it. Narrate while output scrolls:
> "An agent is registered, gets a SPIFFE ID, and starts un-attested. Watch —
> issuing a credential before attestation is refused. After it attests, it gets a
> short-lived JWT-SVID, not a static key. Rotating revokes the old one. And every
> action lands in a hash-chained audit log that verifies its own integrity."

Point at the final `audit chain intact = True`.

### 1:05 – 1:45 · MONEY SHOT 1 — per-tool authorization  (`python demo_gateway.py`)
> "Here's the gap Charon closes. In plain MCP, once an agent reaches a server it
> can call any tool. This agent is scoped to read files only."

Point at each line:
> "It reads a file — allowed. It tries to read /etc/shadow — blocked, path
> escape. It tries to charge a card — **blocked, missing scope.** And the tool
> list only shows it the tools it can actually use."

### 1:45 – 2:30 · MONEY SHOT 2 — delegation provenance  (`python demo_delegation.py`)
> "Agents delegate to other agents. Using RFC 8693 token exchange, authority
> flows human → orchestrator → planner → executor, narrowing at each hop."

Point at the trace line:
> "From the executor's credential alone, we trace the whole chain back to the
> originating human. The gateway records that provenance on every action."

Then scroll to the reaper output:
> "And the reaper sweeps up the mess automatically — idling quiet agents,
> decommissioning an orphan whose owner left, and flagging an over-scoped agent."

### 2:30 – 2:50 · Hardening  (`python demo_hardening.py`)
> "Tokens can be bound to a key with DPoP. So when this token is stolen — no
> proof, wrong key, or a replayed proof — it's rejected. Only the real key-holder
> gets in."

### 2:50 – 3:00 · Close
> "SPIFFE, OAuth token exchange, DPoP — composed into a lifecycle engine for the
> agent-identity frontier. 81 tests, including an adversarial suite. Code and
> writeup in the repo."

Show the dashboard at `http://127.0.0.1:8000/` (delegation graph) as the final
frame if time allows.

---

**Pre-flight checklist**
- [ ] `python -m unittest discover -s tests` is green (shows 81 passing)
- [ ] terminal width ≥ 100 cols, large font
- [ ] `uvicorn charon.api.main:app` running if you show the dashboard
- [ ] screen recorder set to 1080p
