"""FastAPI HTTP layer.

A thin adapter over the domain services. All security logic lives in
charon.service / charon.credentials / charon.lifecycle; this module only does
request/response plumbing.

Run:  uvicorn charon.api.main:app --reload
Docs: http://127.0.0.1:8000/docs
"""
from __future__ import annotations

import os

from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, Field

from charon.attestation import AttestationError, DevAttestor
from charon.ca import CertificateAuthority
from charon.credentials import CredentialAuthority, CredentialError, NotIssuable
from charon.delegation import DelegationError
from charon.lifecycle import (
    IllegalTransition,
    LifecycleState,
    TransitionGuardFailed,
)
from charon.reaper import Reaper
from charon.repository import SQLiteRepository
from charon.service import Registry, UnknownAgent

from .dashboard import DASHBOARD_HTML

TRUST_DOMAIN = os.environ.get("CHARON_TRUST_DOMAIN", "charon.local")
DB_PATH = os.environ.get("CHARON_DB", "charon.db")

# --- composition root --------------------------------------------------------
_repo = SQLiteRepository(DB_PATH)
_ca = CertificateAuthority()
_authority = CredentialAuthority(_ca, TRUST_DOMAIN)
_registry = Registry(_repo, _authority, TRUST_DOMAIN)

app = FastAPI(title="Charon — NHI Lifecycle Engine", version="0.1.0")


# --- schemas -----------------------------------------------------------------
class RegisterRequest(BaseModel):
    name: str
    owner: str
    purpose: str
    scopes: list[str] = Field(default_factory=list)
    parent_id: str | None = None


class AttestRequest(BaseModel):
    method: str = "join-token"


class TransitionRequest(BaseModel):
    target: LifecycleState
    reason: str | None = None


class RevokeRequest(BaseModel):
    token: str
    reason: str | None = None


class VerifyRequest(BaseModel):
    token: str


class RotateRequest(BaseModel):
    previous_token: str | None = None


def _agent_dto(agent) -> dict:
    return {
        "id": agent.id,
        "name": agent.name,
        "owner": agent.owner,
        "purpose": agent.purpose,
        "scopes": agent.scopes,
        "parent_id": agent.parent_id,
        "spiffe_id": agent.spiffe_id,
        "state": agent.state.value,
        "attested": agent.attested,
        "created_at": agent.created_at,
        "last_seen": agent.last_seen,
    }


# --- agent lifecycle ---------------------------------------------------------
@app.post("/agents", status_code=201)
def register_agent(req: RegisterRequest):
    agent = _registry.register(
        req.name, req.owner, req.purpose, req.scopes, req.parent_id
    )
    return _agent_dto(agent)


@app.get("/agents")
def list_agents():
    return [_agent_dto(a) for a in _registry.list()]


@app.get("/agents/{agent_id}")
def get_agent(agent_id: str):
    try:
        return _agent_dto(_registry.get(agent_id))
    except UnknownAgent:
        raise HTTPException(404, "agent not found")


@app.post("/agents/{agent_id}/attest")
def attest_agent(agent_id: str, req: AttestRequest):
    # The HTTP path uses the DevAttestor (recorded as 'dev-insecure' in the audit
    # log). Real join-token / k8s-SA attestation runs server-side via the
    # attestation module; a production deployment would add a mint endpoint and
    # dispatch on req.method here.
    try:
        return _agent_dto(_registry.attest(agent_id, attestor=DevAttestor()))
    except UnknownAgent:
        raise HTTPException(404, "agent not found")
    except AttestationError as e:
        raise HTTPException(400, str(e))


@app.post("/agents/{agent_id}/transition")
def transition_agent(agent_id: str, req: TransitionRequest):
    try:
        return _agent_dto(_registry.transition(agent_id, req.target, req.reason))
    except UnknownAgent:
        raise HTTPException(404, "agent not found")
    except (IllegalTransition, TransitionGuardFailed) as e:
        raise HTTPException(409, str(e))


# --- credentials -------------------------------------------------------------
@app.post("/agents/{agent_id}/credentials")
def issue_credential(agent_id: str):
    try:
        token = _registry.issue_credential(agent_id)
        return {"token": token, "token_type": "JWT-SVID"}
    except UnknownAgent:
        raise HTTPException(404, "agent not found")
    except NotIssuable as e:
        raise HTTPException(409, str(e))


@app.post("/agents/{agent_id}/credentials/rotate")
def rotate_credential(agent_id: str, req: RotateRequest):
    try:
        token = _registry.rotate_credential(agent_id, req.previous_token)
        return {"token": token, "token_type": "JWT-SVID"}
    except UnknownAgent:
        raise HTTPException(404, "agent not found")
    except CredentialError as e:
        raise HTTPException(409, str(e))


@app.post("/agents/{agent_id}/credentials/revoke")
def revoke_credential(agent_id: str, req: RevokeRequest):
    try:
        _registry.revoke_credential(agent_id, req.token, req.reason)
        return {"status": "revoked"}
    except UnknownAgent:
        raise HTTPException(404, "agent not found")


@app.post("/credentials/verify")
def verify_credential(req: VerifyRequest):
    try:
        return {"valid": True, "claims": _registry.verify_credential(req.token)}
    except CredentialError as e:
        raise HTTPException(401, str(e))


# --- trust bundle & audit ----------------------------------------------------
@app.get("/.well-known/charon/trust-bundle")
def trust_bundle():
    """Public keys a verifier (e.g. the MCP gateway) trusts."""
    return _ca.trust_bundle()


@app.get("/audit")
def audit():
    return {
        "intact": _registry.audit_ok(),
        "entries": [
            {
                "seq": e.seq,
                "timestamp": e.timestamp,
                "event": e.event,
                "subject": e.subject,
                "details": e.details,
                "entry_hash": e.entry_hash,
            }
            for e in _registry.audit_entries()
        ],
    }


@app.get("/healthz")
def healthz():
    return {"status": "ok", "trust_domain": TRUST_DOMAIN}


# --- delegation (Phase 5) ----------------------------------------------------
class BeginOboRequest(BaseModel):
    human_principal: str
    actor_token: str
    scope: list[str]


class ExchangeRequest(BaseModel):
    subject_token: str
    actor_token: str
    scope: list[str] | None = None


@app.post("/delegation/begin")
def delegation_begin(req: BeginOboRequest):
    try:
        token = _registry.begin_on_behalf_of(
            req.human_principal, req.actor_token, req.scope
        )
        return {"token": token, "token_type": "JWT-SVID"}
    except (DelegationError, CredentialError) as e:
        raise HTTPException(400, str(e))


@app.post("/delegation/exchange")
def delegation_exchange(req: ExchangeRequest):
    try:
        token = _registry.delegate(req.subject_token, req.actor_token, req.scope)
        return {"token": token, "token_type": "JWT-SVID"}
    except (DelegationError, CredentialError) as e:
        raise HTTPException(400, str(e))


@app.post("/delegation/trace")
def delegation_trace(req: VerifyRequest):
    try:
        prov = _registry.trace(req.token)
        return {"principal": prov.principal, "actors": prov.actors, "path": prov.path}
    except CredentialError as e:
        raise HTTPException(401, str(e))


@app.get("/delegations")
def list_delegations():
    return [
        {
            "principal": d.principal,
            "delegator": d.delegator,
            "delegate": d.delegate,
            "scope": d.scope,
            "created_at": d.created_at,
        }
        for d in _registry.list_delegations()
    ]


# --- reaper (Phase 6) --------------------------------------------------------
class ReaperConfig(BaseModel):
    idle_after: float = 86_400
    decommission_after_idle: float = 7 * 86_400
    departed_owners: list[str] = Field(default_factory=list)
    apply: bool = False


@app.post("/reaper/run")
def reaper_run(cfg: ReaperConfig):
    reaper = Reaper(
        _registry,
        idle_after=cfg.idle_after,
        decommission_after_idle=cfg.decommission_after_idle,
        departed_owners=set(cfg.departed_owners),
    )
    actions = reaper.run_once(apply=cfg.apply)
    return {
        "applied": cfg.apply,
        "actions": [
            {"agent_id": a.agent_id, "name": a.name, "action": a.action,
             "detail": a.detail}
            for a in actions
        ],
    }


# --- dashboard (Phase 6) -----------------------------------------------------
@app.get("/", response_class=HTMLResponse)
def dashboard():
    return DASHBOARD_HTML

