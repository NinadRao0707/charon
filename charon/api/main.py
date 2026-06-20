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
from pydantic import BaseModel, Field

from charon.ca import CertificateAuthority
from charon.credentials import CredentialAuthority, CredentialError, NotIssuable
from charon.lifecycle import (
    IllegalTransition,
    LifecycleState,
    TransitionGuardFailed,
)
from charon.repository import SQLiteRepository
from charon.service import Registry, UnknownAgent

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
    try:
        return _agent_dto(_registry.attest(agent_id, req.method))
    except UnknownAgent:
        raise HTTPException(404, "agent not found")


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
