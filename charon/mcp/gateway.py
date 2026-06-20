"""Phase 4 — the MCP Authorization Gateway.

The gateway sits in front of one or more MCP servers and authorizes *every
individual tool call*. This closes MCP's structural all-or-nothing gap: in plain
MCP, once an agent can reach a server it can call any tool the server exposes.
Here, each ``tools/call`` is checked against the credential's scopes and
argument-level constraints before it is allowed to reach the server.

Per call the gateway:
  1. verifies the presented JWT-SVID (signature, expiry, audience, revocation),
  2. resolves the tool's declared required-scope + constraints,
  3. asks the PolicyEngine for an allow/deny decision,
  4. records the decision in the shared hash-chained audit log,
  5. forwards to the real server only if allowed; otherwise returns an error.

Transport is modelled as JSON-RPC-shaped dicts so the core is testable without a
live transport. ``charon/mcp/stdio_server.py`` wraps this gateway behind the
official MCP SDK for real deployments.
"""
from __future__ import annotations

from charon.credentials import CredentialError
from charon.dpop import DpopError, ReplayCache, verify_proof
from charon.policy import EmbeddedPolicyEngine, PolicyEngine
from charon.service import Registry

from .servers import MCPServer

# JSON-RPC error codes (custom range for authz failures).
ERR_UNAUTHENTICATED = -32001  # missing / invalid credential
ERR_FORBIDDEN = -32002  # valid credential, but policy denied
ERR_BAD_REQUEST = -32600
ERR_UNKNOWN_TOOL = -32601


class MCPGateway:
    def __init__(
        self,
        registry: Registry,
        servers: list[MCPServer],
        policy: PolicyEngine | None = None,
        resource_url: str = "https://charon.gateway/mcp",
        credential_verifier=None,
    ):
        self._registry = registry
        self._servers = {s.name: s for s in servers}
        self._policy = policy or EmbeddedPolicyEngine()
        self._resource_url = resource_url
        # Verifier seam: defaults to the registry's own JWT-SVID verification, but
        # a SPIRE deployment can pass charon.spire.SpireJwtVerifier here instead.
        self._verify = credential_verifier or registry.verify_credential
        self._replay = ReplayCache()

    # -- public JSON-RPC entrypoint ----------------------------------------

    def handle(self, request: dict) -> dict:
        method = request.get("method")
        req_id = request.get("id")
        if method == "tools/list":
            return self._handle_list(request, req_id)
        if method == "tools/call":
            return self._handle_call(request, req_id)
        return _error(req_id, ERR_BAD_REQUEST, f"unsupported method {method!r}")

    # -- handlers ----------------------------------------------------------

    def _handle_list(self, request: dict, req_id) -> dict:
        ok, claims, err = self._authenticate(request)
        if not ok:
            return _error(req_id, ERR_UNAUTHENTICATED, err)
        scopes = set(claims.get("scope", "").split())
        # Only advertise tools the credential could actually invoke. Hiding
        # unusable tools shrinks the attack surface and limits confused-deputy.
        visible = []
        for server in self._servers.values():
            for t in server.list_tools():
                if t.required_scope in scopes:
                    visible.append(
                        {
                            "name": f"{server.name}.{t.name}",
                            "description": t.description,
                        }
                    )
        return _result(req_id, {"tools": visible})

    def _handle_call(self, request: dict, req_id) -> dict:
        ok, claims, err = self._authenticate(request)
        if not ok:
            return _error(req_id, ERR_UNAUTHENTICATED, err)

        params = request.get("params", {}) or {}
        full_name = params.get("name", "")
        args = params.get("arguments", {}) or {}
        subject = claims.get("sub", "unknown")

        if "." not in full_name:
            return _error(req_id, ERR_BAD_REQUEST, "tool name must be 'server.tool'")
        server_name, tool_name = full_name.split(".", 1)

        server = self._servers.get(server_name)
        if server is None:
            return _error(req_id, ERR_UNKNOWN_TOOL, f"unknown server {server_name!r}")
        spec = server.tool(tool_name)
        if spec is None:
            return _error(req_id, ERR_UNKNOWN_TOOL, f"unknown tool {full_name!r}")

        decision = self._policy.evaluate(
            {
                "agent": subject,
                "scopes": claims.get("scope", "").split(),
                "server": server_name,
                "tool": tool_name,
                "args": args,
                "required_scope": spec.required_scope,
                "constraints": spec.constraints,
            }
        )

        # The acting agent is the immediate actor (outermost act.sub) for a
        # delegated credential, otherwise the subject itself.
        actor = (claims.get("act") or {}).get("sub") or subject
        provenance = _provenance_str(claims)

        self._registry.record_authorization(
            actor,
            decision.allow,
            server_name,
            tool_name,
            reason=decision.reason,
            required_scope=spec.required_scope,
            provenance=provenance,
        )

        if not decision.allow:
            return _error(req_id, ERR_FORBIDDEN, decision.reason)

        # Authorized: record activity for the *acting* agent (feeds the reaper).
        agent = self._registry.get_by_spiffe(actor)
        if agent is not None:
            self._registry.record_activity(agent.id)
        result = server.call_tool(tool_name, args)
        return _result(req_id, result)

    # -- helpers -----------------------------------------------------------

    def _authenticate(self, request: dict):
        """Return (ok, claims, error). Credential may be a top-level field or in
        params._meta.authorization (Bearer <jwt>). If the credential is key-bound
        (carries a cnf.jkt), a valid DPoP proof is also required."""
        token = request.get("credential")
        if not token:
            meta = (request.get("params", {}) or {}).get("_meta", {}) or {}
            auth = meta.get("authorization", "")
            if auth.lower().startswith("bearer "):
                token = auth[7:]
        if not token:
            return False, {}, "no credential presented"
        try:
            claims = self._verify(token)
        except CredentialError as exc:
            return False, {}, str(exc)

        # Proof-of-possession: if the token is bound to a key, demand a DPoP proof.
        jkt = (claims.get("cnf") or {}).get("jkt")
        if jkt:
            proof = request.get("dpop") or (
                (request.get("params", {}) or {}).get("_meta", {}) or {}
            ).get("dpop")
            if not proof:
                return False, {}, "credential is DPoP-bound but no proof presented"
            try:
                verify_proof(
                    proof, "POST", self._resource_url, jkt, self._replay
                )
            except DpopError as exc:
                return False, {}, f"DPoP proof rejected: {exc}"
        return True, claims, ""


def _result(req_id, result: dict) -> dict:
    return {"jsonrpc": "2.0", "id": req_id, "result": result}


def _error(req_id, code: int, message: str) -> dict:
    return {"jsonrpc": "2.0", "id": req_id, "error": {"code": code, "message": message}}


def _provenance_str(claims: dict) -> str | None:
    """Render 'principal -> a -> b -> actor' for a delegated credential."""
    if "act" not in claims:
        return None
    actors_recent_first = []
    act = claims.get("act")
    while isinstance(act, dict):
        if "sub" in act:
            actors_recent_first.append(act["sub"])
        act = act.get("act")
    path = [claims.get("sub", "unknown"), *reversed(actors_recent_first)]
    return " -> ".join(path)
