"""Phase 4 — Authorization policy.

The gateway asks a PolicyEngine a single question per tool call: *may this
credential, with these scopes, invoke this tool with these arguments?* Keeping
the decision behind an interface lets us run a dependency-free embedded engine
for development and tests, and swap in OPA (Open Policy Agent) for the real
deployment without touching the gateway.

The policy input document the gateway builds looks like:

    {
      "agent":  "spiffe://td/agent/abc",
      "scopes": ["fs:read"],
      "server": "payments",
      "tool":   "charge",
      "args":   {"amount": 5000, "currency": "usd"},
      "required_scope": "pay:charge",      # declared by the tool
      "constraints": {"max_amount": 10000} # declared by the tool
    }

Two checks define least privilege here:
  1. scope check    — required_scope must be present in the credential's scopes
  2. constraint check — argument-level limits (path confinement, amount caps)
"""
from __future__ import annotations

import json
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Protocol


@dataclass
class PolicyDecision:
    allow: bool
    reason: str


class PolicyEngine(Protocol):
    def evaluate(self, input_doc: dict) -> PolicyDecision: ...


class EmbeddedPolicyEngine:
    """Pure-Python least-privilege evaluator. Fails closed."""

    def evaluate(self, input_doc: dict) -> PolicyDecision:
        scopes = set(input_doc.get("scopes", []))
        required = input_doc.get("required_scope")
        server = input_doc.get("server")
        tool = input_doc.get("tool")
        args = input_doc.get("args", {}) or {}
        constraints = input_doc.get("constraints", {}) or {}

        # 1) scope check
        if required and required not in scopes:
            return PolicyDecision(
                False,
                f"missing required scope {required!r} for {server}.{tool} "
                f"(have {sorted(scopes)})",
            )

        # 2) argument-level constraints
        # path confinement: the requested path must sit under an allowed root.
        allowed_root = constraints.get("allowed_root")
        if allowed_root is not None:
            path = str(args.get("path", ""))
            norm = _normalize(path)
            if not norm.startswith(_normalize(allowed_root)):
                return PolicyDecision(
                    False, f"path {path!r} escapes allowed root {allowed_root!r}"
                )

        # amount cap: a charge/refund may not exceed the configured maximum.
        max_amount = constraints.get("max_amount")
        if max_amount is not None and "amount" in args:
            try:
                amount = float(args["amount"])
            except (TypeError, ValueError):
                return PolicyDecision(False, "amount is not a number")
            if amount > float(max_amount):
                return PolicyDecision(
                    False, f"amount {amount} exceeds max {max_amount}"
                )

        return PolicyDecision(True, "permitted by policy")


class OpaPolicyEngine:
    """Delegates the decision to a running OPA instance over HTTP.

    Expects a Rego package ``charon.authz`` exposing ``allow`` (bool) and
    ``reason`` (string). See ``policies/authz.rego``. Uses only stdlib so no
    extra dependency is required. Fails closed on any error.
    """

    def __init__(
        self,
        opa_url: str = "http://localhost:8181",
        decision_path: str = "charon/authz",
        timeout: float = 2.0,
    ):
        self._url = f"{opa_url.rstrip('/')}/v1/data/{decision_path}"
        self._timeout = timeout

    def evaluate(self, input_doc: dict) -> PolicyDecision:
        body = json.dumps({"input": input_doc}).encode("utf-8")
        req = urllib.request.Request(
            self._url, data=body, headers={"Content-Type": "application/json"}
        )
        try:
            with urllib.request.urlopen(req, timeout=self._timeout) as resp:
                payload = json.loads(resp.read().decode("utf-8"))
        except (urllib.error.URLError, OSError, json.JSONDecodeError) as exc:
            return PolicyDecision(False, f"OPA unreachable, failing closed: {exc}")

        result = payload.get("result", {})
        allow = bool(result.get("allow", False))
        reason = result.get("reason") or ("permitted by OPA" if allow else "denied by OPA")
        return PolicyDecision(allow, reason)


def _normalize(path: str) -> str:
    import posixpath

    # Resolve . and .. so "/data/../etc/passwd" can't sneak past a prefix check.
    return posixpath.normpath("/" + path.lstrip("/"))
