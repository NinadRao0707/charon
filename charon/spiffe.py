"""SPIFFE ID construction and parsing.

A SPIFFE ID is a URI of the form:

    spiffe://<trust-domain>/<path>

For Charon, every non-human identity is named:

    spiffe://<trust-domain>/agent/<agent-uuid>

This module is intentionally tiny and dependency-free so it can be reused by
both the credential authority and the (future) MCP gateway without dragging in
the web framework.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

# Trust-domain charset per the SPIFFE spec (lowercase letters, digits, and the
# characters . - _). We validate loosely but reject obviously malformed input.
_TRUST_DOMAIN_RE = re.compile(r"^[a-z0-9._-]+$")
_SCHEME = "spiffe://"


class InvalidSpiffeId(ValueError):
    """Raised when a string is not a well-formed SPIFFE ID."""


@dataclass(frozen=True)
class SpiffeId:
    trust_domain: str
    path: str  # always begins with "/"

    def __str__(self) -> str:  # canonical URI form
        return f"{_SCHEME}{self.trust_domain}{self.path}"

    @property
    def uri(self) -> str:
        return str(self)


def for_agent(trust_domain: str, agent_id: str) -> SpiffeId:
    """Build the canonical SPIFFE ID for an agent."""
    _validate_trust_domain(trust_domain)
    if not agent_id or "/" in agent_id:
        raise InvalidSpiffeId(f"invalid agent id: {agent_id!r}")
    return SpiffeId(trust_domain=trust_domain, path=f"/agent/{agent_id}")


def parse(uri: str) -> SpiffeId:
    """Parse a SPIFFE ID URI back into its components."""
    if not uri.startswith(_SCHEME):
        raise InvalidSpiffeId(f"missing spiffe:// scheme: {uri!r}")
    remainder = uri[len(_SCHEME):]
    if "/" not in remainder:
        # A trust domain with no path is technically valid SPIFFE, but Charon
        # never issues such IDs, so treat it as malformed for our purposes.
        raise InvalidSpiffeId(f"missing path component: {uri!r}")
    trust_domain, path = remainder.split("/", 1)
    _validate_trust_domain(trust_domain)
    return SpiffeId(trust_domain=trust_domain, path=f"/{path}")


def _validate_trust_domain(trust_domain: str) -> None:
    if not trust_domain or not _TRUST_DOMAIN_RE.match(trust_domain):
        raise InvalidSpiffeId(f"invalid trust domain: {trust_domain!r}")
