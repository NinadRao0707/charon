"""Run the Charon gateway as a real MCP server over stdio.

This wraps the transport-agnostic ``MCPGateway`` behind the official MCP Python
SDK so MCP clients (Claude Desktop, IDEs, agent frameworks) can connect to it.
The gateway still authorizes every tool call; this module only adapts the
transport.

Requires the MCP SDK:   pip install mcp
Run:                    python -m charon.mcp.stdio_server

The client must supply a Charon JWT-SVID. Here we read it from the
CHARON_CREDENTIAL environment variable for simplicity; a production deployment
would terminate OAuth 2.1 at the gateway and inject the verified token per
session.
"""
from __future__ import annotations

import os

from charon.ca import CertificateAuthority
from charon.credentials import CredentialAuthority
from charon.mcp.gateway import MCPGateway
from charon.mcp.servers import EmailServer, FilesystemServer, PaymentsServer
from charon.repository import SQLiteRepository
from charon.service import Registry

try:
    from mcp.server.fastmcp import FastMCP
except ImportError as exc:  # pragma: no cover
    raise SystemExit(
        "The MCP SDK is required for the stdio server: pip install mcp"
    ) from exc

TRUST_DOMAIN = os.environ.get("CHARON_TRUST_DOMAIN", "charon.local")


def build_gateway() -> MCPGateway:
    repo = SQLiteRepository(os.environ.get("CHARON_DB", "charon.db"))
    ca = CertificateAuthority()
    registry = Registry(repo, CredentialAuthority(ca, TRUST_DOMAIN), TRUST_DOMAIN)
    servers = [FilesystemServer(), PaymentsServer(), EmailServer()]
    return MCPGateway(registry, servers)


gateway = build_gateway()
mcp = FastMCP("charon-gateway")


@mcp.tool()
def call(server_tool: str, arguments: dict | None = None) -> dict:
    """Proxy a tool call through Charon's authorization gateway.

    server_tool: "server.tool" (e.g. "filesystem.read_file")
    arguments:   tool arguments
    """
    request = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {"name": server_tool, "arguments": arguments or {}},
        "credential": os.environ.get("CHARON_CREDENTIAL", ""),
    }
    response = gateway.handle(request)
    if "error" in response:
        raise PermissionError(response["error"]["message"])
    return response["result"]


if __name__ == "__main__":
    mcp.run()
