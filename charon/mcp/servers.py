"""Phase 4 — toy MCP servers.

Three small servers that stand in for real MCP tool providers. Each declares,
per tool, the scope it requires and any argument-level constraints. The gateway
reads these declarations to build the policy input; the servers themselves do no
authorization — that is entirely the gateway's job, which is the whole point
(closing MCP's all-or-nothing access gap).

The ``call_tool`` implementations are deliberately inert stubs: this project is
about the identity and authorization layer, not about actually moving money or
sending mail.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable


@dataclass
class ToolSpec:
    name: str
    description: str
    required_scope: str
    constraints: dict = field(default_factory=dict)


class MCPServer:
    """Minimal MCP-server interface the gateway proxies in front of."""

    name: str

    def list_tools(self) -> list[ToolSpec]:  # pragma: no cover - interface
        raise NotImplementedError

    def tool(self, name: str) -> ToolSpec | None:
        for t in self.list_tools():
            if t.name == name:
                return t
        return None

    def call_tool(self, name: str, args: dict) -> dict:  # pragma: no cover - interface
        raise NotImplementedError


class FilesystemServer(MCPServer):
    name = "filesystem"

    def __init__(self, allowed_root: str = "/data"):
        self._allowed_root = allowed_root

    def list_tools(self) -> list[ToolSpec]:
        c = {"allowed_root": self._allowed_root}
        return [
            ToolSpec("read_file", "Read a file", "fs:read", c),
            ToolSpec("list_dir", "List a directory", "fs:read", c),
            ToolSpec("write_file", "Write a file", "fs:write", c),
        ]

    def call_tool(self, name: str, args: dict) -> dict:
        return {"server": self.name, "tool": name, "ok": True, "args": args}


class PaymentsServer(MCPServer):
    name = "payments"

    def __init__(self, max_amount: float = 10000):
        self._max = max_amount

    def list_tools(self) -> list[ToolSpec]:
        c = {"max_amount": self._max}
        return [
            ToolSpec("charge", "Charge a card", "pay:charge", c),
            ToolSpec("refund", "Refund a transaction", "pay:refund", c),
        ]

    def call_tool(self, name: str, args: dict) -> dict:
        return {"server": self.name, "tool": name, "ok": True, "args": args}


class EmailServer(MCPServer):
    name = "email"

    def list_tools(self) -> list[ToolSpec]:
        return [
            ToolSpec("send_email", "Send an email", "email:send"),
            ToolSpec("read_inbox", "Read the inbox", "email:read"),
        ]

    def call_tool(self, name: str, args: dict) -> dict:
        return {"server": self.name, "tool": name, "ok": True, "args": args}
