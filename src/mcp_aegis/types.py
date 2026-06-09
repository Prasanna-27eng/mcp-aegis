"""Shared types for mcp-aegis. Import from here; never define these elsewhere."""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class Decision(str, Enum):
    ALLOW            = "ALLOW"
    BLOCK            = "BLOCK"
    LOG_ONLY         = "LOG_ONLY"
    REQUIRE_APPROVAL = "REQUIRE_APPROVAL"


@dataclass
class MCPRequest:
    """A JSON-RPC request intercepted from the AI agent."""
    session_id:  str    # UUID assigned at connection time
    request_id:  Any    # JSON-RPC id (str | int | None)
    method:      str    # e.g. "tools/call", "resources/read"
    params:      dict   # full params dict
    raw:         dict   # original JSON-RPC envelope
    received_at: float = field(default_factory=time.time)

    @property
    def tool_name(self) -> str | None:
        if self.method == "tools/call":
            return self.params.get("name")
        return None

    @property
    def resource_uri(self) -> str | None:
        if self.method == "resources/read":
            return self.params.get("uri")
        return None


@dataclass
class PolicyDecision:
    """Result of evaluating a policy rule against an MCPRequest."""
    decision:  Decision
    rule_name: str    # which rule fired, e.g. "block_shell"
    reason:    str    # human-readable explanation
    dry_run:   bool = False  # if True, decision is advisory — never actually blocks


@dataclass
class AuditEvent:
    """Immutable record written to the SQLite audit log."""
    session_id:      str
    request_id:      str | None
    method:          str
    tool_name:       str | None
    resource_uri:    str | None
    decision:        Decision
    rule_name:       str
    reason:          str
    payload_preview: str           # first 300 chars of JSON-encoded params
    upstream_status: int | None    # HTTP status from upstream MCP server
    latency_ms:      int
    dry_run:         bool  = False
    ts:              float = field(default_factory=time.time)
