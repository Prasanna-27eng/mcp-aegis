from __future__ import annotations

import json
import time
import uuid
from typing import Any

import httpx

from mcp_aegis.audit import AuditLog
from mcp_aegis.policy import PolicyEngine
from mcp_aegis.types import AuditEvent, Decision, MCPRequest, PolicyDecision

_INTERCEPTED_METHODS = frozenset({"tools/call", "resources/read", "sampling/createMessage"})

_BLOCK_ERROR = {"code": -32600, "message": ""}


class MCPProxy:
    def __init__(
        self,
        upstream_url: str,
        policy: PolicyEngine,
        audit: AuditLog,
        dry_run: bool = False,
    ) -> None:
        self._upstream_url = upstream_url
        self._policy = policy
        self._audit = audit
        self._dry_run = dry_run

    async def handle(self, raw_body: bytes, session_id: str) -> tuple[int, dict]:
        envelope: dict[str, Any] = json.loads(raw_body)
        method: str = envelope.get("method", "")
        params: dict = envelope.get("params") or {}
        request_id: Any = envelope.get("id")

        request = MCPRequest(
            session_id=session_id,
            request_id=request_id,
            method=method,
            params=params,
            raw=envelope,
        )

        decision: PolicyDecision = self._policy.evaluate(request, dry_run=self._dry_run)

        t0 = time.monotonic()
        upstream_status: int | None = None
        response_body: dict

        actually_block = decision.decision is Decision.BLOCK and not self._dry_run

        if actually_block:
            response_body = {
                "jsonrpc": "2.0",
                "id": request_id,
                "error": {"code": -32600, "message": decision.reason},
            }
        else:
            upstream_status, response_body = await self._post_upstream(raw_body)

        latency_ms = int((time.monotonic() - t0) * 1000)

        self._audit.write(
            AuditEvent(
                session_id=session_id,
                request_id=str(request_id) if request_id is not None else None,
                method=method,
                tool_name=request.tool_name,
                resource_uri=request.resource_uri,
                decision=decision.decision,
                rule_name=decision.rule_name,
                reason=decision.reason,
                payload_preview=json.dumps(params)[:300],
                upstream_status=upstream_status,
                latency_ms=latency_ms,
                dry_run=self._dry_run,
            )
        )

        status_code = upstream_status if upstream_status is not None else 200
        return status_code, response_body

    async def forward(self, raw_body: bytes) -> tuple[int, dict]:
        return await self._post_upstream(raw_body)

    async def _post_upstream(self, raw_body: bytes) -> tuple[int, dict]:
        async with httpx.AsyncClient() as client:
            response = await client.post(
                self._upstream_url,
                content=raw_body,
                headers={"Content-Type": "application/json"},
                # Generous timeout: upstream MCP servers may run tools synchronously
                timeout=120.0,
            )
        return response.status_code, response.json()
