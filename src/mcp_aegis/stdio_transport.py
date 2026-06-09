"""Stdio transport for mcp-aegis — bidirectional JSON-RPC proxy over stdin/stdout.

Two modes:
  HTTP upstream:  each request is forwarded as an HTTP POST.
  Subprocess:     upstream MCP server is spawned as a child process; stdin/stdout are piped.

Usage (HTTP):
    await run_stdio_http("http://localhost:3000", policy_path, db_path, dry_run)

Usage (subprocess):
    await run_stdio_subprocess("npx -y @modelcontextprotocol/server-filesystem /path",
                               policy_path, db_path, dry_run)
"""
from __future__ import annotations

import asyncio
import json
import sys
import time
import uuid
from typing import Any

from .audit import AuditLog
from .policy import PolicyEngine
from .proxy import MCPProxy, _INTERCEPTED_METHODS
from .types import AuditEvent, Decision, MCPRequest

_stdout_lock = asyncio.Lock()


async def _write_stdout(data: bytes) -> None:
    async with _stdout_lock:
        sys.stdout.buffer.write(data)
        sys.stdout.buffer.flush()


# ---------------------------------------------------------------------------
# HTTP upstream mode
# ---------------------------------------------------------------------------

async def run_stdio_http(
    upstream_url: str,
    policy_path: str,
    db_path: str,
    dry_run: bool,
) -> None:
    """Read newline-delimited JSON-RPC from stdin, apply policy, POST to upstream."""
    session_id = str(uuid.uuid4())
    policy = PolicyEngine(policy_path, dry_run=dry_run)
    audit = AuditLog(db_path)
    proxy = MCPProxy(upstream_url, policy, audit, dry_run=dry_run)

    loop = asyncio.get_event_loop()
    reader = asyncio.StreamReader()
    protocol = asyncio.StreamReaderProtocol(reader)
    await loop.connect_read_pipe(lambda: protocol, sys.stdin)

    async for raw in reader:
        raw = raw.strip()
        if not raw:
            continue
        try:
            envelope: dict[str, Any] = json.loads(raw)
        except json.JSONDecodeError:
            continue

        method: str = envelope.get("method", "")
        request_id: Any = envelope.get("id")

        if method in _INTERCEPTED_METHODS and request_id is not None:
            _status, resp = await proxy.handle(raw, session_id)
        else:
            _status, resp = await proxy.forward(raw)

        if request_id is not None:
            await _write_stdout((json.dumps(resp) + "\n").encode())


# ---------------------------------------------------------------------------
# Subprocess upstream mode
# ---------------------------------------------------------------------------

async def run_stdio_subprocess(
    upstream_cmd: str,
    policy_path: str,
    db_path: str,
    dry_run: bool,
) -> None:
    """Spawn upstream MCP server as subprocess; proxy its stdin/stdout with policy enforcement."""
    session_id = str(uuid.uuid4())
    policy = PolicyEngine(policy_path, dry_run=dry_run)
    audit = AuditLog(db_path)

    proc = await asyncio.create_subprocess_shell(
        upstream_cmd,
        stdin=asyncio.subprocess.PIPE,
        stdout=asyncio.subprocess.PIPE,
        stderr=None,  # inherit mcp-aegis stderr
    )

    loop = asyncio.get_event_loop()
    stdin_reader = asyncio.StreamReader()
    stdin_proto = asyncio.StreamReaderProtocol(stdin_reader)
    await loop.connect_read_pipe(lambda: stdin_proto, sys.stdin)

    async def proxy_proc_stdout() -> None:
        """Forward subprocess stdout → our stdout transparently."""
        async for line in proc.stdout:  # type: ignore[union-attr]
            await _write_stdout(line if line.endswith(b"\n") else line + b"\n")

    async def proxy_agent_stdin() -> None:
        """Read agent stdin, apply policy, forward or block."""
        async for raw in stdin_reader:
            raw = raw.strip()
            if not raw:
                continue
            try:
                envelope: dict[str, Any] = json.loads(raw)
            except json.JSONDecodeError:
                continue

            method: str = envelope.get("method", "")
            request_id: Any = envelope.get("id")
            params: dict = envelope.get("params") or {}

            # Notifications (no id) and non-intercepted methods pass through untouched.
            if method not in _INTERCEPTED_METHODS or request_id is None:
                proc.stdin.write(raw + b"\n")  # type: ignore[union-attr]
                await proc.stdin.drain()  # type: ignore[union-attr]
                continue

            request = MCPRequest(
                session_id=session_id,
                request_id=request_id,
                method=method,
                params=params,
                raw=envelope,
            )
            decision = policy.evaluate(request, dry_run=dry_run)

            actually_block = (
                decision.decision in (Decision.BLOCK, Decision.REQUIRE_APPROVAL)
                and not dry_run
            )

            t0 = time.monotonic()
            upstream_status: int | None = None

            if actually_block:
                suffix = " Run `mcp-aegis pending` to review." if decision.decision is Decision.REQUIRE_APPROVAL else ""
                error_resp = {
                    "jsonrpc": "2.0",
                    "id": request_id,
                    "error": {"code": -32600, "message": decision.reason + suffix},
                }
                await _write_stdout((json.dumps(error_resp) + "\n").encode())
            else:
                proc.stdin.write(raw + b"\n")  # type: ignore[union-attr]
                await proc.stdin.drain()  # type: ignore[union-attr]
                upstream_status = 200

            latency_ms = int((time.monotonic() - t0) * 1000)

            event = AuditEvent(
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
                dry_run=dry_run,
            )
            audit.write(event)

            if decision.decision is Decision.REQUIRE_APPROVAL and not dry_run:
                audit.add_pending(event)

    try:
        await asyncio.gather(proxy_proc_stdout(), proxy_agent_stdin())
    except (asyncio.CancelledError, BrokenPipeError):
        pass
    finally:
        if proc.returncode is None:
            proc.terminate()
            try:
                await asyncio.wait_for(proc.wait(), timeout=3.0)
            except asyncio.TimeoutError:
                proc.kill()
