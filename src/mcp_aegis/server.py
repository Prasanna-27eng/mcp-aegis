from __future__ import annotations

import json
import uuid
from contextlib import asynccontextmanager
from typing import AsyncIterator

import httpx
from fastapi import FastAPI, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, StreamingResponse

from mcp_aegis.audit import AuditLog
from mcp_aegis.policy import PolicyEngine
from mcp_aegis.proxy import MCPProxy, _INTERCEPTED_METHODS


def create_app(
    upstream_url: str,
    policy_path: str,
    db_path: str,
    dry_run: bool,
    port: int,
) -> FastAPI:
    proxy: MCPProxy

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        nonlocal proxy
        policy = PolicyEngine(policy_path)
        audit = AuditLog(db_path)
        proxy = MCPProxy(upstream_url, policy, audit, dry_run=dry_run)
        yield

    app = FastAPI(title="mcp-aegis", lifespan=lifespan)

    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_methods=["*"],
        allow_headers=["*"],
    )

    @app.post("/")
    async def rpc_endpoint(request: Request) -> Response:
        session_id = request.headers.get("X-MCP-Session-ID") or str(uuid.uuid4())
        raw_body = await request.body()

        envelope = json.loads(raw_body)
        method: str = envelope.get("method", "")

        if method in _INTERCEPTED_METHODS:
            status_code, body = await proxy.handle(raw_body, session_id)
        else:
            status_code, body = await proxy.forward(raw_body)

        return JSONResponse(content=body, status_code=status_code)

    @app.get("/sse")
    async def sse_endpoint(request: Request) -> StreamingResponse:
        session_id = request.headers.get("X-MCP-Session-ID") or str(uuid.uuid4())
        upstream_sse_url = upstream_url.rstrip("/") + "/sse"

        async def event_stream() -> AsyncIterator[bytes]:
            async with httpx.AsyncClient() as client:
                async with client.stream(
                    "GET",
                    upstream_sse_url,
                    headers={"X-MCP-Session-ID": session_id},
                    # No timeout: SSE connections are long-lived by design
                    timeout=None,
                ) as response:
                    async for chunk in response.aiter_bytes():
                        yield chunk

        return StreamingResponse(
            event_stream(),
            media_type="text/event-stream",
            headers={
                "Cache-Control": "no-cache",
                "X-Accel-Buffering": "no",
            },
        )

    @app.get("/health")
    async def health() -> dict:
        return {"status": "ok", "upstream": upstream_url, "dry_run": dry_run}

    return app
