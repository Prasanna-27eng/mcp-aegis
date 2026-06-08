"""SQLite-backed audit log for mcp-aegis."""
from __future__ import annotations

import os
import sqlite3
import sys
import threading
import time
from collections import deque
from dataclasses import asdict
from typing import Any
from urllib.request import Request, urlopen
from urllib.error import URLError

from .types import AuditEvent, Decision


_CREATE_SESSIONS = """
CREATE TABLE IF NOT EXISTS sessions (
    session_id TEXT PRIMARY KEY,
    started_at REAL NOT NULL,
    last_seen  REAL NOT NULL,
    agent_hint TEXT
)
"""

_CREATE_EVENTS = """
CREATE TABLE IF NOT EXISTS events (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id      TEXT    NOT NULL,
    request_id      TEXT,
    ts              REAL    NOT NULL,
    method          TEXT    NOT NULL,
    tool_name       TEXT,
    resource_uri    TEXT,
    decision        TEXT    NOT NULL,
    rule_name       TEXT    NOT NULL,
    reason          TEXT    NOT NULL,
    payload_preview TEXT    NOT NULL,
    upstream_status INTEGER,
    latency_ms      INTEGER NOT NULL,
    dry_run         INTEGER NOT NULL DEFAULT 0,
    FOREIGN KEY (session_id) REFERENCES sessions(session_id)
)
"""

_CREATE_INDEXES = [
    "CREATE INDEX IF NOT EXISTS idx_events_session  ON events (session_id)",
    "CREATE INDEX IF NOT EXISTS idx_events_ts       ON events (ts)",
    "CREATE INDEX IF NOT EXISTS idx_events_decision ON events (decision)",
    "CREATE INDEX IF NOT EXISTS idx_events_tool     ON events (tool_name)",
]

_INSERT_SESSION = """
INSERT INTO sessions (session_id, started_at, last_seen, agent_hint)
VALUES (?, ?, ?, ?)
ON CONFLICT(session_id) DO UPDATE SET last_seen = excluded.last_seen
"""

_INSERT_EVENT = """
INSERT INTO events (
    session_id, request_id, ts, method, tool_name, resource_uri,
    decision, rule_name, reason, payload_preview,
    upstream_status, latency_ms, dry_run
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
"""


def _row_to_event(row: sqlite3.Row) -> AuditEvent:
    return AuditEvent(
        session_id=row["session_id"],
        request_id=row["request_id"],
        method=row["method"],
        tool_name=row["tool_name"],
        resource_uri=row["resource_uri"],
        decision=Decision(row["decision"]),
        rule_name=row["rule_name"],
        reason=row["reason"],
        payload_preview=row["payload_preview"],
        upstream_status=row["upstream_status"],
        latency_ms=row["latency_ms"],
        dry_run=bool(row["dry_run"]),
        ts=row["ts"],
    )


class _WebhookSender:
    def __init__(self, url: str) -> None:
        self._url = url
        self._buffer: deque[bytes] = deque(maxlen=100)
        self._lock = threading.Lock()

    def send(self, event: AuditEvent) -> None:
        import json

        payload = {k: (v.value if isinstance(v, Decision) else v)
                   for k, v in asdict(event).items()}
        body = json.dumps(payload).encode()
        threading.Thread(target=self._dispatch, args=(body,), daemon=True).start()

    def _dispatch(self, body: bytes) -> None:
        with self._lock:
            retry_items = list(self._buffer)
            self._buffer.clear()

        for buffered in retry_items:
            self._post(buffered)

        self._post(body)

    def _post(self, body: bytes) -> None:
        try:
            req = Request(
                self._url,
                data=body,
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with urlopen(req, timeout=5):
                pass
        except (URLError, OSError) as exc:
            print(f"[mcp-aegis] webhook send failed: {exc}", file=sys.stderr)
            with self._lock:
                self._buffer.append(body)


class AuditLog:
    def __init__(self, db_path: str = "~/.mcp-aegis/audit.db") -> None:
        path = os.path.expanduser(db_path)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        self._path = path
        self._lock = threading.Lock()
        self._init_db()

        webhook_url = os.environ.get("MCP_AEGIS_WEBHOOK_URL")
        self._webhook: _WebhookSender | None = (
            _WebhookSender(webhook_url) if webhook_url else None
        )

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self._path, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=NORMAL")
        return conn

    def _init_db(self) -> None:
        with self._lock, self._connect() as conn:
            conn.execute(_CREATE_SESSIONS)
            conn.execute(_CREATE_EVENTS)
            for idx in _CREATE_INDEXES:
                conn.execute(idx)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def write(self, event: AuditEvent, agent_hint: str | None = None) -> None:
        now = event.ts
        with self._lock, self._connect() as conn:
            conn.execute(_INSERT_SESSION, (event.session_id, now, now, agent_hint))
            conn.execute(
                _INSERT_EVENT,
                (
                    event.session_id,
                    event.request_id,
                    event.ts,
                    event.method,
                    event.tool_name,
                    event.resource_uri,
                    event.decision.value,
                    event.rule_name,
                    event.reason,
                    event.payload_preview,
                    event.upstream_status,
                    event.latency_ms,
                    int(event.dry_run),
                ),
            )

        if self._webhook and event.decision in (Decision.BLOCK, Decision.LOG_ONLY):
            self._webhook.send(event)

    def query(
        self,
        session_id: str | None = None,
        method: str | None = None,
        decision: Decision | None = None,
        tool_name: str | None = None,
        since_ts: float | None = None,
        limit: int = 100,
    ) -> list[AuditEvent]:
        clauses: list[str] = []
        params: list[Any] = []

        if session_id is not None:
            clauses.append("session_id = ?")
            params.append(session_id)
        if method is not None:
            clauses.append("method = ?")
            params.append(method)
        if decision is not None:
            clauses.append("decision = ?")
            params.append(decision.value)
        if tool_name is not None:
            clauses.append("tool_name = ?")
            params.append(tool_name)
        if since_ts is not None:
            clauses.append("ts >= ?")
            params.append(since_ts)

        where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
        sql = f"SELECT * FROM events {where} ORDER BY ts DESC LIMIT ?"
        params.append(limit)

        with self._connect() as conn:
            rows = conn.execute(sql, params).fetchall()

        return [_row_to_event(r) for r in rows]

    def stats(self) -> dict:
        now = time.time()
        with self._connect() as conn:
            total = conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]

            by_decision: dict[str, int] = {d.value: 0 for d in Decision}
            for row in conn.execute(
                "SELECT decision, COUNT(*) FROM events GROUP BY decision"
            ):
                by_decision[row[0]] = row[1]

            top_blocked = [
                {"tool": r[0], "count": r[1]}
                for r in conn.execute(
                    "SELECT tool_name, COUNT(*) AS c FROM events "
                    "WHERE decision = 'BLOCK' AND tool_name IS NOT NULL "
                    "GROUP BY tool_name ORDER BY c DESC LIMIT 10"
                )
            ]

            top_log_only = [
                {"tool": r[0], "count": r[1]}
                for r in conn.execute(
                    "SELECT tool_name, COUNT(*) AS c FROM events "
                    "WHERE decision = 'LOG_ONLY' AND tool_name IS NOT NULL "
                    "GROUP BY tool_name ORDER BY c DESC LIMIT 10"
                )
            ]

            sessions_count = conn.execute("SELECT COUNT(*) FROM sessions").fetchone()[0]

            events_last_hour = conn.execute(
                "SELECT COUNT(*) FROM events WHERE ts >= ?", (now - 3600,)
            ).fetchone()[0]

            events_last_24h = conn.execute(
                "SELECT COUNT(*) FROM events WHERE ts >= ?", (now - 86400,)
            ).fetchone()[0]

        return {
            "total_events": total,
            "by_decision": by_decision,
            "top_blocked_tools": top_blocked,
            "top_log_only_tools": top_log_only,
            "sessions_count": sessions_count,
            "events_last_hour": events_last_hour,
            "events_last_24h": events_last_24h,
        }

    def sessions(self, limit: int = 20) -> list[dict]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT session_id, started_at, last_seen, agent_hint "
                "FROM sessions ORDER BY last_seen DESC LIMIT ?",
                (limit,),
            ).fetchall()
        return [dict(r) for r in rows]

    def tail(self, n: int = 20) -> list[AuditEvent]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM events ORDER BY ts DESC LIMIT ?", (n,)
            ).fetchall()
        return [_row_to_event(r) for r in rows]
