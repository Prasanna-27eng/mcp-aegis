# mcp-aegis

**MCP security gateway. Sits between your AI agent and any MCP server. Blocks dangerous calls by default.**

[![PyPI version](https://img.shields.io/pypi/v/mcp-aegis.svg)](https://pypi.org/project/mcp-aegis/)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

> **v0.2** — stdio transport, `REQUIRE_APPROVAL` decision, AegisTrace native integration

---

## The problem

AI agents connected to MCP servers have no audit trail, no controls, and no way to know what they've accessed. The MCP protocol itself has no built-in security layer.

In a 24-hour test, Claude Code with the filesystem MCP server tried to read `~/.ssh/id_rsa`, scan the home directory, and issue outbound HTTP requests. There was no log. There was no block. There was no way to know it had happened.

`mcp-aegis` fixes that. It intercepts every tool call before it reaches the MCP server, enforces a policy, and writes a tamper-evident audit log.

---

## Demo

```
$ pip install mcp-aegis
$ mcp-aegis serve --upstream http://localhost:3000 --dry-run

mcp-aegis 0.1.0 — MCP Security Gateway
Upstream : http://localhost:3000
Listening: http://localhost:8765
Policy   : policy_default.toml (dry-run: yes)
Audit DB : ~/.mcp-aegis/audit.db

# Point your agent at http://localhost:8765 instead of http://localhost:3000
# Then watch what it tries to do:

$ mcp-aegis logs --tail

ts                   session  method      tool                    decision   rule                      latency_ms
2026-06-09 14:22:01  a3f9b1   tools/call  list_directory          LOG_ONLY   log_home_directory_crawl        12
2026-06-09 14:22:03  a3f9b1   tools/call  read_file               LOG_ONLY   log_home_directory_crawl         8
2026-06-09 14:22:07  a3f9b1   tools/call  bash                    BLOCK      block_shell_execution            0
2026-06-09 14:22:09  a3f9b1   resources   file://~/.ssh/id_rsa    BLOCK      block_credential_reads           0
```

---

## Install

```bash
pip install mcp-aegis
```

---

## Quick start

```bash
# 1. Install
pip install mcp-aegis

# 2. Start the gateway in front of your MCP server
mcp-aegis serve --upstream http://localhost:3000

# 3. Point your AI agent at the gateway instead
#    Change: http://localhost:3000  →  http://localhost:8765

# 4. Watch the audit log
mcp-aegis logs --tail
```

First time? Run with `--dry-run` to audit without blocking anything. You'll see exactly what your agent is reaching for.

---

## Configuration

The built-in policy blocks the highest-risk patterns out of the box. To customise, create a TOML file:

```toml
# my-policy.toml

[[rules]]
name     = "block_prod_db"
decision = "BLOCK"
reason   = "Never write to the production database from an AI agent."
tools    = ["execute_sql", "*_write", "*_insert"]

[[rules]]
name     = "log_all_file_reads"
decision = "LOG_ONLY"
reason   = "Audit every file read."
methods  = ["resources/read"]

[[rules]]
name     = "allow_safe_tools"
decision = "ALLOW"
reason   = "Explicitly allow safe read-only tools."
tools    = ["get_time", "calculator", "search_web"]
```

Rules are evaluated in order — first match wins. Pass your policy at startup:

```bash
mcp-aegis serve --upstream http://localhost:3000 --policy my-policy.toml
```

Test a tool against the policy without starting the server:

```bash
mcp-aegis policy test bash
# Decision : BLOCK
# Rule     : block_shell_execution
# Reason   : Shell execution tools allow arbitrary code execution...

mcp-aegis policy test get_weather
# Decision : ALLOW
# Rule     : default_allow
# Reason   : No rule matched — allowing by default
```

---

## What it blocks by default

| Rule | What it catches | Decision |
|------|----------------|----------|
| `block_shell_execution` | `bash`, `shell`, `exec`, `run_command`, `*_exec`, `*_bash` | **BLOCK** |
| `block_credential_reads` | Resources at `~/.ssh/*`, `~/.aws/*`, `.env`, `credentials`, `.netrc`, `.gnupg/*` | **BLOCK** |
| `log_home_directory_crawl` | `list_directory`, `read_file`, `*_read`, `*_list` under home paths | LOG_ONLY |
| `log_network_requests` | `http_request`, `curl`, `fetch`, `*_request`, `*_fetch` | LOG_ONLY |
| `log_git_credential_exposure` | Resources at `.git/config`, `.gitconfig` | LOG_ONLY |
| `log_sampling_calls` | `sampling/createMessage` (LLM-calls-LLM) | LOG_ONLY |
| `log_database_writes` | `*_write`, `*_delete`, `*_drop`, `execute_sql`, `query` | LOG_ONLY |

`BLOCK` = request terminated at the gateway, never reaches the MCP server.  
`LOG_ONLY` = request passes through but is recorded in the audit log.

---

## Dry-run mode

Not ready to block yet? Start with `--dry-run`:

```bash
mcp-aegis serve --upstream http://localhost:3000 --dry-run
```

Every decision is logged but nothing is blocked. Run it for 24 hours and then check:

```bash
mcp-aegis stats
# Total events : 847
# By Decision  : ALLOW 701 (82.8%)  LOG_ONLY 130 (15.4%)  BLOCK 16 (1.9%)
# Top blocked  : bash (7)  read_file (5)  execute_sql (4)
```

That's the data you need to tune your policy before enabling enforcement.

---

## stdio transport (v0.2)

Connect mcp-aegis directly to Claude Desktop or any agent that uses the MCP stdio protocol:

```bash
# HTTP upstream (MCP server already running over HTTP)
mcp-aegis serve --transport stdio --upstream http://localhost:3000

# Subprocess upstream (MCP server spawned as a child process)
mcp-aegis serve --transport stdio --upstream-cmd "npx -y @modelcontextprotocol/server-filesystem /Users/you/Documents"
```

Claude Desktop config (`~/Library/Application Support/Claude/claude_desktop_config.json`):

```json
{
  "mcpServers": {
    "filesystem-guarded": {
      "command": "mcp-aegis",
      "args": [
        "serve",
        "--transport", "stdio",
        "--upstream-cmd", "npx -y @modelcontextprotocol/server-filesystem /Users/you/Documents"
      ]
    }
  }
}
```

---

## REQUIRE_APPROVAL (v0.2)

A new policy decision that pauses a tool call and queues it for human review:

```toml
[[rules]]
name     = "require_approval_db_writes"
decision = "REQUIRE_APPROVAL"
reason   = "Production database write — human approval required."
tools    = ["execute_sql", "*_write", "*_delete"]
```

When the agent hits this rule the call is blocked and logged as pending. Review and resolve:

```bash
mcp-aegis pending
# id        ts                   method        tool/resource                  rule
# 4a1b2c3d  2026-06-09 14:33:01  tools/call    execute_sql                    require_approval_db_writes

mcp-aegis approve 4a1b2c3d   # marks as approved; agent must retry the call
mcp-aegis deny 4a1b2c3d      # marks as denied
```

---

## CLI reference

```
mcp-aegis serve     --upstream URL | --upstream-cmd CMD
                    [--transport http|stdio] [--port INT] [--policy PATH] [--db PATH] [--dry-run]
mcp-aegis logs      [--session ID] [--limit INT] [--tail] [--decision ALLOW|BLOCK|LOG_ONLY|REQUIRE_APPROVAL]
mcp-aegis stats     [--db PATH]
mcp-aegis pending   [--db PATH]
mcp-aegis approve   ID [--db PATH]
mcp-aegis deny      ID [--db PATH]
mcp-aegis policy test TOOL_NAME  [--policy PATH] [--method METHOD]
mcp-aegis policy show            [--policy PATH]
```

---

## Connecting to AegisTrace (v0.2 native integration)

Set `AEGISTRACE_URL` and `AEGISTRACE_INGEST_KEY` to forward every BLOCK and REQUIRE_APPROVAL event into your AegisTrace AI Action Approval Queue in real time.

```bash
export AEGISTRACE_URL=https://your-aegistrace.com
export AEGISTRACE_INGEST_KEY=your-ingest-api-key
mcp-aegis serve --upstream http://localhost:3000
```

Events appear instantly in AegisTrace at `/app/agent-security` — with session ID, tool name, rule that fired, and payload preview. REQUIRE_APPROVAL events show as `pending` for analyst review.

For generic webhook forwarding (any SIEM):

```bash
export MCP_AEGIS_WEBHOOK_URL=https://your-siem.com/webhook
```

[AegisTrace](https://github.com/Prasanna-27eng/AegisTrace) — the open-source Trust Operating System that makes every AI action auditable and human-approved.

---

## Architecture

```
AI Agent  →  POST http://localhost:8765/  →  mcp-aegis gateway
                                               │
                                          PolicyEngine (TOML rules)
                                               │
                                        ┌──────┴──────┐
                                      BLOCK        ALLOW / LOG_ONLY
                                        │               │
                                   JSON-RPC         Forward to
                                   error back    upstream MCP server
                                        │               │
                                        └──────┬────────┘
                                           AuditLog (SQLite)
                                           Webhook (optional)
```

Transport: HTTP/SSE (stdio support coming in v0.2).

---

## Roadmap

**v0.2 (shipped)**
- [x] stdio transport — `--transport stdio` with `--upstream-cmd` subprocess mode (Claude Desktop compatible)
- [x] `REQUIRE_APPROVAL` decision — blocks call, queues for review; `mcp-aegis pending/approve/deny`
- [x] AegisTrace native integration — BLOCK/REQUIRE_APPROVAL appear in the AI Action Approval Queue
- [x] `AEGISTRACE_URL` + `AEGISTRACE_INGEST_KEY` env vars

**v0.3+**
- Community policy library — `mcp-aegis policy install github-mcp`
- STIX 2.1 export for threat intelligence sharing
- MITRE ATT&CK technique tagging on blocked events
- Docker image + systemd installer

---

## Contributing

Issues and PRs welcome at [github.com/Prasanna-27eng/AegisTrace](https://github.com/Prasanna-27eng/AegisTrace).

---

## License

MIT
