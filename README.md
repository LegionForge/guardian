# legionforge-guardian

**Deterministic security sidecar for LLM agent frameworks.**

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-blue)](https://www.python.org)
[![PyPI](https://img.shields.io/pypi/v/legionforge-guardian)](https://pypi.org/project/legionforge-guardian)

💛 [Support this project](https://legionforge.org/donations) — LegionForge is open-source and independently maintained.

---

## The Problem

LLM agents can be prompt-injected, manipulated into calling dangerous tools, and
coaxed into exfiltrating data — all through natural language alone. Most frameworks
have no security layer. The ones that do rely on another LLM to evaluate requests,
which means the checker can itself be injected.

## What Guardian Does

Guardian is a FastAPI sidecar (port 9766) that runs **seven deterministic checks**
before any tool call is executed. No LLM. No heuristics. Pattern matching,
hash validation, and cryptographic verification — decisions that cannot be
prompt-injected.

Drop it in front of any agent framework. If Guardian says halt, the tool doesn't run.

---

## The Seven Checks

| # | Check | What it blocks |
|---|---|---|
| 0 | **Task token ACL** | Tools outside the JWT-scoped permission set |
| 1 | **Tool registry** | Unregistered tools; revoked tools (10s propagation) |
| 2 | **Capability boundary** | Forbidden actions: `register_tool`, `spawn_agent_direct`, `escalate_scope`, and 5 others |
| 3 | **Destructive pattern detection** | 9 regex families: credential probing, shell injection, bulk exfiltration, data staging, reconnaissance, privilege escalation, and more |
| 4 | **Sequence contracts** | Tool call sequences that deviate from registered agent playbooks |
| 5 | **Hash integrity** | Tools whose description or schema hash has changed since registration (tamper detection) |
| 6 | **Adaptive rules** | Hot-reloaded rules from DB — block/log/sandbox without redeployment |

All checks run in order. First failure halts or sandboxes immediately. No LLM calls.

---

## Quickstart (Docker Compose — 30 seconds)

```bash
git clone https://github.com/LegionForge/LegionForge-Guardian
cd LegionForge-Guardian

# Start Guardian + its own PostgreSQL (init.sql runs automatically)
GUARDIAN_DB_PASSWORD=changeme docker compose up -d

# Verify it's running
curl http://localhost:9766/health
# {"status": "ok", "service": "guardian", "version": "4.0.0"}
```

> **Port conflict?** If port 9766 is already in use, override it:
> `GUARDIAN_PORT=9767 GUARDIAN_DB_PASSWORD=changeme docker compose up -d`

---

## Python SDK

```python
from legionforge_guardian import guardian_check

# Before executing any tool call in your agent:
result = await guardian_check(
    tool_name="web_search",
    tool_input={"query": "latest AI news"},
    agent_state={"agent_id": "researcher", "run_id": "abc123"},
)

if not result["allowed"]:
    # Guardian says halt or sandbox — do not execute the tool
    raise SecurityError(result["reason"])
```

Or use the client class directly:

```python
from legionforge_guardian.sdk.client import GuardianClient

client = GuardianClient(url="http://localhost:9766")
result = await client.check(
    tool_name="file_write",
    tool_input={"path": "/etc/crontab", "content": "..."},
    agent_state={"agent_id": "worker", "run_id": "xyz"},
)
# → allowed=False, tier="halt", threat_type="SYSTEM_PATH_PROBE"
```

The SDK is **fail-safe**: a network error or timeout returns a synthetic halt response.
Guardian failure never silently allows tool execution.

---

## Framework Integration

### LangGraph

```python
from legionforge_guardian.sdk.client import GuardianClient

guardian = GuardianClient()

class SecureToolNode:
    async def __call__(self, state):
        tool_call = state["messages"][-1].tool_calls[0]
        result = await guardian.check(
            tool_name=tool_call["name"],
            tool_input=tool_call["args"],
            agent_state={"agent_id": state["agent_id"], "run_id": state["run_id"]},
        )
        if not result["allowed"]:
            return {"messages": [ToolMessage(content=f"BLOCKED: {result['reason']}")]}
        # execute the tool normally
        ...
```

### AutoGen

```python
async def guardian_hook(sender, recipient, messages, config):
    for msg in messages:
        if msg.get("tool_calls"):
            for call in msg["tool_calls"]:
                result = await guardian.check(call["function"]["name"], call["function"]["arguments"], {})
                if not result["allowed"]:
                    raise ValueError(f"Guardian blocked: {result['reason']}")
    return messages, config
```

### Generic (any framework)

```bash
# Before executing a tool, POST to /check:
curl -s -X POST http://localhost:9766/check \
  -H "Authorization: Bearer $GUARDIAN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "tool_id": "web_search",
    "action": "invoke",
    "args": {"query": "..."},
    "agent_id": "my_agent",
    "run_id": "run_001",
    "sequence_so_far": []
  }'
# {"allowed": true, "tier": "allow", "reason": "All checks passed", "confidence": 1.0}
```

---

## API Reference

### `POST /check` — Enforcement hot path

Requires `Authorization: Bearer <TASK_TOKEN_SECRET>` when `GUARDIAN_REQUIRE_AUTH=true`.

**Request:**
```json
{
  "tool_id": "web_search",
  "action": "invoke",
  "args": {"query": "internal admin panel credentials"},
  "agent_id": "researcher_agent",
  "run_id": "run_abc123",
  "sequence_so_far": ["web_search"],
  "task_token": null
}
```

**Response:**
```json
{
  "allowed": false,
  "tier": "halt",
  "reason": "Destructive pattern 'CREDENTIAL_PROBE' detected in tool args",
  "threat_type": "DESTRUCTIVE_PATTERN",
  "confidence": 1.0
}
```

`tier` values: `"allow"` | `"sandbox"` | `"halt"`

### `POST /report` — Async threat event ingestion

Send threat events from your application for audit log recording.

### `GET /rules` — Read-only cache view

Returns currently loaded tool registry, sequence contracts, and adaptive rules.
Requires auth.

### `GET /health` — Liveness check

Always unauthenticated. Used by Docker healthcheck.

---

## Environment Variables

| Variable | Default | Description |
|---|---|---|
| `GUARDIAN_DB_HOST` | `localhost` | PostgreSQL host |
| `GUARDIAN_DB_PORT` | `5432` | PostgreSQL port |
| `GUARDIAN_DB_NAME` | `guardian` | Database name |
| `GUARDIAN_DB_USER` | `guardian` | Database user |
| `GUARDIAN_DB_PASSWORD` | *(required)* | Database password |
| `TASK_TOKEN_SECRET` | *(required when auth enabled)* | Bearer token for /check and /rules |
| `GUARDIAN_REQUIRE_AUTH` | `true` | Set `false` for local dev only |
| `GUARDIAN_HOST` | `127.0.0.1` | Bind address (see note below) |
| `GUARDIAN_PORT` | `9766` | Listening port |

**Production note:** Guardian defaults to `127.0.0.1` (localhost only). When running
in Docker, set `GUARDIAN_HOST=0.0.0.0` to allow the container's port mapping to work.
Never expose Guardian's port publicly — it must only be reachable by the agent process.

**Security note:** When `GUARDIAN_REQUIRE_AUTH=true`, `TASK_TOKEN_SECRET` must be set.
Guardian will refuse requests with 503 if auth is required but no secret is configured.
Use a secrets manager (Vault, AWS Secrets Manager, macOS Keychain) rather than plain
environment variables in production.

---

## Database Setup

Guardian needs two tables. Run `init.sql` against any PostgreSQL 14+ instance:

```bash
psql $GUARDIAN_DB_URL -f init.sql
```

If you're deploying alongside LegionForge, Guardian uses LegionForge's existing
tables. Running `init.sql` against a LegionForge database is safe — all statements
use `CREATE TABLE IF NOT EXISTS`.

---

## Architecture

```
Your Agent Framework
        │
        ▼  (before every tool call)
┌───────────────────┐
│   Guardian /check  │  ← FastAPI, localhost:9766
│                   │
│  Check 0: Token   │
│  Check 1: Registry│
│  Check 2: Caps    │  ← In-memory caches, refreshed every 10s
│  Check 3: Patterns│
│  Check 4: Sequence│
│  Check 5: Hash    │
│  Check 6: Rules   │  ← Hot-reloaded from DB
│                   │
└───────────────────┘
        │
        ▼  (if allowed)
   Tool executes
```

**Design principles:**
- **No LLM in the hot path.** Every decision is deterministic and auditable.
- **Fail-safe.** Network error or timeout → synthetic halt. Guardian failure never
  silently permits tool execution.
- **Fail-closed.** Unknown tools are rejected. Novel sequences are sandboxed.
  Auth misconfiguration returns 503, not 200.
- **In-memory hot path.** Registry + rules cached at startup, refreshed every 10s.
  DB latency is not on the critical path.
- **Tamper-evident audit log.** SHA-256 hash chain on every check result.
  Verifiable offline.

### Why not an LLM-based checker?

An LLM evaluating another LLM's output can itself be prompt-injected. If the agent
under evaluation has been compromised, its output can contain instructions that
manipulate the checker. Deterministic pattern matching cannot be prompt-injected.
The security boundary must be outside the LLM's influence.

---

## Security

See [SECURITY.md](SECURITY.md) for the threat model, what Guardian does not protect
against, and vulnerability reporting instructions.

---

## Tested Against

Guardian was validated against 24 adversarial attack functions covering:
prompt injection, credential probing, SSRF, path traversal, shell injection,
privilege escalation, data exfiltration, tool tampering, and sequence contract
violations. Result: **0 bypasses** on a clean LegionForge deployment.

Reproduce: `make test-pentest` in the LegionForge monorepo.

---

## License

MIT — see [LICENSE](LICENSE).

Part of the [LegionForge](https://github.com/LegionForge/LegionForge) project.
Built by [Jp Cruz](https://github.com/jp-cruz).
