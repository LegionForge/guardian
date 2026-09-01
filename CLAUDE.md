# LegionForge Guardian — Project Rules

Extends global rules at `~/.claude/CLAUDE.md`. Global rules take precedence on any conflict.

---

## Secrets — Guardian-Specific Rules

All global secrets-handling rules apply. Guardian-specific additions:

**Secret file:** `/Volumes/MAC_MINI_1TB/LegionForge-Guardian/.env.guardian`
- Never `cat`, `Read`, or `grep` this file
- Always use `--env-file .env.guardian` with docker commands
- Template (safe to read): `.env.example`

**Banned patterns specific to this repo:**
```bash
# NEVER
docker inspect legionforge-guardian --format '{{json .Config.Env}}'
docker run -e POSTGRES_PASSWORD=<value> ...
docker run -e TASK_TOKEN_SECRET=<value> ...

# ALWAYS
docker run --env-file .env.guardian legionforge-guardian:latest
docker inspect legionforge-guardian --format '{{.Config.Image}} {{.State.Status}}'
```

**Verification is always functional, never credential-based:**
```bash
curl -s http://localhost:9766/health   # db_reachable + status = source of truth
```

---

## Docker Stack

| Container | Port | Network |
|-----------|------|---------|
| `legionforge-guardian` | `127.0.0.1:9766` | `guardian_guardian-net` |
| `guardian-postgres-1` | `127.0.0.1:5434` (host) | `guardian_guardian-net` |

Postgres hostname inside the network: `postgres`

**Start/stop via Makefile:**
```bash
make guardian-start   # uses --env-file .env.guardian
make guardian-stop
```

---

## Test Commands

```bash
make test              # 57 unit tests, no services needed
make test-cov          # with coverage report (threshold: 50%)
make test-guardian-live  # spins up fresh Docker stack, runs live tests, tears down
GUARDIAN_TEST_URL=http://localhost:9766 python -m pytest tests/test_live.py -v
```

---

## Key Architecture Notes

- Zero LLM calls — all enforcement is deterministic
- Fail-closed on every auth/config error (never fail-open)
- Cache TTL: 10s, refreshed by background asyncio task in lifespan
- Seven checks in order: task token → registry → capability → destructive pattern → sequence → hash integrity → adaptive rules
- `guardian_canary` tool is seeded in DB; any invocation triggers immediate halt + threat event
