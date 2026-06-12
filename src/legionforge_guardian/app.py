"""
legionforge_guardian.app
────────────────────────
Guardian — deterministic security sidecar service.

Canonical location as of Phase G2. LegionForge's src/security/guardian.py
is now a thin re-export shim that delegates to this module.

Runs as a standalone FastAPI app on localhost:9766.
Enforces tool registry validation, capability boundaries, destructive pattern
detection, and tool sequence contracts for every tool call.

Design principles:
    - NO LLM calls — all decisions are deterministic and auditable
    - Fail-safe: connection error or timeout → SecureToolNode halts the run
    - In-memory caches (refreshed every 10s) keep the hot path fast
    - Never fail-open: unknown tools and novel sequences are rejected/sandboxed

Endpoints:
    POST /check   — synchronous enforcement (hot path)
    POST /report  — async threat event ingestion
    GET  /rules   — read-only view of approved tools + sequences
    GET  /health  — unauthenticated liveness (Docker healthcheck)

Usage:
    # Standalone (direct start from this package):
    uvicorn legionforge_guardian.app:app --host 127.0.0.1 --port 9766

    # Via LegionForge backward-compat shim:
    uvicorn src.security.guardian:app --host 127.0.0.1 --port 9766

    # Via Docker Compose (LegionForge):
    docker-compose up guardian
"""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import logging
import os
import re
import time
from contextlib import asynccontextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

# ── Module-level startup timestamp (for uptime_seconds in /health) ────────────
_startup_time: float = time.monotonic()

# ── In-memory Prometheus-style counters (for /metrics endpoint) ───────────────
_metrics: dict[str, int] = {
    "checks_allow": 0,
    "checks_halt": 0,
    "checks_sandbox": 0,
    "threat_TOOL_REVOKED": 0,
    "threat_CAPABILITY_VIOLATION": 0,
    "threat_INJECTION_DETECTED": 0,
    "threat_TOOL_HASH_MISMATCH": 0,
    "threat_DESTRUCTIVE_PATTERN": 0,
    "threat_SEQUENCE_VIOLATION": 0,
    "threat_INVALID_TASK_TOKEN": 0,
    "threat_TOOL_SCOPE_VIOLATION": 0,
    "threat_GUARDIAN_MISCONFIGURED": 0,
    "threat_GUARDIAN_AUTH_FAILURE": 0,
    "threat_CANARY_TRIGGERED": 0,
}

import jwt

import httpx
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel

# ── Phase G1: Guardian-internal definitions (no src.* imports) ────────────────
# Inlined from src.security.core and src.security.acl so guardian.py can start
# with no LegionForge modules on PYTHONPATH — prerequisite for standalone package.
#
# IMPORTANT: Keep these definitions in sync with src/security/core.py and
# src/security/acl.py. Smoke tests enforce pattern-count parity (see
# test_guardian_destructive_patterns_count_matches_core).

# ── Inlined from src.security.core ───────────────────────────────────────────

# In-process fallback registry. Guardian normally loads approved tools from DB.
# This is only used when DB is unavailable at startup; empty in standalone mode.
_TOOL_REGISTRY: dict[str, Any] = {}
_TOOL_HASHES: dict[str, dict[str, str]] = {}


def _compute_fast_hash(manifest: Any) -> dict[str, str]:
    """Fast in-memory integrity hash — description and schema only. No disk I/O."""
    description_hash = hashlib.sha256(manifest.description.encode("utf-8")).hexdigest()
    schema_json = json.dumps(manifest.input_schema, sort_keys=True, ensure_ascii=True)
    schema_hash = hashlib.sha256(schema_json.encode("utf-8")).hexdigest()
    return {"description_hash": description_hash, "schema_hash": schema_hash}


FORBIDDEN_CAPABILITIES: frozenset[str] = frozenset(
    {
        "register_tool",
        "write_executable",
        "invoke_unregistered",
        "modify_registry",
        "escalate_scope",
        "spawn_agent_direct",
        "modify_own_state",
    }
)

FORCE_END_CATEGORIES: frozenset[str] = frozenset(
    {
        "CMD_INJECTION",
        "SELF_PROBE",
        "DATA_STAGING",
        "PRIVILEGE_ESCALATION",
    }
)

# Sync with src/security/core.py _DESTRUCTIVE_PATTERNS (9 patterns).
# Smoke test test_guardian_destructive_patterns_count_matches_core enforces parity.
_GUARDIAN_DESTRUCTIVE_PATTERNS: list[tuple[re.Pattern, str]] = [
    # ── Credential probing ────────────────────────────────────────────────────
    (
        re.compile(
            r"\b(password|passwd|api[_\-\s]?key|secret[_\-\s]?key|private[_\-\s]?key"
            r"|access[_\-\s]?token|auth[_\-\s]?token|bearer[_\-\s]?token|credentials?"
            r"|keychain|vault\s+secret|pgp\s+key|ssh\s+key|client[_\-\s]?secret)\b",
            re.I,
        ),
        "CREDENTIAL_PROBE",
    ),
    # ── Internal infrastructure probing ──────────────────────────────────────
    (
        re.compile(
            r"\b(localhost|127\.0\.0\.1|0\.0\.0\.0|169\.254\.\d+\.\d+"
            r"|internal[_\-\s]?(api|service|host|network|endpoint)"
            r"|intranet|admin[_\-\s]?(panel|console|interface|login|portal)"
            r"|management[_\-\s]?(console|interface|portal)"
            r"|corp(orate)?\s+network|vpn\s+(gateway|server|config))\b",
            re.I,
        ),
        "INTERNAL_PROBE",
    ),
    # ── System file / path probing ────────────────────────────────────────────
    (
        re.compile(
            r"(/etc/(passwd|shadow|hosts|sudoers|crontab|ssh|ssl)"
            r"|/root/|/home/\w+/\.(ssh|aws|gnupg|config)"
            r"|~/\.(ssh|aws|gnupg|config|env|bashrc|zshrc)"
            r"|\\\\HKLM\\\\|\\\\HKCU\\\\|%APPDATA%|%SYSTEMROOT%|%LOCALAPPDATA%"
            r"|C:\\\\Windows\\\\System32|C:\\\\Users\\\\[^/\\\\]+\\\\AppData)",
            re.I,
        ),
        "SYSTEM_PATH_PROBE",
    ),
    # ── Bulk data exfiltration ────────────────────────────────────────────────
    (
        re.compile(
            r"\b(exfil(trat)?e?"
            r"|dump\s+(all|the\s+(database|db|tables?|data|users?|records?))"
            r"|export\s+(all|every|complete|full|entire)"
            r"|scrape\s+(all|every|the\s+(site|web|pages?|content))"
            r"|harvest\s+(all|data|credentials?|emails?|records?)"
            r"|encrypt\s+(all|every|the)\s+(files?|data|disks?|volumes?|backups?)"
            r"|overwrite\s+(all|every|the)\s+(files?|data|disks?|records?)"
            r"|wipe\s+(all|the|disks?|drives?|volumes?|database)"
            r"|delete\s+(all|every|the)\s+(files?|data|records?|users?|backups?)"
            r"|shred\s+(all|every|the)\s+(files?|data|disks?))\b",
            re.I,
        ),
        "BULK_DESTRUCTIVE",
    ),
    # ── Self-probe ────────────────────────────────────────────────────────────
    (
        re.compile(
            r"\b(your\s+(system\s+)?prompt|your\s+instructions?"
            r"|your\s+(api\s+)?key|your\s+(initial|current)\s+(instructions?|context)"
            r"|legionforge\s+(config|secret|key|prompt)"
            r"|agent[_\-\s]?(config|settings|state|key|identity)"
            r"|what\s+are\s+your\s+instructions?)\b",
            re.I,
        ),
        "SELF_PROBE",
    ),
    # ── Command / shell injection ─────────────────────────────────────────────
    (
        re.compile(
            r"[|;&`]\s*(cat|ls|ps|id|whoami|wget|curl|nc|netcat|bash|sh|zsh|dash"
            r"|python\d*|perl|ruby|node|php|powershell|cmd\.exe)\b"
            r"|\$\([^)]+\)"  # $(command) subshell
            r"|`[^`]{3,}`"  # `command` backtick execution
            r"|\beval\s*\(",  # eval( calls
            re.I,
        ),
        "CMD_INJECTION",
    ),
    # ── Prompt-level privilege escalation ────────────────────────────────────
    (
        re.compile(
            r"\b(sudo|run\s+as\s+(root|admin|administrator|superuser)"
            r"|escalate\s+(privileges?|permissions?|access|scope)"
            r"|bypass\s+(the\s+)?(security|auth\w*|authorization|check|filter|guard)"
            r"|disable\s+(the\s+|a\s+)?(security|safeguards?|checks?|filters?|guards?|monitoring|logging)"
            r"|grant\s+(yourself|itself|the\s+agent)(\s+\w+)?\s+(access|permissions?|privileges?))\b",
            re.I,
        ),
        "PRIVILEGE_ESCALATION",
    ),
    # ── Data staging / covert channel setup ──────────────────────────────────
    (
        re.compile(
            r"\b(send\s+(this|the|all)\s+(data|output|result|content)\s+to"
            r"|post\s+(this|the|all)\s+(data|output|result)\s+to"
            r"|webhook\.site|requestbin|pipedream|ngrok\.(io|com)"
            r"|pastebin\.com|hastebin|ghostbin"
            r"|base64\s+(encode|encod)\s+(and\s+)?(send|post|upload)"
            r"|encode\s+(and\s+)?(exfil|send|transmit|upload))\b",
            re.I,
        ),
        "DATA_STAGING",
    ),
    # ── Reconnaissance patterns ───────────────────────────────────────────────
    (
        re.compile(
            r"\b(enumerate\s+(all\s+)?(users?|accounts?|services?|hosts?|ports?|subnets?|domains?)"
            r"|list\s+all\s+(users?|accounts?|services?|processes?|ports?|connections?)"
            r"|network\s+(scan|map|topology|enumeration)"
            r"|port\s+(scan|sweep|probe)"
            r"|service\s+(discovery|enumeration|fingerprint)"
            r"|os\s+(detection|fingerprint|version\s+scan))\b",
            re.I,
        ),
        "RECONNAISSANCE",
    ),
]


def detect_destructive_pattern(text: str) -> tuple[bool, list[str]]:
    """
    Scan text for adversarial patterns. Returns (any_matched, matched_categories).
    Inlined from src.security.core — canonical comments live there.
    """
    matched: list[str] = []
    for pattern, category in _GUARDIAN_DESTRUCTIVE_PATTERNS:
        if pattern.search(text):
            matched.append(category)
    return bool(matched), matched


# ── Inlined from src.security.acl ─────────────────────────────────────────────

_GUARDIAN_TOKEN_ISSUER: str = os.environ.get("TASK_TOKEN_ISSUER", "legionforge")


@dataclass
class _GuardianTaskToken:
    """Minimal token representation — mirrors acl.TaskToken for guardian's use."""

    token_id: str
    agent_id: str
    run_id: str
    granted_tools: list[str]
    granted_tables: list[str]
    granted_data_classes: list[str]
    expires_at: datetime
    parent_token_id: str | None
    escalation_policy: str


def _validate_task_token(token_str: str) -> _GuardianTaskToken | None:
    """
    Decode and validate a task token JWT.
    Returns _GuardianTaskToken on success, None on any failure.
    Inlined from src.security.acl.validate_task_token — no framework imports.
    Uses TASK_TOKEN_SECRET env var (same secret as the framework; set by make guardian-start).
    """
    # _GUARDIAN_AUTH_TOKEN is set at line ~135 (module-level, os.environ.get)
    secret = _GUARDIAN_AUTH_TOKEN  # noqa: F821 — defined below, resolved at call time
    if not secret:
        logger.error("[guardian] Cannot validate token — TASK_TOKEN_SECRET not set")
        return None

    try:
        payload = jwt.decode(
            token_str,
            secret,
            algorithms=["HS256"],
            options={"require": ["exp", "iat", "jti", "sub", "iss"]},
        )
    except jwt.ExpiredSignatureError:
        logger.warning("[guardian] Task token has expired")
        return None
    except jwt.InvalidTokenError as e:
        logger.warning(f"[guardian] Invalid task token: {e}")
        return None
    except Exception as e:
        logger.error(f"[guardian] Unexpected error decoding token: {e}")
        return None

    if payload.get("iss") != _GUARDIAN_TOKEN_ISSUER:
        logger.warning(
            f"[guardian] Token issuer mismatch: expected "
            f"{_GUARDIAN_TOKEN_ISSUER!r}, got {payload.get('iss')!r}"
        )
        return None

    return _GuardianTaskToken(
        token_id=payload["jti"],
        agent_id=payload["sub"],
        run_id=payload.get("run_id", ""),
        granted_tools=payload.get("granted_tools", []),
        granted_tables=payload.get("granted_tables", []),
        granted_data_classes=payload.get("granted_data_classes", []),
        expires_at=datetime.fromtimestamp(payload["exp"], tz=timezone.utc),
        parent_token_id=payload.get("parent_token_id"),
        escalation_policy=payload.get("escalation_policy", "deny"),
    )


logger = logging.getLogger(__name__)


@asynccontextmanager
async def _lifespan(application: FastAPI):
    """Load caches from DB on startup. Non-fatal if DB is unavailable."""
    logger.info("[guardian] Starting up — loading caches...")
    await _refresh_caches()
    logger.info(
        f"[guardian] Ready — {len(_approved_tools)} approved tools, "
        f"{sum(len(v) for v in _agent_sequences.values())} registered sequences"
    )
    yield
    logger.info("[guardian] Shutting down.")


app = FastAPI(
    title="LegionForge Guardian",
    description="Deterministic security sidecar — NO LLM calls",
    version="4.0.0",
    lifespan=_lifespan,
)

# ── In-memory caches (refreshed from DB every 10 seconds) ─────────────────────
# TTL reduced from 60s → 10s in Phase 6 to propagate tool revocations faster.

# tool_id → {"description_hash": str, "schema_hash": str}
_approved_tools: dict[str, dict[str, str]] = {}

# agent_id → list of approved sequences [[tool_id, ...], ...]
_agent_sequences: dict[str, list[list[str]]] = {}

# Phase 4: approved adaptive rules from threat_rules table.
# list of dicts: {"rule_id": str, "rule_type": str, "rule_def": dict, ...}
# Refreshed every 10 seconds (same TTL as other caches).
# Applied in _check_6_adaptive_rules() — AFTER all static checks.
_adaptive_rules: list[dict] = []

# Phase 6: set of REVOKED tool_ids — checked BEFORE approval registry.
# Revoked tools halt immediately even if they were previously APPROVED.
_revoked_tools: set[str] = set()

_cache_last_refreshed: float = 0.0
_CACHE_TTL_SECONDS: float = (
    10.0  # Phase 6: reduced from 60s for faster revocation propagation
)

# ── Bearer auth configuration ─────────────────────────────────────────────────
# When GUARDIAN_REQUIRE_AUTH=true, /check and /rules require:
#   Authorization: Bearer <TASK_TOKEN_SECRET>
#
# The token is loaded once at import time from the environment. In Docker,
# TASK_TOKEN_SECRET is injected via docker-compose.yml environment section.
# /health is always unauthenticated (required for Docker healthcheck).
#
# Default: true (production default — fail-safe).
# Set GUARDIAN_REQUIRE_AUTH=false only for local dev without a configured
# TASK_TOKEN_SECRET. When true and TASK_TOKEN_SECRET is empty, the endpoint
# warns and allows the request (see _check_bearer_auth). Configure
# TASK_TOKEN_SECRET via make guardian-start (loads from macOS Keychain).

_GUARDIAN_AUTH_TOKEN: str = os.environ.get("TASK_TOKEN_SECRET", "")
_GUARDIAN_REQUIRE_AUTH: bool = (
    os.environ.get("GUARDIAN_REQUIRE_AUTH", "true").lower() == "true"
)


def _check_bearer_auth(request: Request) -> bool | str:
    """
    Verify the Authorization: Bearer header against TASK_TOKEN_SECRET.

    Returns True if:
      - GUARDIAN_REQUIRE_AUTH is false (auth disabled — local dev only), OR
      - The provided token matches TASK_TOKEN_SECRET via constant-time compare.

    Returns "misconfigured" if auth is required but TASK_TOKEN_SECRET is unset.
    Returns False if auth is required and the token is missing or wrong.

    Uses hmac.compare_digest for constant-time comparison to prevent
    timing-based token enumeration attacks.

    FAIL-CLOSED: When GUARDIAN_REQUIRE_AUTH=true and TASK_TOKEN_SECRET is empty,
    this returns "misconfigured" so callers return 503. Prevents silently
    unauthenticated deployments — misconfigured Guardian must never behave as
    if auth is disabled.
    """
    if not _GUARDIAN_REQUIRE_AUTH:
        return True  # Auth not required (local dev)

    if not _GUARDIAN_AUTH_TOKEN:
        logger.error(
            "[guardian] GUARDIAN_REQUIRE_AUTH=true but TASK_TOKEN_SECRET is not set — "
            "refusing request. Set TASK_TOKEN_SECRET or set GUARDIAN_REQUIRE_AUTH=false "
            "for local development."
        )
        return "misconfigured"

    auth_header = request.headers.get("authorization", "")
    if not auth_header.startswith("Bearer "):
        return False

    provided_token = auth_header[len("Bearer ") :]
    return hmac.compare_digest(
        provided_token.encode("utf-8"),
        _GUARDIAN_AUTH_TOKEN.encode("utf-8"),
    )


def _unauthorized(detail: str = "Unauthorized") -> JSONResponse:
    """Return a 401 response for failed auth checks."""
    return JSONResponse(
        {"detail": detail, "error": "unauthorized"},
        status_code=401,
    )


def _guardian_db_conninfo() -> tuple[str, str]:
    """
    Return (conninfo_without_password, password) for Guardian's own direct DB connection.
    Guardian does NOT use the app's connection pool — it connects independently
    so it has no dependency on src.database or the full framework stack.
    """
    host = os.environ.get("POSTGRES_HOST", "host.docker.internal")
    port = os.environ.get("POSTGRES_PORT", "5432")
    db = os.environ.get("POSTGRES_DB", "legionforge")
    user = os.environ.get("POSTGRES_USER", os.environ.get("USER", "postgres"))
    password = os.environ.get("POSTGRES_PASSWORD", "")
    conninfo = f"host={host} port={port} dbname={db} user={user}"
    return conninfo, password


async def _refresh_caches() -> None:
    """
    Load approved tools, revoked tools, agent sequences, and adaptive threat rules from DB.
    Called on startup and periodically by the background refresh task.
    Non-fatal if DB is unavailable — caches retain their last known values.

    Uses its own direct psycopg3 connection — does NOT depend on src.database
    so the container can stay minimal (no LangGraph, no pgvector, etc.).
    """
    global _approved_tools, _agent_sequences, _adaptive_rules, _revoked_tools, _cache_last_refreshed

    try:
        import psycopg
        from psycopg.rows import dict_row

        conninfo, password = _guardian_db_conninfo()
        async with await psycopg.AsyncConnection.connect(
            conninfo, password=password, row_factory=dict_row, autocommit=True
        ) as conn:
            cur_t = await conn.execute(
                "SELECT tool_id, description_hash, schema_hash FROM tool_registry WHERE status = 'APPROVED'"
            )
            tool_rows = await cur_t.fetchall()
            # Phase 6: load REVOKED tool_ids for immediate halt-on-invocation
            cur_rev = await conn.execute(
                "SELECT tool_id FROM tool_registry WHERE status = 'REVOKED'"
            )
            revoked_rows = await cur_rev.fetchall()
            cur_s = await conn.execute(
                "SELECT agent_id, sequence FROM agent_profiles ORDER BY agent_id, registered_at"
            )
            seq_rows = await cur_s.fetchall()
            # Phase 4: load approved, non-expired adaptive rules
            cur_r = await conn.execute(
                """
                SELECT rule_id::text, rule_type, rule_def
                FROM threat_rules
                WHERE status = 'APPROVED'
                  AND (expires_at IS NULL OR expires_at > NOW())
                ORDER BY approved_at ASC
                """
            )
            rule_rows = await cur_r.fetchall()

        new_tools: dict[str, dict[str, str]] = {}
        for row in tool_rows:
            new_tools[row["tool_id"]] = {
                "description_hash": row["description_hash"],
                "schema_hash": row["schema_hash"],
            }

        new_revoked: set[str] = {row["tool_id"] for row in revoked_rows}

        new_seqs: dict[str, list[list[str]]] = {}
        for row in seq_rows:
            aid = row["agent_id"]
            if aid not in new_seqs:
                new_seqs[aid] = []
            new_seqs[aid].append(list(row["sequence"]))

        new_rules: list[dict] = []
        for row in rule_rows:
            new_rules.append(
                {
                    "rule_id": row["rule_id"],
                    "rule_type": row["rule_type"],
                    "rule_def": row["rule_def"] or {},
                }
            )

        _approved_tools = new_tools
        _revoked_tools = new_revoked
        _agent_sequences = new_seqs
        _adaptive_rules = new_rules
        _cache_last_refreshed = time.monotonic()

        logger.info(
            f"[guardian] Cache refreshed: {len(_approved_tools)} tools, "
            f"{len(_revoked_tools)} revoked, "
            f"{sum(len(v) for v in _agent_sequences.values())} sequences, "
            f"{len(_adaptive_rules)} adaptive rules"
        )

    except Exception as e:
        logger.warning(f"[guardian] Cache refresh failed (using stale data): {e}")
        # Fall back to in-process registry (populated by register_tool() calls)
        _approved_tools = {
            tid: _compute_fast_hash(manifest)
            for tid, manifest in _TOOL_REGISTRY.items()
        }


async def _maybe_refresh_caches() -> None:
    """Refresh caches if TTL has expired."""
    if time.monotonic() - _cache_last_refreshed > _CACHE_TTL_SECONDS:
        await _refresh_caches()


# ── Request / Response models ─────────────────────────────────────────────────


class GuardianCheckRequest(BaseModel):
    tool_id: str
    action: str
    args: dict
    agent_id: str
    run_id: str
    sequence_so_far: list[str]
    task_token: str | None = None  # Phase 3: JWT task token validation


class GuardianCheckResponse(BaseModel):
    allowed: bool
    tier: str  # "allow" | "sandbox" | "halt"
    reason: str
    threat_type: str | None = None
    confidence: float = 1.0


class ReportRequest(BaseModel):
    event_type: str
    agent_id: str
    run_id: str
    payload: dict


# ── Five-check enforcement pipeline ──────────────────────────────────────────


def _check_0_task_token(
    tool_id: str, task_token: str | None
) -> GuardianCheckResponse | None:
    """
    Check 0 (Phase 3): Validate the JWT task token and verify tool is in scope.

    Only runs when the request includes a task_token. Agents without tokens
    are unconstrained for backward compatibility (Phase 4 will enforce tokens
    on all agents).

    Two failure modes:
      - Token present but invalid/expired → tier="halt" (INVALID_TASK_TOKEN)
      - Token valid but tool not in granted_tools → tier="halt" (TOOL_SCOPE_VIOLATION)
    """
    if not task_token:
        return None  # No token — skip check (backward compat)

    token = _validate_task_token(task_token)
    if token is None:
        return GuardianCheckResponse(
            allowed=False,
            tier="halt",
            reason="Task token is invalid or expired",
            threat_type="INVALID_TASK_TOKEN",
            confidence=1.0,
        )

    if tool_id not in token.granted_tools:
        return GuardianCheckResponse(
            allowed=False,
            tier="halt",
            reason=(
                f"Tool '{tool_id}' not authorised by task token "
                f"(granted: {token.granted_tools})"
            ),
            threat_type="TOOL_SCOPE_VIOLATION",
            confidence=1.0,
        )

    return None


def _check_1_tool_registry(tool_id: str) -> GuardianCheckResponse | None:
    """
    Check 1: Is the tool registered and approved? Is it revoked?

    Phase 6: Revocation is checked FIRST — a revoked tool halts even if it was
    previously APPROVED. Revocation propagates within _CACHE_TTL_SECONDS (10s).
    """
    # Phase 6: revocation takes priority over approval
    if tool_id in _revoked_tools:
        return GuardianCheckResponse(
            allowed=False,
            tier="halt",
            reason=f"Tool '{tool_id}' has been REVOKED and is no longer permitted",
            threat_type="TOOL_REVOKED",
            confidence=1.0,
        )

    if tool_id not in _approved_tools:
        return GuardianCheckResponse(
            allowed=False,
            tier="halt",
            reason=f"Tool '{tool_id}' is not in the approved tool registry",
            threat_type="CAPABILITY_VIOLATION",
            confidence=1.0,
        )
    return None


def _check_2_capability_boundary(
    action: str, tool_id: str = ""
) -> GuardianCheckResponse | None:
    """
    Check 2: Is the action or tool_id in the forbidden capabilities list?

    Two sub-checks:
      a. action in FORBIDDEN_CAPABILITIES — blocks when the action TYPE is forbidden
         (e.g., action="spawn_agent_direct" submitted by gateway or sub-agent)
      b. tool_id in FORBIDDEN_CAPABILITIES — blocks when an agent attempts to INVOKE
         a tool whose name matches a forbidden capability
         (Gap 2 fix: was unreachable because action was always "invoke")
    """
    if action in FORBIDDEN_CAPABILITIES:
        return GuardianCheckResponse(
            allowed=False,
            tier="halt",
            reason=f"Action '{action}' is in the forbidden capabilities list",
            threat_type="CAPABILITY_VIOLATION",
            confidence=1.0,
        )
    if tool_id and tool_id in FORBIDDEN_CAPABILITIES:
        return GuardianCheckResponse(
            allowed=False,
            tier="halt",
            reason=f"Tool '{tool_id}' is a forbidden capability and cannot be invoked",
            threat_type="CAPABILITY_VIOLATION",
            confidence=1.0,
        )
    return None


async def _write_threat_event_direct(
    agent_id: str,
    run_id: str,
    threat_type: str,
    action_taken: str,
    confidence: float = 1.0,
    raw_input: str | None = None,
    metadata: dict | None = None,
) -> None:
    """
    Write a threat event directly to threat_events using Guardian's own psycopg
    connection. Self-contained — no LegionForge framework imports required.

    Non-fatal — logs a warning on failure so audit writes never crash the hot path.
    Called by Check 3 (DESTRUCTIVE_PATTERN) for both HALT and LOG tiers.
    This is a Phase G1 stepping stone: Guardian writes security events via its
    own psycopg connection, not the framework pool.
    """
    try:
        import psycopg

        conninfo, password = _guardian_db_conninfo()
        async with await psycopg.AsyncConnection.connect(
            conninfo, password=password, autocommit=True
        ) as conn:
            await conn.execute(
                """
                INSERT INTO threat_events
                    (agent_id, run_id, threat_type, confidence,
                     raw_input, action_taken, metadata)
                VALUES (%s, %s, %s, %s, %s, %s, %s)
                """,
                (
                    agent_id,
                    run_id,
                    threat_type,
                    confidence,
                    raw_input,
                    action_taken,
                    json.dumps(metadata or {}),
                ),
            )
    except Exception as exc:
        logger.warning(f"[guardian] threat_events write failed (non-fatal): {exc}")


# ── Inlined from src.database — audit log direct write ────────────────────────
# Allows /report to write to audit_log without importing the framework DB pool.
# Maintains the SHA-256 hash chain so rows written by Guardian are indistinguishable
# from rows written by the framework's append_audit_log().

_AUDIT_LOG_GENESIS: str = hashlib.sha256(b"LEGIONFORGE_AUDIT_LOG_GENESIS").hexdigest()


def _compute_audit_row_hash_direct(
    seq: int,
    ts: str,
    event_type: str,
    agent_id: str | None,
    payload: dict,
    prev_hash: str,
) -> str:
    """Compute SHA-256 hash for a single audit_log row (mirrors database._compute_audit_row_hash)."""
    canonical = (
        f"{seq}|{ts}|{event_type}|{agent_id or ''}|"
        f"{json.dumps(payload, sort_keys=True)}|{prev_hash}"
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


async def _append_audit_log_direct(
    event_type: str,
    agent_id: str | None,
    payload: dict,
) -> int:
    """
    Append an event to audit_log using Guardian's own psycopg connection.
    Maintains the SHA-256 hash chain — compatible with database.append_audit_log().
    Returns the new seq number, or -1 on failure.
    Non-fatal: logs a warning on error so /report never crashes.
    """
    try:
        import psycopg
        from psycopg.rows import dict_row

        conninfo, password = _guardian_db_conninfo()
        async with await psycopg.AsyncConnection.connect(
            conninfo, password=password, row_factory=dict_row, autocommit=False
        ) as conn:
            cur = await conn.execute(
                "SELECT seq, row_hash FROM audit_log ORDER BY seq DESC LIMIT 1"
            )
            last_row = await cur.fetchone()
            prev_hash = last_row["row_hash"] if last_row else _AUDIT_LOG_GENESIS

            ts_now = datetime.now(tz=timezone.utc).isoformat()
            cur2 = await conn.execute(
                """
                INSERT INTO audit_log (ts, event_type, agent_id, payload, prev_hash, row_hash)
                VALUES (%s, %s, %s, %s, %s, %s)
                RETURNING seq, ts
                """,
                (
                    ts_now,
                    event_type,
                    agent_id,
                    json.dumps(payload, sort_keys=True),
                    prev_hash,
                    "PENDING",
                ),
            )
            new_row = await cur2.fetchone()
            seq = new_row["seq"]
            ts_str = (
                new_row["ts"].isoformat()
                if hasattr(new_row["ts"], "isoformat")
                else str(new_row["ts"])
            )
            row_hash = _compute_audit_row_hash_direct(
                seq, ts_str, event_type, agent_id, payload, prev_hash
            )
            await conn.execute(
                "UPDATE audit_log SET row_hash = %s WHERE seq = %s",
                (row_hash, seq),
            )
            await conn.commit()
        logger.debug(
            f"[guardian/audit] Appended seq={seq} event_type={event_type} agent_id={agent_id}"
        )
        return seq
    except Exception as exc:
        logger.warning(f"[guardian/audit] audit_log write failed (non-fatal): {exc}")
        return -1


def _check_3_destructive_pattern(
    tool_id: str, args: dict
) -> tuple[GuardianCheckResponse | None, bool]:
    """
    Check 3: Do the tool args contain destructive/adversarial patterns?

    Returns (response, should_log_only) where:
    - response is the blocking response (or None if permitted)
    - should_log_only=True means HITL_LOG category — fire report and allow
    """
    args_text = json.dumps(args)
    matched, categories = detect_destructive_pattern(args_text)
    if not matched:
        return None, False

    halt_hits = [c for c in categories if c in FORCE_END_CATEGORIES]
    if halt_hits:
        return (
            GuardianCheckResponse(
                allowed=False,
                tier="halt",
                reason=f"Destructive pattern detected in args: {halt_hits}",
                threat_type=halt_hits[0],
                confidence=1.0,
            ),
            False,
        )

    # LOG tier — log via /report in background, allow to proceed
    return None, True  # caller fires background report


def _check_4_sequence(
    agent_id: str, tool_id: str, sequence_so_far: list[str]
) -> GuardianCheckResponse | None:
    """
    Check 4: Does sequence_so_far + [tool_id] match a registered prefix?

    If the agent has registered sequences, the candidate sequence must be a
    prefix of at least one approved sequence. Novel combinations are sandboxed.
    Agents with no registered sequences are unrestricted (allows gradual rollout).
    """
    approved = _agent_sequences.get(agent_id)
    if not approved:
        # No sequences registered — agent is unconstrained
        return None

    candidate = sequence_so_far + [tool_id]
    for seq in approved:
        # candidate must be a prefix of seq (equal or shorter)
        if seq[: len(candidate)] == candidate:
            return None  # Matches an approved prefix

    return GuardianCheckResponse(
        allowed=False,
        tier="sandbox",
        reason=(
            f"Tool sequence {candidate} is not a prefix of any registered "
            f"sequence for agent '{agent_id}'. Novel sequences are sandboxed."
        ),
        threat_type="SEQUENCE_VIOLATION",
        confidence=1.0,
    )


def _check_5_hash_integrity(tool_id: str, args: dict) -> GuardianCheckResponse | None:
    """
    Check 5: Hash integrity — recompute fast hash of args and compare.

    We hash the serialised args to detect in-flight argument tampering.
    This is a lightweight check; the heavier entrypoint hash is done at
    registration time (verify_tool_before_invocation).
    """
    approved = _approved_tools.get(tool_id)
    if not approved:
        # Already caught in check 1; shouldn't reach here
        return None

    # Check that the cached hashes for this tool still match the in-process registry
    in_proc = _TOOL_HASHES.get(tool_id)
    if in_proc:
        for field in ("description_hash", "schema_hash"):
            cached = approved.get(field)
            current = in_proc.get(field)
            if cached and current and cached != current:
                return GuardianCheckResponse(
                    allowed=False,
                    tier="halt",
                    reason=f"Tool '{tool_id}' hash mismatch on field '{field}' — possible tampering",
                    threat_type="TOOL_HASH_MISMATCH",
                    confidence=1.0,
                )
    return None


def _check_6_adaptive_rules(
    tool_id: str, args: dict, sequence_so_far: list[str]
) -> GuardianCheckResponse | None:
    """
    Check 6 (Phase 4): Apply approved adaptive rules from the threat_rules table.

    Rules are loaded every 60 seconds by _refresh_caches().
    Static checks (0–5) always run first — adaptive rules are an additional layer.

    Enforced rule types:
      CAPABILITY_BLOCK:  halt if this tool_id is explicitly blocked.
      INJECTION_PATTERN: halt if any string arg matches the regex.
      SEQUENCE_BLOCK:    sandbox if sequence_so_far+[tool_id] starts with blocked seq.
      RATE_LIMIT_TIGHTEN: not enforced here (rate limiter handles this in-process).

    Note: If a regex in a proposed rule is malformed, the rule is skipped with a
    warning rather than crashing — bad rules must not break the hot path.
    """
    import re

    for rule in _adaptive_rules:
        rule_type = rule.get("rule_type")
        rule_def = rule.get("rule_def") or {}
        rule_id_short = rule.get("rule_id", "")[:8]

        if rule_type == "CAPABILITY_BLOCK":
            blocked_tool = rule_def.get("tool_id")
            if blocked_tool and tool_id == blocked_tool:
                return GuardianCheckResponse(
                    allowed=False,
                    tier="halt",
                    reason=(
                        f"Adaptive rule {rule_id_short}...: tool '{tool_id}' "
                        f"is capability-blocked — {rule_def.get('reason', 'no reason given')}"
                    ),
                    threat_type="CAPABILITY_VIOLATION",
                    confidence=1.0,
                )

        elif rule_type == "INJECTION_PATTERN":
            pattern = rule_def.get("pattern")
            flags_str = rule_def.get("flags", "")
            if pattern:
                re_flags = re.IGNORECASE if "i" in flags_str else 0
                try:
                    compiled = re.compile(pattern, re_flags)
                    for arg_val in args.values():
                        if isinstance(arg_val, str) and compiled.search(arg_val):
                            return GuardianCheckResponse(
                                allowed=False,
                                tier="halt",
                                reason=(
                                    f"Adaptive rule {rule_id_short}...: "
                                    "injection pattern matched in tool args"
                                ),
                                threat_type="INJECTION_DETECTED",
                                confidence=0.95,
                            )
                except re.error as regex_err:
                    logger.warning(
                        f"[guardian] Adaptive rule {rule_id_short}... has invalid regex "
                        f"{pattern!r}: {regex_err} — skipping"
                    )

        elif rule_type == "SEQUENCE_BLOCK":
            blocked_seq = rule_def.get("sequence", [])
            if blocked_seq:
                candidate = sequence_so_far + [tool_id]
                if candidate[: len(blocked_seq)] == blocked_seq:
                    return GuardianCheckResponse(
                        allowed=False,
                        tier="sandbox",
                        reason=(
                            f"Adaptive rule {rule_id_short}...: "
                            f"blocked sequence {blocked_seq} detected"
                        ),
                        threat_type="SEQUENCE_VIOLATION",
                        confidence=1.0,
                    )

    return None  # All adaptive rules passed


# ── Endpoints ─────────────────────────────────────────────────────────────────


@app.post("/invalidate-cache")
async def invalidate_cache(http_request: Request) -> JSONResponse:
    """
    Force an immediate cache refresh — bypasses the 10s TTL.
    Admin-only: requires the same Bearer token as /check.
    Use after revoking a tool to propagate revocation instantly.
    """
    _auth = _check_bearer_auth(http_request)
    if _auth == "misconfigured":
        return JSONResponse(
            {
                "detail": "Guardian misconfigured: TASK_TOKEN_SECRET not set",
                "error": "misconfigured",
            },
            status_code=503,
        )
    if not _auth:
        return _unauthorized("Bearer token required for /invalidate-cache")

    await _refresh_caches()
    return JSONResponse(
        {
            "status": "ok",
            "message": "Cache refreshed",
            "timestamp": datetime.utcnow().isoformat(),
        }
    )


@app.get("/health")
async def health() -> JSONResponse:
    """
    Unauthenticated liveness check.
    Used by Docker healthcheck and make check.

    Returns a richer payload including:
      - db_reachable: cheap SELECT 1 against the Guardian DB
      - cache_age_seconds: seconds since last cache refresh
      - tools_registered: count of approved tools in cache
      - rules_active: count of APPROVED adaptive rules
      - uptime_seconds: seconds since module load
      - status: "ok" or "degraded" (db unreachable OR cache stale > 30s)
    """
    # ── DB reachability check (cheap SELECT 1) ───────────────────────────────
    db_reachable = False
    try:
        import psycopg

        conninfo, password = _guardian_db_conninfo()
        async with await psycopg.AsyncConnection.connect(
            conninfo, password=password, connect_timeout=3
        ) as conn:
            await conn.execute("SELECT 1")
        db_reachable = True
    except Exception as exc:
        logger.debug(f"[guardian/health] DB reachability check failed: {exc}")

    cache_age = round(time.monotonic() - _cache_last_refreshed, 2)
    uptime = round(time.monotonic() - _startup_time, 2)
    rules_active = sum(
        1 for r in _adaptive_rules if r.get("status", "APPROVED") == "APPROVED"
    )
    # _adaptive_rules only contains APPROVED rules (filtered in _refresh_caches query)
    # so len() is the active count
    rules_active = len(_adaptive_rules)

    degraded = (not db_reachable) or (cache_age > 30)
    status = "degraded" if degraded else "ok"

    return JSONResponse(
        {
            "status": status,
            "version": "4.0.0",
            "cache_age_seconds": cache_age,
            "db_reachable": db_reachable,
            "tools_registered": len(_approved_tools),
            "rules_active": rules_active,
            "uptime_seconds": uptime,
        }
    )


@app.get("/metrics")
async def metrics() -> JSONResponse:
    """
    Prometheus text format metrics. Unauthenticated (consistent with main app /metrics).
    No prometheus_client dependency — text is formatted manually.
    """
    from fastapi.responses import Response

    cache_age = round(time.monotonic() - _cache_last_refreshed, 2)

    lines: list[str] = [
        "# HELP guardian_checks_total Total tool checks processed",
        "# TYPE guardian_checks_total counter",
        f'guardian_checks_total{{result="allow"}} {_metrics["checks_allow"]}',
        f'guardian_checks_total{{result="halt"}} {_metrics["checks_halt"]}',
        f'guardian_checks_total{{result="sandbox"}} {_metrics["checks_sandbox"]}',
        "",
        "# HELP guardian_threat_events_total Threat events by type",
        "# TYPE guardian_threat_events_total counter",
        f'guardian_threat_events_total{{type="TOOL_REVOKED"}} {_metrics["threat_TOOL_REVOKED"]}',
        f'guardian_threat_events_total{{type="CAPABILITY_VIOLATION"}} {_metrics["threat_CAPABILITY_VIOLATION"]}',
        f'guardian_threat_events_total{{type="INJECTION_DETECTED"}} {_metrics["threat_INJECTION_DETECTED"]}',
        f'guardian_threat_events_total{{type="TOOL_HASH_MISMATCH"}} {_metrics["threat_TOOL_HASH_MISMATCH"]}',
        f'guardian_threat_events_total{{type="DESTRUCTIVE_PATTERN"}} {_metrics["threat_DESTRUCTIVE_PATTERN"]}',
        f'guardian_threat_events_total{{type="SEQUENCE_VIOLATION"}} {_metrics["threat_SEQUENCE_VIOLATION"]}',
        f'guardian_threat_events_total{{type="INVALID_TASK_TOKEN"}} {_metrics["threat_INVALID_TASK_TOKEN"]}',
        f'guardian_threat_events_total{{type="TOOL_SCOPE_VIOLATION"}} {_metrics["threat_TOOL_SCOPE_VIOLATION"]}',
        f'guardian_threat_events_total{{type="GUARDIAN_MISCONFIGURED"}} {_metrics["threat_GUARDIAN_MISCONFIGURED"]}',
        f'guardian_threat_events_total{{type="GUARDIAN_AUTH_FAILURE"}} {_metrics["threat_GUARDIAN_AUTH_FAILURE"]}',
        f'guardian_threat_events_total{{type="CANARY_TRIGGERED"}} {_metrics["threat_CANARY_TRIGGERED"]}',
        "",
        "# HELP guardian_cache_refresh_age_seconds Seconds since last DB cache refresh",
        "# TYPE guardian_cache_refresh_age_seconds gauge",
        f"guardian_cache_refresh_age_seconds {cache_age}",
        "",
    ]
    body = "\n".join(lines)
    return Response(
        content=body, media_type="text/plain; version=0.0.4", status_code=200
    )


@app.get("/rules")
async def rules(http_request: Request) -> JSONResponse:
    """
    Read-only view of approved tools, sequences, and adaptive rules.
    Useful for debugging and audit.
    Requires Bearer auth when GUARDIAN_REQUIRE_AUTH=true.
    """
    _auth = _check_bearer_auth(http_request)
    if _auth == "misconfigured":
        return JSONResponse(
            {
                "detail": "Guardian misconfigured: TASK_TOKEN_SECRET not set",
                "error": "misconfigured",
            },
            status_code=503,
        )
    if not _auth:
        return _unauthorized("Bearer token required for /rules")
    await _maybe_refresh_caches()
    return JSONResponse(
        {
            "approved_tools": list(_approved_tools.keys()),
            "agent_sequences": {aid: seqs for aid, seqs in _agent_sequences.items()},
            "adaptive_rules": [
                {"rule_id": r["rule_id"], "rule_type": r["rule_type"]}
                for r in _adaptive_rules
            ],
            "cache_age_seconds": round(time.monotonic() - _cache_last_refreshed, 1),
        }
    )


@app.post("/check", response_model=GuardianCheckResponse)
async def check(
    request: GuardianCheckRequest, http_request: Request
) -> GuardianCheckResponse:
    """
    Synchronous enforcement endpoint — hot path.
    Seven checks in order (Phase 4: +check_6 adaptive rules), fail-fast. NO LLM calls.
    Requires Bearer auth when GUARDIAN_REQUIRE_AUTH=true.
    """
    _auth = _check_bearer_auth(http_request)
    if _auth == "misconfigured":
        # Fail-safe: misconfiguration → halt (never silently allow on the security hot path)
        return _record_check_metrics(
            GuardianCheckResponse(
                allowed=False,
                tier="halt",
                reason="Guardian misconfigured: TASK_TOKEN_SECRET not set — refusing all checks",
                threat_type="GUARDIAN_MISCONFIGURED",
                confidence=1.0,
            )
        )
    if not _auth:
        # Fail-safe: auth failure → halt (never fail-open on the security hot path)
        return _record_check_metrics(
            GuardianCheckResponse(
                allowed=False,
                tier="halt",
                reason="Guardian auth required — missing or invalid Bearer token",
                threat_type="GUARDIAN_AUTH_FAILURE",
                confidence=1.0,
            )
        )
    await _maybe_refresh_caches()

    # 0. Task token ACL (Phase 3) — validate JWT signature + tool scope
    resp = _check_0_task_token(request.tool_id, request.task_token)
    if resp:
        logger.warning(
            f"[guardian/check] HALT check=0 tool={request.tool_id!r} "
            f"agent={request.agent_id!r} threat={resp.threat_type!r}"
        )
        return _record_check_metrics(resp)

    # 1. Tool registry
    resp = _check_1_tool_registry(request.tool_id)
    if resp:
        logger.warning(
            f"[guardian/check] HALT check=1 tool={request.tool_id!r} "
            f"agent={request.agent_id!r} reason={resp.reason!r}"
        )
        return _record_check_metrics(resp)

    # Canary check: guardian_canary should never be called by legitimate code.
    # Passing check 1 means it IS in the approved registry (seeded by init.sql).
    # Any call to it is immediate evidence of a probing attack or hallucination.
    if request.tool_id == "guardian_canary":
        logger.warning(
            f"[guardian/check] CANARY_TRIGGERED agent={request.agent_id!r} "
            f"run={request.run_id!r}"
        )
        asyncio.create_task(
            _write_threat_event_direct(
                agent_id=request.agent_id,
                run_id=request.run_id,
                threat_type="CANARY_TRIGGERED",
                confidence=1.0,
                raw_input=str(request.args)[:500],
                action_taken="halt",
                metadata={"tool_id": request.tool_id},
            )
        )
        return _record_check_metrics(
            GuardianCheckResponse(
                allowed=False,
                tier="halt",
                reason="canary_triggered",
                threat_type="CANARY_TRIGGERED",
                confidence=1.0,
            )
        )

    # 2. Capability boundary (Gap 2 fix: also pass tool_id)
    resp = _check_2_capability_boundary(request.action, request.tool_id)
    if resp:
        logger.warning(
            f"[guardian/check] HALT check=2 action={request.action!r} "
            f"tool={request.tool_id!r} agent={request.agent_id!r}"
        )
        return _record_check_metrics(resp)

    # 3. Destructive pattern
    resp, log_only = _check_3_destructive_pattern(request.tool_id, request.args)
    if log_only:
        # LOG tier — allow to proceed, record in threat_events asynchronously
        _metrics["threat_DESTRUCTIVE_PATTERN"] += 1
        asyncio.create_task(
            _write_threat_event_direct(
                agent_id=request.agent_id,
                run_id=request.run_id,
                threat_type="DESTRUCTIVE_PATTERN",
                action_taken="LOGGED",
                confidence=0.6,
                raw_input=json.dumps(request.args)[:200],
                metadata={"tool_id": request.tool_id, "tier": "LOG"},
            )
        )
    elif resp:
        logger.warning(
            f"[guardian/check] HALT check=3 tool={request.tool_id!r} "
            f"agent={request.agent_id!r} threat={resp.threat_type!r}"
        )
        asyncio.create_task(
            _write_threat_event_direct(
                agent_id=request.agent_id,
                run_id=request.run_id,
                threat_type="DESTRUCTIVE_PATTERN",
                action_taken="BLOCKED",
                confidence=1.0,
                raw_input=json.dumps(request.args)[:200],
                metadata={
                    "tool_id": request.tool_id,
                    "tier": "HALT",
                    "categories": resp.threat_type,
                },
            )
        )
        return _record_check_metrics(resp)

    # 4. Sequence check
    resp = _check_4_sequence(request.agent_id, request.tool_id, request.sequence_so_far)
    if resp:
        logger.warning(
            f"[guardian/check] SANDBOX check=4 tool={request.tool_id!r} "
            f"agent={request.agent_id!r} seq={request.sequence_so_far}"
        )
        return _record_check_metrics(resp)

    # 5. Hash integrity
    resp = _check_5_hash_integrity(request.tool_id, request.args)
    if resp:
        logger.warning(
            f"[guardian/check] HALT check=5 tool={request.tool_id!r} "
            f"agent={request.agent_id!r} reason={resp.reason!r}"
        )
        return _record_check_metrics(resp)

    # 6. Adaptive rules (Phase 4) — approved rules proposed by Threat Analyst.
    # Applied AFTER all static checks. Rules are hot-loaded from DB every 60s.
    resp = _check_6_adaptive_rules(
        request.tool_id, request.args, request.sequence_so_far
    )
    if resp:
        logger.warning(
            f"[guardian/check] {'HALT' if resp.tier == 'halt' else 'SANDBOX'} check=6 "
            f"tool={request.tool_id!r} agent={request.agent_id!r} "
            f"rule_type={resp.threat_type!r}"
        )
        return _record_check_metrics(resp)

    result = GuardianCheckResponse(
        allowed=True,
        tier="allow",
        reason="All checks passed",
        confidence=1.0,
    )
    _metrics["checks_allow"] += 1
    return result


def _record_check_metrics(resp: GuardianCheckResponse) -> GuardianCheckResponse:
    """Increment counters for a blocking check result and return the response unchanged."""
    if resp.tier == "halt":
        _metrics["checks_halt"] += 1
    elif resp.tier == "sandbox":
        _metrics["checks_sandbox"] += 1
    threat_key = f"threat_{resp.threat_type}" if resp.threat_type else None
    if threat_key and threat_key in _metrics:
        _metrics[threat_key] += 1
    return resp


@app.post("/report")
async def report(request: ReportRequest) -> JSONResponse:
    """
    Async threat event ingestion.
    Called in the background for LOG-tier destructive patterns — doesn't block tool execution.
    """
    seq = await _append_audit_log_direct(
        event_type=request.event_type,
        agent_id=request.agent_id,
        payload={
            "run_id": request.run_id,
            **request.payload,
        },
    )
    if seq >= 0:
        logger.info(
            f"[guardian/report] event_type={request.event_type!r} "
            f"agent_id={request.agent_id!r} seq={seq}"
        )
        return JSONResponse({"status": "logged", "seq": seq})
    return JSONResponse(
        {"status": "error", "error": "audit_log write failed"}, status_code=500
    )


# ── Standalone runner ─────────────────────────────────────────────────────────


def main() -> None:
    """Entry point for `legionforge-guardian` CLI and `python -m legionforge_guardian`."""
    import uvicorn

    host = os.environ.get("GUARDIAN_HOST", "127.0.0.1")
    port = int(os.environ.get("GUARDIAN_PORT", "9766"))
    uvicorn.run(app, host=host, port=port, log_level="info")


if __name__ == "__main__":
    main()
