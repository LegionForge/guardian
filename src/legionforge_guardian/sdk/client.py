"""
legionforge_guardian.sdk.client
────────────────────────────────
Async HTTP client for the Guardian sidecar (/check, /report, /health).

Usage:
    from legionforge_guardian import guardian_check

    result = await guardian_check(
        tool_id="web_fetch",
        action="invoke",
        args={"url": "https://example.com"},
        agent_id="researcher",
        run_id="abc-123",
        sequence_so_far=[],
        guardian_url="http://localhost:9766",
        auth_token="your-task-token-secret",
    )
    if not result["allowed"]:
        raise RuntimeError(f"Guardian blocked: {result['reason']}")
"""

from __future__ import annotations

import logging
from typing import Any

import httpx

logger = logging.getLogger(__name__)

_DEFAULT_GUARDIAN_URL = "http://localhost:9766"
_DEFAULT_TIMEOUT = 2.0  # seconds — fail-safe: timeout → caller treats as halt


class GuardianClient:
    """
    Async HTTP client for the Guardian sidecar.

    Instantiate once and reuse across requests for connection pooling.
    The client is fail-safe: any network error returns a synthetic halt response
    rather than raising — callers should always check result["allowed"].
    """

    def __init__(
        self,
        url: str = _DEFAULT_GUARDIAN_URL,
        auth_token: str = "",  # nosec B107 — empty default means "no auth", not a hardcoded password
        timeout: float = _DEFAULT_TIMEOUT,
    ) -> None:
        self.url = url.rstrip("/")
        self.auth_token = auth_token
        self.timeout = timeout

    def _headers(self) -> dict[str, str]:
        if self.auth_token:
            return {"Authorization": f"Bearer {self.auth_token}"}
        return {}

    async def check(
        self,
        tool_id: str,
        action: str,
        args: dict[str, Any],
        agent_id: str,
        run_id: str,
        sequence_so_far: list[str],
        task_token: str | None = None,
    ) -> dict[str, Any]:
        """
        POST /check — synchronous enforcement.
        Returns the raw JSON response dict.
        On any network/timeout error, returns a synthetic halt response.
        """
        payload: dict[str, Any] = {
            "tool_id": tool_id,
            "action": action,
            "args": args,
            "agent_id": agent_id,
            "run_id": run_id,
            "sequence_so_far": sequence_so_far,
        }
        if task_token is not None:
            payload["task_token"] = task_token

        try:
            async with httpx.AsyncClient(
                timeout=self.timeout, headers=self._headers()
            ) as client:
                r = await client.post(f"{self.url}/check", json=payload)
                r.raise_for_status()
                return r.json()
        except Exception as exc:
            logger.error(f"[guardian-client] /check failed — treating as halt: {exc}")
            return {
                "allowed": False,
                "tier": "halt",
                "reason": f"Guardian unreachable: {exc}",
                "threat_type": "GUARDIAN_UNREACHABLE",
                "confidence": 1.0,
            }

    async def report(
        self,
        event_type: str,
        agent_id: str,
        run_id: str,
        payload: dict[str, Any],
    ) -> dict[str, Any]:
        """
        POST /report — async threat event ingestion.
        Returns the raw JSON response dict. Non-fatal on error.
        """
        body = {
            "event_type": event_type,
            "agent_id": agent_id,
            "run_id": run_id,
            "payload": payload,
        }
        try:
            async with httpx.AsyncClient(
                timeout=self.timeout, headers=self._headers()
            ) as client:
                r = await client.post(f"{self.url}/report", json=body)
                r.raise_for_status()
                return r.json()
        except Exception as exc:
            logger.warning(f"[guardian-client] /report failed (non-fatal): {exc}")
            return {"status": "error", "error": str(exc)}

    async def health(self) -> bool:
        """GET /health — returns True if Guardian responds 200."""
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                r = await client.get(f"{self.url}/health")
                return r.status_code == 200
        except Exception:
            return False


async def guardian_check(
    tool_id: str,
    action: str,
    args: dict[str, Any],
    agent_id: str,
    run_id: str,
    sequence_so_far: list[str],
    task_token: str | None = None,
    guardian_url: str = _DEFAULT_GUARDIAN_URL,
    auth_token: str = "",
    timeout: float = _DEFAULT_TIMEOUT,
) -> dict[str, Any]:
    """
    Convenience coroutine — single /check call without managing a client.

    Returns the Guardian response dict. Always check result["allowed"].
    On network error, returns a synthetic halt (fail-safe).

    Example:
        result = await guardian_check("web_fetch", "invoke", {"url": "..."}, ...)
        if not result["allowed"]:
            raise SecurityError(result["reason"])
    """
    client = GuardianClient(url=guardian_url, auth_token=auth_token, timeout=timeout)
    return await client.check(
        tool_id=tool_id,
        action=action,
        args=args,
        agent_id=agent_id,
        run_id=run_id,
        sequence_so_far=sequence_so_far,
        task_token=task_token,
    )
