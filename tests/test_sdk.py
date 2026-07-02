"""
packages/guardian/tests/test_sdk.py
─────────────────────────────────────
Tests for legionforge_guardian.sdk.client.

These tests run standalone — no LegionForge PYTHONPATH required.
They mock the HTTP layer so no running Guardian sidecar is needed.
"""

from __future__ import annotations

import pytest
import httpx
import respx

from legionforge_guardian.sdk.client import GuardianClient, guardian_check

# ── GuardianClient.check ──────────────────────────────────────────────────────


@pytest.mark.asyncio
@respx.mock
async def test_client_check_allowed():
    respx.post("http://localhost:9766/check").mock(
        return_value=httpx.Response(
            200,
            json={
                "allowed": True,
                "tier": "allow",
                "reason": "all checks passed",
                "confidence": 1.0,
            },
        )
    )
    client = GuardianClient()
    result = await client.check(
        tool_id="web_fetch",
        action="invoke",
        args={"url": "https://example.com"},
        agent_id="researcher",
        run_id="test-run-1",
        sequence_so_far=[],
    )
    assert result["allowed"] is True
    assert result["tier"] == "allow"


@pytest.mark.asyncio
@respx.mock
async def test_client_check_halt():
    respx.post("http://localhost:9766/check").mock(
        return_value=httpx.Response(
            200,
            json={
                "allowed": False,
                "tier": "halt",
                "reason": "CMD_INJECTION detected",
                "threat_type": "CMD_INJECTION",
                "confidence": 1.0,
            },
        )
    )
    client = GuardianClient()
    result = await client.check(
        tool_id="bash",
        action="invoke",
        args={"cmd": "ls | cat /etc/passwd"},
        agent_id="researcher",
        run_id="test-run-2",
        sequence_so_far=[],
    )
    assert result["allowed"] is False
    assert result["tier"] == "halt"
    assert result["threat_type"] == "CMD_INJECTION"


@pytest.mark.asyncio
async def test_client_check_network_error_returns_halt():
    """Network failure must return a synthetic halt — fail-safe."""
    client = GuardianClient(url="http://192.0.2.1:9766", timeout=0.01)
    result = await client.check(
        tool_id="web_fetch",
        action="invoke",
        args={},
        agent_id="researcher",
        run_id="test-run-3",
        sequence_so_far=[],
    )
    assert result["allowed"] is False
    assert result["tier"] == "halt"
    assert result["threat_type"] == "GUARDIAN_UNREACHABLE"


@pytest.mark.asyncio
@respx.mock
async def test_client_sends_auth_header():
    route = respx.post("http://localhost:9766/check").mock(
        return_value=httpx.Response(
            200,
            json={"allowed": True, "tier": "allow", "reason": "ok", "confidence": 1.0},
        )
    )
    client = GuardianClient(auth_token="my-secret")
    await client.check("tool", "invoke", {}, "agent", "run", [])
    assert route.called
    assert route.calls[0].request.headers.get("authorization") == "Bearer my-secret"


@pytest.mark.asyncio
@respx.mock
async def test_client_sends_task_token_when_provided():
    route = respx.post("http://localhost:9766/check").mock(
        return_value=httpx.Response(
            200,
            json={"allowed": True, "tier": "allow", "reason": "ok", "confidence": 1.0},
        )
    )
    client = GuardianClient()
    await client.check(
        "tool", "invoke", {}, "agent", "run", [], task_token="jwt-token-here"
    )
    import json

    body = json.loads(route.calls[0].request.content)
    assert body["task_token"] == "jwt-token-here"


@pytest.mark.asyncio
@respx.mock
async def test_client_omits_task_token_when_none():
    route = respx.post("http://localhost:9766/check").mock(
        return_value=httpx.Response(
            200,
            json={"allowed": True, "tier": "allow", "reason": "ok", "confidence": 1.0},
        )
    )
    client = GuardianClient()
    await client.check("tool", "invoke", {}, "agent", "run", [], task_token=None)
    import json

    body = json.loads(route.calls[0].request.content)
    assert "task_token" not in body


# ── GuardianClient.health ─────────────────────────────────────────────────────


@pytest.mark.asyncio
@respx.mock
async def test_client_health_true_on_200():
    respx.get("http://localhost:9766/health").mock(
        return_value=httpx.Response(200, json={"status": "ok"})
    )
    client = GuardianClient()
    assert await client.health() is True


@pytest.mark.asyncio
@respx.mock
async def test_client_health_false_on_503():
    respx.get("http://localhost:9766/health").mock(return_value=httpx.Response(503))
    client = GuardianClient()
    assert await client.health() is False


@pytest.mark.asyncio
async def test_client_health_false_on_network_error():
    client = GuardianClient(url="http://192.0.2.1:9766", timeout=0.01)
    assert await client.health() is False


# ── guardian_check convenience function ───────────────────────────────────────


@pytest.mark.asyncio
@respx.mock
async def test_guardian_check_convenience():
    respx.post("http://localhost:9766/check").mock(
        return_value=httpx.Response(
            200,
            json={"allowed": True, "tier": "allow", "reason": "ok", "confidence": 1.0},
        )
    )
    result = await guardian_check(
        tool_id="web_fetch",
        action="invoke",
        args={"url": "https://example.com"},
        agent_id="researcher",
        run_id="run-1",
        sequence_so_far=[],
    )
    assert result["allowed"] is True


@pytest.mark.asyncio
async def test_guardian_check_network_error_is_fail_safe():
    result = await guardian_check(
        tool_id="web_fetch",
        action="invoke",
        args={},
        agent_id="researcher",
        run_id="run-2",
        sequence_so_far=[],
        guardian_url="http://192.0.2.1:9766",
        timeout=0.01,
    )
    assert result["allowed"] is False
    assert result["threat_type"] == "GUARDIAN_UNREACHABLE"
