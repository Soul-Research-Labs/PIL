"""Integration tests for core API routes.

These tests exercise the real FastAPI app against an in-memory SQLite database
to verify:
  - Authentication enforcement (401 for anon, 200/201 for auth'd)
  - CRUD operations via the JSON API
  - Correct response schemas

Run with:
    pytest engine/tests/test_integration.py -v
"""

from __future__ import annotations

import pytest
from httpx import AsyncClient

# Import the integration fixtures so pytest discovers them.
pytest_plugins = ["engine.tests.conftest_integration"]


# ── Health ───────────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_health(anon_client: AsyncClient):
    """Health endpoint should be publicly accessible."""
    resp = await anon_client.get("/api/health")
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "healthy"


# ── Auth enforcement ─────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_dashboard_requires_auth(anon_client: AsyncClient):
    """Dashboard stats must return 401/403 without a token."""
    resp = await anon_client.get("/api/v1/dashboard/stats")
    assert resp.status_code in (401, 403)


@pytest.mark.asyncio
async def test_projects_requires_auth(anon_client: AsyncClient):
    """Projects listing must require auth."""
    resp = await anon_client.get("/api/v1/projects/")
    assert resp.status_code in (401, 403)


@pytest.mark.asyncio
async def test_findings_requires_auth(anon_client: AsyncClient):
    """Findings listing must require auth."""
    resp = await anon_client.get("/api/v1/findings/")
    assert resp.status_code in (401, 403)


@pytest.mark.asyncio
async def test_reports_requires_auth(anon_client: AsyncClient):
    """Reports listing must require auth."""
    resp = await anon_client.get("/api/v1/reports/")
    assert resp.status_code in (401, 403)


# ── Authenticated CRUD ───────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_list_projects_empty(auth_client: AsyncClient):
    """Authenticated user gets an empty project list initially."""
    resp = await auth_client.get("/api/v1/projects/")
    assert resp.status_code == 200
    assert resp.json() == []


@pytest.mark.asyncio
async def test_list_findings_empty(auth_client: AsyncClient):
    """Authenticated user gets an empty findings list initially."""
    resp = await auth_client.get("/api/v1/findings/")
    assert resp.status_code == 200
    assert resp.json() == []


@pytest.mark.asyncio
async def test_list_reports_empty(auth_client: AsyncClient):
    """Authenticated user gets an empty reports list initially."""
    resp = await auth_client.get("/api/v1/reports/")
    assert resp.status_code == 200
    assert resp.json() == []


# ── Auth routes ──────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_get_me(auth_client: AsyncClient):
    """GET /auth/me returns the authenticated user's profile."""
    resp = await auth_client.get("/api/v1/auth/me")
    assert resp.status_code == 200
    data = resp.json()
    assert "username" in data
    assert "email" in data


@pytest.mark.asyncio
async def test_patch_me(auth_client: AsyncClient):
    """PATCH /auth/me updates display name."""
    resp = await auth_client.patch(
        "/api/v1/auth/me",
        json={"display_name": "Updated Name"},
    )
    assert resp.status_code == 200
    assert resp.json()["display_name"] == "Updated Name"


# ── QuickScan auth enforcement ───────────────────────────────────────────────


@pytest.mark.asyncio
async def test_quickscan_requires_auth(anon_client: AsyncClient):
    """QuickScan POST endpoints must require auth."""
    resp = await anon_client.post(
        "/api/v1/quickscan/source",
        json={"source_code": "pragma solidity ^0.8.0;"},
    )
    assert resp.status_code in (401, 403)


# ── Soul fuzzer auth enforcement ─────────────────────────────────────────────


@pytest.mark.asyncio
async def test_soul_fuzz_requires_auth(anon_client: AsyncClient):
    """Soul fuzz POST must require auth."""
    resp = await anon_client.post(
        "/api/v1/soul/fuzz",
        json={
            "source_code": "pragma solidity ^0.8.0; contract X {}",
            "contract_name": "X",
        },
    )
    assert resp.status_code in (401, 403)
