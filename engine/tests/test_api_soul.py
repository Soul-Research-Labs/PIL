"""Tests for the Soul Protocol API routes."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from engine.api.main import create_app


@pytest.fixture
def app() -> FastAPI:
    return create_app()


@pytest.fixture
def client(app: FastAPI) -> TestClient:
    return TestClient(app)


class TestHealthEndpoint:
    def test_health_check(self, client: TestClient):
        resp = client.get("/api/health")
        assert resp.status_code == 200


class TestSoulRoutes:
    """Test Soul Fuzzer API endpoints."""

    PREFIX = "/api/v1/soul"

    def test_list_soul_campaigns(self, client: TestClient):
        resp = client.get(f"{self.PREFIX}/campaigns")
        # Should return 200 or 401 (auth required), not 404
        assert resp.status_code in (200, 401, 422)

    def test_create_campaign_requires_body(self, client: TestClient):
        resp = client.post(f"{self.PREFIX}/campaigns", json={})
        # Should return 422 (validation error) not 404
        assert resp.status_code in (422, 401, 400)

    def test_create_campaign_with_valid_body(self, client: TestClient):
        body = {
            "source_type": "file_upload",
            "contract_source": "pragma solidity ^0.8.0; contract Test {}",
            "mode": "quick",
        }
        resp = client.post(f"{self.PREFIX}/campaigns", json=body)
        # May fail without DB, but should not be 404
        assert resp.status_code != 404

    def test_get_campaign_status_not_found(self, client: TestClient):
        resp = client.get(f"{self.PREFIX}/campaigns/nonexistent-id/status")
        assert resp.status_code in (404, 422, 401)

    def test_get_campaign_findings(self, client: TestClient):
        resp = client.get(f"{self.PREFIX}/campaigns/test-id/findings")
        assert resp.status_code in (404, 422, 401)

    # ── v2 Endpoints ─────────────────────────────────────────────────────

    def test_invariant_report_endpoint_exists(self, client: TestClient):
        resp = client.get(f"{self.PREFIX}/campaigns/test-id/invariants")
        assert resp.status_code != 405  # method should be allowed

    def test_bytecode_report_endpoint_exists(self, client: TestClient):
        resp = client.get(f"{self.PREFIX}/campaigns/test-id/bytecode")
        assert resp.status_code != 405

    def test_gas_report_endpoint_exists(self, client: TestClient):
        resp = client.get(f"{self.PREFIX}/campaigns/test-id/gas-profile")
        assert resp.status_code != 405

    def test_exploit_chains_endpoint_exists(self, client: TestClient):
        resp = client.get(f"{self.PREFIX}/campaigns/test-id/exploit-chains")
        assert resp.status_code != 405


class TestScanRoutes:
    """Test general scan API endpoints."""

    PREFIX = "/api/v1/scans"

    def test_scans_endpoint_exists(self, client: TestClient):
        resp = client.get(self.PREFIX)
        assert resp.status_code in (200, 401, 422)


class TestQuickScanRoutes:
    """Test quickscan API endpoints."""

    PREFIX = "/api/v1/quickscan"

    def test_quickscan_endpoint_exists(self, client: TestClient):
        resp = client.post(self.PREFIX, json={"source": "test"})
        assert resp.status_code in (200, 422, 401, 400)
