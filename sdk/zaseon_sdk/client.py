"""ZASEON API client — async and sync interfaces."""

from __future__ import annotations

import asyncio
import time
from typing import Any

import httpx

from zaseon_sdk.models import (
    AnalyticsSummary,
    CursorPage,
    Finding,
    QuickScanResult,
    ScanConfig,
    ScanResult,
    ScanStatus,
)


class ZaseonError(Exception):
    """Base exception for ZASEON SDK errors."""

    def __init__(self, message: str, status_code: int | None = None, response: Any = None):
        super().__init__(message)
        self.status_code = status_code
        self.response = response


class ZaseonAuthError(ZaseonError):
    """Authentication/authorization error."""


class ZaseonRateLimitError(ZaseonError):
    """Rate limit exceeded."""

    def __init__(self, message: str, retry_after: int = 60, **kwargs):
        super().__init__(message, **kwargs)
        self.retry_after = retry_after


class ZaseonClient:
    """Async Python client for the ZASEON API.

    Usage::

        async with ZaseonClient(api_key="zsk_...") as client:
            result = await client.quick_scan(source_code="pragma solidity ^0.8.0; ...")
            for finding in result.findings:
                print(f"[{finding.severity.value}] {finding.title}")

    Or synchronously::

        client = ZaseonClient(api_key="zsk_...")
        result = client.quick_scan_sync(source_code="...source...")
        client.close_sync()
    """

    def __init__(
        self,
        api_key: str | None = None,
        base_url: str = "https://api.zaseon.dev",
        token: str | None = None,
        timeout: float = 120.0,
        max_retries: int = 3,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self._timeout = timeout
        self._max_retries = max_retries

        headers: dict[str, str] = {
            "User-Agent": "zaseon-sdk/0.1.0",
            "Accept": "application/json",
        }
        if api_key:
            headers["X-API-Key"] = api_key
        elif token:
            headers["Authorization"] = f"Bearer {token}"

        self._client = httpx.AsyncClient(
            base_url=self.base_url,
            headers=headers,
            timeout=httpx.Timeout(timeout),
        )

    # ── Context manager ──────────────────────────────────────────────

    async def __aenter__(self) -> ZaseonClient:
        return self

    async def __aexit__(self, *args) -> None:
        await self.close()

    async def close(self) -> None:
        """Close the underlying HTTP client."""
        await self._client.aclose()

    def close_sync(self) -> None:
        """Close synchronously."""
        asyncio.get_event_loop().run_until_complete(self.close())

    # ── HTTP primitives ──────────────────────────────────────────────

    async def _request(
        self,
        method: str,
        path: str,
        **kwargs,
    ) -> httpx.Response:
        """Make an HTTP request with retry logic."""
        url = f"/api/v1{path}" if not path.startswith("/api") else path
        last_exc: Exception | None = None

        for attempt in range(self._max_retries):
            try:
                resp = await self._client.request(method, url, **kwargs)

                if resp.status_code == 401:
                    raise ZaseonAuthError(
                        "Authentication failed — check your API key or token",
                        status_code=401,
                        response=resp.json() if resp.content else None,
                    )
                if resp.status_code == 429:
                    retry_after = int(resp.headers.get("Retry-After", "60"))
                    if attempt < self._max_retries - 1:
                        await asyncio.sleep(retry_after)
                        continue
                    raise ZaseonRateLimitError(
                        "Rate limit exceeded",
                        retry_after=retry_after,
                        status_code=429,
                    )
                if resp.status_code >= 500 and attempt < self._max_retries - 1:
                    await asyncio.sleep(2 ** attempt)
                    continue

                resp.raise_for_status()
                return resp

            except httpx.RequestError as exc:
                last_exc = exc
                if attempt < self._max_retries - 1:
                    await asyncio.sleep(2 ** attempt)
                    continue

        raise ZaseonError(f"Request failed after {self._max_retries} attempts: {last_exc}")

    async def _get(self, path: str, **kwargs) -> dict[str, Any]:
        resp = await self._request("GET", path, **kwargs)
        return resp.json()

    async def _post(self, path: str, **kwargs) -> dict[str, Any]:
        resp = await self._request("POST", path, **kwargs)
        return resp.json()

    # ── Quick Scan (synchronous result) ──────────────────────────────

    async def quick_scan(
        self,
        source_code: str,
        contract_name: str = "Contract",
    ) -> QuickScanResult:
        """Run a quick 60-second scan and return results immediately.

        Args:
            source_code: Solidity source code
            contract_name: Name of the main contract

        Returns:
            QuickScanResult with findings and score
        """
        data = await self._post(
            "/soul/quick-fuzz",
            json={"source_code": source_code, "contract_name": contract_name},
        )
        return QuickScanResult(**data)

    async def quick_scan_address(
        self,
        address: str,
        chain: str = "ethereum",
    ) -> QuickScanResult:
        """Quick-scan a deployed contract by address.

        Args:
            address: Contract address (0x...)
            chain: Chain identifier (ethereum, polygon, bsc, etc.)
        """
        data = await self._post(
            "/quickscan/address",
            json={"address": address, "chain": chain},
        )
        return QuickScanResult(**data)

    # ── Full Scan (async campaign) ───────────────────────────────────

    async def start_scan(self, config: ScanConfig) -> str:
        """Start a full fuzzing campaign. Returns the scan/campaign ID.

        Args:
            config: Scan configuration

        Returns:
            Campaign ID string
        """
        data = await self._post("/soul/fuzz", json=config.model_dump(exclude_none=True))
        return data.get("campaign_id", data.get("id", ""))

    async def get_scan(self, scan_id: str) -> ScanResult:
        """Get the current status and results of a scan.

        Args:
            scan_id: The campaign/scan ID returned by start_scan
        """
        data = await self._get(f"/soul/campaign/{scan_id}")
        return ScanResult(**data)

    async def wait_for_scan(
        self,
        scan_id: str,
        poll_interval: float = 5.0,
        timeout: float = 600.0,
    ) -> ScanResult:
        """Poll a scan until it completes or times out.

        Args:
            scan_id: Campaign ID
            poll_interval: Seconds between status checks
            timeout: Maximum seconds to wait

        Returns:
            Final ScanResult

        Raises:
            ZaseonError: If scan times out
        """
        start = time.monotonic()
        while time.monotonic() - start < timeout:
            result = await self.get_scan(scan_id)
            if result.status in (ScanStatus.COMPLETED, ScanStatus.FAILED, ScanStatus.CANCELLED):
                return result
            await asyncio.sleep(poll_interval)

        raise ZaseonError(f"Scan {scan_id} did not complete within {timeout}s")

    # ── Targeted Analysis ────────────────────────────────────────────

    async def symbolic_analysis(
        self,
        source_code: str,
        contract_name: str = "Contract",
    ) -> dict[str, Any]:
        """Run symbolic execution analysis."""
        return await self._post(
            "/soul/symbolic",
            json={"source_code": source_code, "contract_name": contract_name},
        )

    async def differential_test(
        self,
        source_v1: str,
        source_v2: str,
        contract_name: str = "Contract",
    ) -> dict[str, Any]:
        """Run differential testing between two contract versions."""
        return await self._post(
            "/soul/differential",
            json={
                "source_code_v1": source_v1,
                "source_code_v2": source_v2,
                "contract_name": contract_name,
            },
        )

    # ── Findings & Reports ───────────────────────────────────────────

    async def list_findings(
        self,
        scan_id: str | None = None,
        severity: str | None = None,
        cursor: str | None = None,
        limit: int = 50,
    ) -> CursorPage:
        """List findings with cursor-based pagination.

        Args:
            scan_id: Filter by scan ID
            severity: Filter by severity (critical, high, medium, low, info)
            cursor: Pagination cursor from previous response
            limit: Items per page (max 100)
        """
        params: dict[str, Any] = {"limit": min(limit, 100)}
        if scan_id:
            params["scan_id"] = scan_id
        if severity:
            params["severity"] = severity
        if cursor:
            params["cursor"] = cursor

        data = await self._get("/findings", params=params)
        return CursorPage(**data)

    async def get_report(
        self,
        scan_id: str,
        format: str = "json",
    ) -> dict[str, Any] | bytes:
        """Download a scan report.

        Args:
            scan_id: Scan/campaign ID
            format: Report format (json, sarif, html, pdf)

        Returns:
            Parsed JSON for json/sarif, raw bytes for html/pdf
        """
        resp = await self._request(
            "GET",
            f"/reports/{scan_id}",
            params={"format": format},
        )
        if format in ("html", "pdf"):
            return resp.content
        return resp.json()

    # ── Analytics ────────────────────────────────────────────────────

    async def get_analytics(
        self,
        days: int = 30,
        granularity: str = "day",
    ) -> AnalyticsSummary:
        """Get analytics summary.

        Args:
            days: Time range in days
            granularity: day | week | month
        """
        data = await self._get(
            "/analytics/summary",
            params={"days": days, "granularity": granularity},
        )
        return AnalyticsSummary(**data)

    # ── Auth helpers ─────────────────────────────────────────────────

    async def login(self, email: str, password: str) -> str:
        """Login and set the Bearer token. Returns access token.

        Args:
            email: User email
            password: User password
        """
        data = await self._post(
            "/auth/login",
            json={"email": email, "password": password},
        )
        token = data["access_token"]
        self._client.headers["Authorization"] = f"Bearer {token}"
        return token

    # ── Sync wrappers ────────────────────────────────────────────────

    def quick_scan_sync(self, source_code: str, contract_name: str = "Contract") -> QuickScanResult:
        """Synchronous wrapper for quick_scan."""
        return asyncio.get_event_loop().run_until_complete(
            self.quick_scan(source_code, contract_name)
        )

    def start_scan_sync(self, config: ScanConfig) -> str:
        """Synchronous wrapper for start_scan."""
        return asyncio.get_event_loop().run_until_complete(self.start_scan(config))

    def wait_for_scan_sync(self, scan_id: str, **kwargs) -> ScanResult:
        """Synchronous wrapper for wait_for_scan."""
        return asyncio.get_event_loop().run_until_complete(
            self.wait_for_scan(scan_id, **kwargs)
        )
