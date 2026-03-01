"""Prometheus metrics middleware.

Exposes /api/metrics endpoint with request counts, latencies,
and custom business metrics for monitoring.
"""

from __future__ import annotations

import time
from typing import Callable

from fastapi import FastAPI, Request, Response
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import PlainTextResponse

# Lightweight in-process metrics (no dependency on prometheus_client)
# Compatible with Prometheus text exposition format


class _Counter:
    """Simple thread-safe counter."""

    def __init__(self, name: str, help_text: str, labels: list[str]) -> None:
        self.name = name
        self.help = help_text
        self.labels = labels
        self._values: dict[tuple, float] = {}

    def inc(self, label_values: tuple, amount: float = 1.0) -> None:
        key = label_values
        self._values[key] = self._values.get(key, 0) + amount

    def collect(self) -> list[str]:
        lines = [f"# HELP {self.name} {self.help}", f"# TYPE {self.name} counter"]
        for labels, value in sorted(self._values.items()):
            label_str = ",".join(f'{k}="{v}"' for k, v in zip(self.labels, labels))
            lines.append(f"{self.name}{{{label_str}}} {value}")
        return lines


class _Histogram:
    """Simple histogram with fixed buckets."""

    BUCKETS = [0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0]

    def __init__(self, name: str, help_text: str, labels: list[str]) -> None:
        self.name = name
        self.help = help_text
        self.labels = labels
        self._observations: dict[tuple, list[float]] = {}

    def observe(self, label_values: tuple, value: float) -> None:
        key = label_values
        if key not in self._observations:
            self._observations[key] = []
        self._observations[key].append(value)

    def collect(self) -> list[str]:
        lines = [f"# HELP {self.name} {self.help}", f"# TYPE {self.name} histogram"]
        for labels, observations in sorted(self._observations.items()):
            label_str = ",".join(f'{k}="{v}"' for k, v in zip(self.labels, labels))
            total = sum(observations)
            count = len(observations)
            for bucket in self.BUCKETS:
                le_count = sum(1 for o in observations if o <= bucket)
                lines.append(f'{self.name}_bucket{{{label_str},le="{bucket}"}} {le_count}')
            lines.append(f'{self.name}_bucket{{{label_str},le="+Inf"}} {count}')
            lines.append(f"{self.name}_sum{{{label_str}}} {total:.6f}")
            lines.append(f"{self.name}_count{{{label_str}}} {count}")
        return lines


class _Gauge:
    """Simple gauge metric."""

    def __init__(self, name: str, help_text: str) -> None:
        self.name = name
        self.help = help_text
        self._value: float = 0

    def set(self, value: float) -> None:
        self._value = value

    def inc(self, amount: float = 1.0) -> None:
        self._value += amount

    def dec(self, amount: float = 1.0) -> None:
        self._value -= amount

    def collect(self) -> list[str]:
        return [
            f"# HELP {self.name} {self.help}",
            f"# TYPE {self.name} gauge",
            f"{self.name} {self._value}",
        ]


# ── Global metrics ───────────────────────────────────────────────────────────

http_requests_total = _Counter(
    "zaseon_http_requests_total",
    "Total HTTP requests",
    ["method", "path", "status"],
)

http_request_duration = _Histogram(
    "zaseon_http_request_duration_seconds",
    "HTTP request duration in seconds",
    ["method", "path"],
)

active_requests = _Gauge(
    "zaseon_active_requests",
    "Number of currently active HTTP requests",
)

scans_total = _Counter(
    "zaseon_scans_total",
    "Total scans initiated",
    ["scan_type"],
)

soul_campaigns_total = _Counter(
    "zaseon_soul_campaigns_total",
    "Total Soul fuzzer campaigns initiated",
    ["mode"],
)

findings_total = _Counter(
    "zaseon_findings_total",
    "Total findings detected",
    ["severity"],
)


def collect_all_metrics() -> str:
    """Collect all metrics in Prometheus text exposition format."""
    all_lines: list[str] = []
    for metric in [
        http_requests_total,
        http_request_duration,
        active_requests,
        scans_total,
        soul_campaigns_total,
        findings_total,
    ]:
        all_lines.extend(metric.collect())
    return "\n".join(all_lines) + "\n"


# ── Middleware ────────────────────────────────────────────────────────────────


class PrometheusMiddleware(BaseHTTPMiddleware):
    """Collect HTTP request metrics."""

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        path = request.url.path

        # Skip metrics endpoint itself
        if path == "/api/metrics":
            return await call_next(request)

        # Normalize path (strip UUIDs and numeric IDs for cardinality control)
        import re
        normalized = re.sub(
            r"/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
            "/{id}",
            path,
        )
        normalized = re.sub(r"/\d+", "/{id}", normalized)

        method = request.method
        active_requests.inc()
        start = time.perf_counter()

        try:
            response = await call_next(request)
            status_code = str(response.status_code)
        except Exception:
            status_code = "500"
            raise
        finally:
            duration = time.perf_counter() - start
            active_requests.dec()
            http_requests_total.inc((method, normalized, status_code))
            http_request_duration.observe((method, normalized), duration)

        return response


def setup_metrics_route(app: FastAPI) -> None:
    """Register the /api/metrics endpoint (internal only)."""

    @app.get("/api/metrics", include_in_schema=False)
    async def metrics_endpoint(request: Request) -> PlainTextResponse:
        # V-015 FIX: Restrict metrics to localhost / internal networks
        client_host = request.client.host if request.client else ""
        allowed = ("127.0.0.1", "::1", "localhost")
        # Also allow Docker internal networks (RFC 1918 ranges only)
        is_internal = (
            client_host in allowed
            or client_host.startswith("10.")
            or client_host.startswith("192.168.")
            or any(
                client_host.startswith(f"172.{i}.")
                for i in range(16, 32)
            )
        )
        if not is_internal:
            from fastapi import HTTPException
            raise HTTPException(status_code=403, detail="Metrics endpoint restricted to internal access")
        return PlainTextResponse(
            collect_all_metrics(),
            media_type="text/plain; version=0.0.4; charset=utf-8",
        )
