"""FastAPI application entrypoint."""

from __future__ import annotations

import logging
import os
import time
from contextlib import asynccontextmanager
from collections.abc import AsyncIterator

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware

from engine.core.config import get_settings
from engine.core.logging import setup_logging
from engine.api.errors import register_error_handlers
from engine.api.middleware.rate_limit import RateLimitMiddleware
from engine.api.middleware.request import RequestIDMiddleware, RequestSizeLimitMiddleware
from engine.api.middleware.metrics import PrometheusMiddleware, setup_metrics_route
from engine.api.routes import scans, projects, findings, reports, quickscan, webhooks, health, soul
from engine.api.routes.auth import router as auth_router
from engine.api.routes.dashboard import router as dashboard_router
from engine.api.routes.notifications import router as notifications_router
from engine.api.routes.diff import router as diff_router
from engine.api.routes.collaboration import router as collaboration_router
from engine.api.routes.orgs import router as orgs_router
from engine.api.routes.audit import router as audit_router
from engine.api.routes.nl_query import router as nl_query_router
from engine.api.routes.analytics import router as analytics_router

logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    """Startup and shutdown events."""
    settings = get_settings()
    setup_logging(env=settings.app_env, log_level="DEBUG" if settings.debug else "INFO")

    # Guard against running without explicit secret in production
    if settings.app_env == "production" and not os.environ.get("ZASEON_SECRET_KEY"):
        raise RuntimeError(
            "ZASEON_SECRET_KEY must be set explicitly in production. "
            "Generate one with: python -c \"import secrets; print(secrets.token_urlsafe(64))\""
        )

    logger.info("Starting %s in %s mode", settings.app_name, settings.app_env)
    yield
    logger.info("Shutting down ZASEON engine")


def create_app() -> FastAPI:
    """Create and configure the FastAPI application."""
    settings = get_settings()

    app = FastAPI(
        title="ZASEON API",
        description=(
            "Coverage-guided smart contract fuzzer and AI security scanner for the Soul Protocol.\n\n"
            "## Authentication\n"
            "Most endpoints require a Bearer JWT token or `X-API-Key` header.\n"
            "Obtain tokens via `POST /api/v1/auth/login` or create API keys in Settings."
        ),
        version="2.0.0",
        lifespan=lifespan,
        docs_url=None if settings.app_env == "production" else "/api/docs",
        redoc_url=None if settings.app_env == "production" else "/api/redoc",
        openapi_url=None if settings.app_env == "production" else "/api/openapi.json",
        openapi_tags=[
            {"name": "health", "description": "Liveness and readiness probes"},
            {"name": "auth", "description": "Authentication — login, register, API keys"},
            {"name": "dashboard", "description": "Dashboard aggregation endpoints"},
            {"name": "soul-fuzzer", "description": "PIL++ fuzzer campaigns, analysis, and introspection"},
            {"name": "scans", "description": "Full async scans (Celery-backed)"},
            {"name": "findings", "description": "Vulnerability findings CRUD"},
            {"name": "reports", "description": "Report generation (PDF/HTML/JSON/SARIF)"},
            {"name": "quickscan", "description": "Quick scan by address or source code"},
            {"name": "projects", "description": "Project management"},
            {"name": "webhooks", "description": "Webhook receivers (GitHub, etc.)"},
            {"name": "notifications", "description": "Notification integrations (Slack, Discord, PagerDuty)"},
            {"name": "collaboration", "description": "Comments, assignments, and SLA tracking"},
            {"name": "organizations", "description": "Multi-tenant organization management"},
            {"name": "audit", "description": "Immutable audit trail and SOC 2 compliance"},
            {"name": "nl-query", "description": "Natural-language scan and findings querying"},
            {"name": "analytics", "description": "Trend analytics, time-series data, and cache stats"},
        ],
        license_info={"name": "MIT", "url": "https://opensource.org/licenses/MIT"},
        contact={"name": "ZASEON Team", "url": "https://github.com/Soul-Research-Labs/SOUL"},
    )

    # ── CORS — configurable origins ──────────────────────────────────
    allowed_origins = [o.strip() for o in settings.cors_allowed_origins.split(",") if o.strip()]
    if settings.app_env == "production" and not allowed_origins:
        allowed_origins = [f"https://{settings.app_name.lower().replace(' ', '')}.io"]

    app.add_middleware(
        CORSMiddleware,
        allow_origins=allowed_origins,
        allow_credentials=True,
        allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
        allow_headers=["Authorization", "X-API-Key", "Content-Type", "X-Request-ID", "Accept"],
        expose_headers=["X-Request-ID", "X-RateLimit-Limit", "X-RateLimit-Remaining"],
    )

    # ── Middleware (outermost first) ─────────────────────────────────
    app.add_middleware(RequestIDMiddleware)
    app.add_middleware(RequestSizeLimitMiddleware)
    app.add_middleware(RateLimitMiddleware, redis_url=settings.redis_url)
    app.add_middleware(PrometheusMiddleware)
    # ── Security headers ─────────────────────────────────────
    @app.middleware("http")
    async def security_headers(request: Request, call_next):
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
        if settings.app_env == "production":
            response.headers["Strict-Transport-Security"] = "max-age=63072000; includeSubDomains; preload"
            response.headers["Content-Security-Policy"] = "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'"
        return response
    # ── Prometheus metrics endpoint ──────────────────────────────────
    setup_metrics_route(app)

    # ── Access logging middleware ────────────────────────────────────
    @app.middleware("http")
    async def access_log(request: Request, call_next):
        start = time.perf_counter()
        response = await call_next(request)
        elapsed = (time.perf_counter() - start) * 1000
        logger.info(
            "%s %s → %d (%.1fms)",
            request.method,
            request.url.path,
            response.status_code,
            elapsed,
            extra={"method": request.method, "path": request.url.path,
                   "status_code": response.status_code, "duration_ms": round(elapsed, 1)},
        )
        return response

    # ── Routes ───────────────────────────────────────────────────────
    app.include_router(health.router, prefix="/api", tags=["health"])
    app.include_router(auth_router, prefix="/api/v1/auth", tags=["auth"])
    app.include_router(dashboard_router, prefix="/api/v1/dashboard", tags=["dashboard"])
    app.include_router(projects.router, prefix="/api/v1/projects", tags=["projects"])
    app.include_router(scans.router, prefix="/api/v1/scans", tags=["scans"])
    app.include_router(findings.router, prefix="/api/v1/findings", tags=["findings"])
    app.include_router(reports.router, prefix="/api/v1/reports", tags=["reports"])
    app.include_router(quickscan.router, prefix="/api/v1/quickscan", tags=["quickscan"])
    app.include_router(soul.router, prefix="/api/v1/soul", tags=["soul-fuzzer"])
    app.include_router(webhooks.router, prefix="/api/webhooks", tags=["webhooks"])
    app.include_router(notifications_router, prefix="/api/v1/notifications", tags=["notifications"])
    app.include_router(diff_router, prefix="/api/v1/findings", tags=["findings"])
    app.include_router(collaboration_router, prefix="/api/v1/collaboration", tags=["collaboration"])
    app.include_router(orgs_router, prefix="/api/v1/orgs", tags=["organizations"])
    app.include_router(audit_router, prefix="/api/v1/audit", tags=["audit"])
    app.include_router(nl_query_router, prefix="/api/v1/query", tags=["nl-query"])
    app.include_router(analytics_router, prefix="/api", tags=["analytics"])

    # ── Structured error handlers ──────────────────────────────────
    register_error_handlers(app)

    return app


app = create_app()
