"""Request middleware — request ID tracking and request size limits.

Adds:
  - X-Request-ID header propagation (or generation) for distributed tracing
  - Request body size enforcement to prevent abuse
"""

from __future__ import annotations

import logging
import uuid
from typing import Callable

from fastapi import Request, Response, status
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.types import ASGIApp

logger = logging.getLogger(__name__)

# 5 MB default max for source code uploads; configurable
DEFAULT_MAX_REQUEST_SIZE = 5 * 1024 * 1024  # 5 MB

# Endpoints that accept larger payloads
LARGE_PAYLOAD_PATHS = {
    "/api/v1/soul/fuzz",
    "/api/v1/soul/concolic",
    "/api/v1/soul/differential",
    "/api/v1/soul/property-test",
    "/api/v1/quickscan/source",
    "/api/v1/quickscan/deep",
}
LARGE_PAYLOAD_MAX = 20 * 1024 * 1024  # 20 MB


class RequestIDMiddleware(BaseHTTPMiddleware):
    """Propagate or generate X-Request-ID for every request."""

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        # Use client-provided ID or generate one
        request_id = request.headers.get("x-request-id") or str(uuid.uuid4())

        # Store on request state for downstream use (e.g., structured logging)
        request.state.request_id = request_id

        response = await call_next(request)
        response.headers["X-Request-ID"] = request_id
        return response


class RequestSizeLimitMiddleware(BaseHTTPMiddleware):
    """Enforce maximum request body size to prevent abuse."""

    def __init__(self, app: ASGIApp, default_max: int = DEFAULT_MAX_REQUEST_SIZE) -> None:
        super().__init__(app)
        self.default_max = default_max

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        # Only check content-length on POST/PUT/PATCH
        if request.method not in ("POST", "PUT", "PATCH"):
            return await call_next(request)

        content_length = request.headers.get("content-length")
        if content_length:
            size = int(content_length)
            path = request.url.path
            max_size = LARGE_PAYLOAD_MAX if path in LARGE_PAYLOAD_PATHS else self.default_max

            if size > max_size:
                return JSONResponse(
                    status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                    content={
                        "detail": f"Request body too large: {size} bytes (max: {max_size})",
                    },
                )

        return await call_next(request)
