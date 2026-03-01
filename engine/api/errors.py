"""Structured error responses for the ZASEON API.

Provides a consistent error envelope across all endpoints:

    {
        "error": {
            "code": "VALIDATION_ERROR",
            "message": "Human-readable description",
            "details": [...optional field-level errors...],
            "request_id": "abc-123"
        }
    }
"""

from __future__ import annotations

import logging
from enum import Enum
from typing import Any

from fastapi import Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from starlette.exceptions import HTTPException as StarletteHTTPException

logger = logging.getLogger(__name__)


# ── Error Codes ──────────────────────────────────────────────────────────────


class ErrorCode(str, Enum):
    """Standard error codes returned in the error envelope."""

    # 4xx client errors
    VALIDATION_ERROR = "VALIDATION_ERROR"
    NOT_FOUND = "NOT_FOUND"
    UNAUTHORIZED = "UNAUTHORIZED"
    FORBIDDEN = "FORBIDDEN"
    CONFLICT = "CONFLICT"
    RATE_LIMITED = "RATE_LIMITED"
    BAD_REQUEST = "BAD_REQUEST"
    PAYLOAD_TOO_LARGE = "PAYLOAD_TOO_LARGE"

    # 5xx server errors
    INTERNAL_ERROR = "INTERNAL_ERROR"
    SERVICE_UNAVAILABLE = "SERVICE_UNAVAILABLE"
    DEPENDENCY_ERROR = "DEPENDENCY_ERROR"
    TIMEOUT = "TIMEOUT"

    # Domain-specific
    COMPILATION_ERROR = "COMPILATION_ERROR"
    SCAN_FAILED = "SCAN_FAILED"
    CAMPAIGN_FAILED = "CAMPAIGN_FAILED"
    FORGE_UNAVAILABLE = "FORGE_UNAVAILABLE"
    LLM_UNAVAILABLE = "LLM_UNAVAILABLE"


# ── Error Schemas ────────────────────────────────────────────────────────────


class FieldError(BaseModel):
    """Individual field validation error."""

    field: str
    message: str
    type: str


class ErrorEnvelope(BaseModel):
    """Standard error response envelope."""

    code: str
    message: str
    details: list[FieldError] | list[dict[str, Any]] | None = None
    request_id: str | None = None


class ErrorResponse(BaseModel):
    """Top-level error response."""

    error: ErrorEnvelope


# ── HTTP status → error code mapping ────────────────────────────────────────

_STATUS_TO_CODE: dict[int, ErrorCode] = {
    400: ErrorCode.BAD_REQUEST,
    401: ErrorCode.UNAUTHORIZED,
    403: ErrorCode.FORBIDDEN,
    404: ErrorCode.NOT_FOUND,
    409: ErrorCode.CONFLICT,
    413: ErrorCode.PAYLOAD_TOO_LARGE,
    422: ErrorCode.VALIDATION_ERROR,
    429: ErrorCode.RATE_LIMITED,
    500: ErrorCode.INTERNAL_ERROR,
    502: ErrorCode.DEPENDENCY_ERROR,
    503: ErrorCode.SERVICE_UNAVAILABLE,
    504: ErrorCode.TIMEOUT,
}


def _get_request_id(request: Request) -> str | None:
    """Extract request ID from headers (set by RequestIDMiddleware)."""
    return request.headers.get("X-Request-ID") or getattr(request.state, "request_id", None)


# ── Exception Handlers ──────────────────────────────────────────────────────


async def validation_exception_handler(
    request: Request, exc: RequestValidationError
) -> JSONResponse:
    """Handle Pydantic / FastAPI validation errors with structured detail."""
    details = []
    for err in exc.errors():
        loc = err.get("loc", [])
        field = ".".join(str(l) for l in loc if l != "body")
        details.append(
            FieldError(
                field=field or "unknown",
                message=err.get("msg", "Invalid value"),
                type=err.get("type", "value_error"),
            ).model_dump()
        )

    body = ErrorResponse(
        error=ErrorEnvelope(
            code=ErrorCode.VALIDATION_ERROR.value,
            message=f"Request validation failed: {len(details)} error(s)",
            details=details,
            request_id=_get_request_id(request),
        )
    )
    return JSONResponse(status_code=422, content=body.model_dump())


async def http_exception_handler(
    request: Request, exc: StarletteHTTPException
) -> JSONResponse:
    """Handle HTTP exceptions with structured error envelope."""
    code = _STATUS_TO_CODE.get(exc.status_code, ErrorCode.INTERNAL_ERROR)

    body = ErrorResponse(
        error=ErrorEnvelope(
            code=code.value,
            message=str(exc.detail) if exc.detail else code.value,
            request_id=_get_request_id(request),
        )
    )
    return JSONResponse(status_code=exc.status_code, content=body.model_dump())


async def unhandled_exception_handler(
    request: Request, exc: Exception
) -> JSONResponse:
    """Handle unexpected exceptions — log full traceback, return generic error."""
    logger.exception(
        "Unhandled exception on %s %s: %s",
        request.method,
        request.url.path,
        exc,
    )

    body = ErrorResponse(
        error=ErrorEnvelope(
            code=ErrorCode.INTERNAL_ERROR.value,
            message="An internal server error occurred. Please try again later.",
            request_id=_get_request_id(request),
        )
    )
    return JSONResponse(status_code=500, content=body.model_dump())


# ── Convenience helpers for raising domain errors ────────────────────────────


class ZaseonAPIError(Exception):
    """Domain-specific API error with structured code + message."""

    def __init__(
        self,
        status_code: int,
        code: ErrorCode,
        message: str,
        details: list[dict[str, Any]] | None = None,
    ):
        self.status_code = status_code
        self.code = code
        self.message = message
        self.details = details
        super().__init__(message)


async def zaseon_error_handler(request: Request, exc: ZaseonAPIError) -> JSONResponse:
    """Handle ZaseonAPIError with structured envelope."""
    body = ErrorResponse(
        error=ErrorEnvelope(
            code=exc.code.value,
            message=exc.message,
            details=exc.details,
            request_id=_get_request_id(request),
        )
    )
    return JSONResponse(status_code=exc.status_code, content=body.model_dump())


def register_error_handlers(app: Any) -> None:
    """Register all structured error handlers on a FastAPI app."""
    app.add_exception_handler(RequestValidationError, validation_exception_handler)
    app.add_exception_handler(StarletteHTTPException, http_exception_handler)
    app.add_exception_handler(ZaseonAPIError, zaseon_error_handler)
    app.add_exception_handler(Exception, unhandled_exception_handler)
