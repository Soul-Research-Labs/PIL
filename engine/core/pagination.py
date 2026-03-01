"""Cursor-based pagination utilities for API endpoints.

Provides consistent, efficient, keyset-based pagination across all
list endpoints. Avoids the performance pitfalls of OFFSET-based
pagination on large tables.

Usage:
    from engine.core.pagination import CursorParams, CursorPage, paginate

    @router.get("/findings", response_model=CursorPage[FindingResponse])
    async def list_findings(params: CursorParams = Depends()):
        stmt = select(Finding).order_by(Finding.created_at.desc())
        return await paginate(session, stmt, params, id_col=Finding.id, order_col=Finding.created_at)
"""

from __future__ import annotations

import base64
import json
from datetime import datetime
from typing import Any, Generic, Sequence, TypeVar

from fastapi import Query
from pydantic import BaseModel, Field
from sqlalchemy import Select, asc, desc, or_
from sqlalchemy.ext.asyncio import AsyncSession

T = TypeVar("T")


# ── Cursor encoding ─────────────────────────────────────────────────────────


def encode_cursor(values: dict[str, Any]) -> str:
    """Encode pagination state into an opaque base64 cursor token."""
    raw = json.dumps(values, default=str)
    return base64.urlsafe_b64encode(raw.encode()).decode()


def decode_cursor(cursor: str) -> dict[str, Any]:
    """Decode a cursor token back into pagination values."""
    try:
        raw = base64.urlsafe_b64decode(cursor.encode()).decode()
        return json.loads(raw)
    except Exception:
        return {}


# ── Request params ───────────────────────────────────────────────────────────


class CursorParams:
    """FastAPI dependency for cursor-based pagination parameters."""

    def __init__(
        self,
        cursor: str | None = Query(None, description="Opaque pagination cursor from previous response"),
        limit: int = Query(20, ge=1, le=100, description="Maximum items to return"),
        direction: str = Query("desc", regex="^(asc|desc)$", description="Sort direction"),
    ):
        self.cursor = cursor
        self.limit = limit
        self.direction = direction

    @property
    def decoded(self) -> dict[str, Any]:
        if not self.cursor:
            return {}
        return decode_cursor(self.cursor)


# ── Response model ───────────────────────────────────────────────────────────


class CursorPage(BaseModel, Generic[T]):
    """Paginated response with cursor-based navigation."""

    items: list[T] = Field(default_factory=list)
    next_cursor: str | None = Field(None, description="Cursor for next page (null if last page)")
    prev_cursor: str | None = Field(None, description="Cursor for previous page (null if first page)")
    has_more: bool = Field(False, description="Whether more items exist beyond this page")
    total_count: int | None = Field(None, description="Total item count (included only if requested)")
    limit: int = Field(20)


# ── Pagination engine ────────────────────────────────────────────────────────


async def paginate(
    session: AsyncSession,
    stmt: Select,
    params: CursorParams,
    *,
    id_col: Any,
    order_col: Any,
    include_total: bool = False,
) -> CursorPage:
    """Apply cursor-based pagination to a SQLAlchemy select statement.

    Uses keyset pagination (WHERE + ORDER BY) for efficient large-table access.

    Args:
        session: Async SQLAlchemy session.
        stmt: Base select statement (without LIMIT/OFFSET).
        params: CursorParams dependency.
        id_col: The unique ID column (tiebreaker for equal order values).
        order_col: The column to order by (e.g., created_at).
        include_total: Whether to include total count (extra query).

    Returns:
        CursorPage with items, cursors, and pagination metadata.
    """
    sort_fn = desc if params.direction == "desc" else asc

    # Apply cursor filter (keyset pagination)
    decoded = params.decoded
    if decoded:
        cursor_val = decoded.get("v")
        cursor_id = decoded.get("id")

        if cursor_val is not None and cursor_id is not None:
            # Try to parse as datetime
            try:
                cursor_val = datetime.fromisoformat(cursor_val)
            except (TypeError, ValueError):
                pass

            if params.direction == "desc":
                stmt = stmt.where(
                    or_(
                        order_col < cursor_val,
                        (order_col == cursor_val) & (id_col < cursor_id),
                    )
                )
            else:
                stmt = stmt.where(
                    or_(
                        order_col > cursor_val,
                        (order_col == cursor_val) & (id_col > cursor_id),
                    )
                )

    # Order and limit (fetch one extra to detect has_more)
    stmt = stmt.order_by(sort_fn(order_col), sort_fn(id_col))
    stmt = stmt.limit(params.limit + 1)

    result = await session.execute(stmt)
    rows = list(result.scalars().all())

    has_more = len(rows) > params.limit
    if has_more:
        rows = rows[: params.limit]

    # Build cursors
    next_cursor = None
    if has_more and rows:
        last = rows[-1]
        next_cursor = encode_cursor({
            "v": str(getattr(last, order_col.key, "")),
            "id": str(getattr(last, id_col.key, "")),
        })

    prev_cursor = None
    if params.cursor and rows:
        first = rows[0]
        prev_cursor = encode_cursor({
            "v": str(getattr(first, order_col.key, "")),
            "id": str(getattr(first, id_col.key, "")),
            "dir": "prev",
        })

    # Optional total count
    total = None
    if include_total:
        from sqlalchemy import func, select as sa_select

        count_stmt = sa_select(func.count()).select_from(stmt.order_by(None).limit(None).subquery())
        total = (await session.execute(count_stmt)).scalar() or 0

    return CursorPage(
        items=rows,
        next_cursor=next_cursor,
        prev_cursor=prev_cursor,
        has_more=has_more,
        total_count=total,
        limit=params.limit,
    )
