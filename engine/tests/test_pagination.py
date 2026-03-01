"""Tests for cursor-based pagination (engine/core/pagination.py).

Covers:
- encode_cursor / decode_cursor round-trip
- CursorParams defaults and custom values
- CursorPage model schema
- paginate() with mock SQLAlchemy session (asc/desc, cursor follow, has_more)
"""

from __future__ import annotations

import json
import base64
import uuid
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from engine.core.pagination import (
    CursorPage,
    CursorParams,
    decode_cursor,
    encode_cursor,
)


# ── Cursor encoding / decoding ──────────────────────────────────────────


class TestCursorEncoding:
    """Test encode_cursor and decode_cursor."""

    def test_round_trip(self):
        original = {"v": "2025-01-15T00:00:00", "id": "abc-123"}
        token = encode_cursor(original)
        decoded = decode_cursor(token)
        assert decoded == original

    def test_encode_produces_base64(self):
        token = encode_cursor({"v": "test", "id": "1"})
        # Should be valid base64
        raw = base64.urlsafe_b64decode(token.encode())
        parsed = json.loads(raw)
        assert parsed["v"] == "test"

    def test_decode_invalid_returns_empty(self):
        result = decode_cursor("not-valid-base64!!!")
        assert result == {}

    def test_decode_empty_string(self):
        result = decode_cursor("")
        assert result == {}

    def test_encode_with_special_chars(self):
        original = {"v": "2025-01-01T00:00:00+00:00", "id": "uuid-with-dashes"}
        token = encode_cursor(original)
        decoded = decode_cursor(token)
        assert decoded == original

    def test_encode_with_numeric_values(self):
        original = {"v": 12345, "id": 67890}
        token = encode_cursor(original)
        decoded = decode_cursor(token)
        assert decoded["v"] == 12345
        assert decoded["id"] == 67890

    def test_encode_datetime_via_default_str(self):
        """encode_cursor uses json.dumps(default=str) for non-serializable types."""
        dt = datetime(2025, 6, 15, 12, 0, tzinfo=timezone.utc)
        token = encode_cursor({"v": str(dt), "id": "x"})
        decoded = decode_cursor(token)
        assert "2025" in decoded["v"]


# ── CursorParams ─────────────────────────────────────────────────────────


class TestCursorParams:
    """Test the CursorParams dependency."""

    def test_defaults(self):
        params = CursorParams()
        assert params.cursor is None
        assert params.limit == 20
        assert params.direction == "desc"

    def test_custom_values(self):
        params = CursorParams(cursor="abc", limit=50, direction="asc")
        assert params.cursor == "abc"
        assert params.limit == 50
        assert params.direction == "asc"

    def test_decoded_with_no_cursor(self):
        params = CursorParams()
        assert params.decoded == {}

    def test_decoded_with_cursor(self):
        token = encode_cursor({"v": "2025-01-01", "id": "123"})
        params = CursorParams(cursor=token)
        decoded = params.decoded
        assert decoded["v"] == "2025-01-01"
        assert decoded["id"] == "123"

    def test_decoded_with_invalid_cursor(self):
        params = CursorParams(cursor="garbage!!!")
        assert params.decoded == {}


# ── CursorPage model ────────────────────────────────────────────────────


class TestCursorPage:
    """Test the CursorPage response model."""

    def test_empty_page(self):
        page = CursorPage(items=[], has_more=False, limit=20)
        assert page.items == []
        assert page.next_cursor is None
        assert page.prev_cursor is None
        assert page.has_more is False
        assert page.total_count is None
        assert page.limit == 20

    def test_page_with_items(self):
        page = CursorPage(
            items=["a", "b", "c"],
            next_cursor="abc",
            has_more=True,
            limit=3,
            total_count=10,
        )
        assert len(page.items) == 3
        assert page.next_cursor == "abc"
        assert page.has_more is True
        assert page.total_count == 10

    def test_page_serialization(self):
        page = CursorPage(items=[1, 2, 3], has_more=True, limit=3)
        data = page.model_dump()
        assert data["items"] == [1, 2, 3]
        assert data["has_more"] is True
        assert data["next_cursor"] is None


# ── paginate() function ──────────────────────────────────────────────────


class TestPaginate:
    """Test the paginate() engine with mock session."""

    @pytest.mark.asyncio
    async def test_first_page_no_cursor(self):
        """Test first page request without cursor."""
        from engine.core.pagination import paginate

        # Create mock objects
        mock_item_1 = MagicMock()
        mock_item_1.id = uuid.uuid4()
        mock_item_1.created_at = datetime(2025, 1, 2, tzinfo=timezone.utc)

        mock_item_2 = MagicMock()
        mock_item_2.id = uuid.uuid4()
        mock_item_2.created_at = datetime(2025, 1, 1, tzinfo=timezone.utc)

        # Mock session.execute
        mock_result = MagicMock()
        mock_result.scalars.return_value.all.return_value = [mock_item_1, mock_item_2]

        mock_session = AsyncMock()
        mock_session.execute = AsyncMock(return_value=mock_result)

        # Mock the statement (needs .where, .order_by, .limit to be chainable)
        mock_stmt = MagicMock()
        mock_stmt.where.return_value = mock_stmt
        mock_stmt.order_by.return_value = mock_stmt
        mock_stmt.limit.return_value = mock_stmt

        params = CursorParams(limit=10)
        mock_id_col = MagicMock()
        mock_id_col.key = "id"
        mock_order_col = MagicMock()
        mock_order_col.key = "created_at"

        page = await paginate(
            mock_session, mock_stmt, params,
            id_col=mock_id_col, order_col=mock_order_col,
        )

        assert isinstance(page, CursorPage)
        assert len(page.items) == 2
        assert page.has_more is False
        assert page.next_cursor is None

    @pytest.mark.asyncio
    async def test_has_more_when_extra_row(self):
        """When fetched rows > limit, has_more should be True."""
        from engine.core.pagination import paginate

        items = []
        for i in range(4):
            m = MagicMock()
            m.id = str(uuid.uuid4())
            m.created_at = datetime(2025, 1, i + 1, tzinfo=timezone.utc)
            items.append(m)

        mock_result = MagicMock()
        mock_result.scalars.return_value.all.return_value = items  # 4 rows for limit=3

        mock_session = AsyncMock()
        mock_session.execute = AsyncMock(return_value=mock_result)

        mock_stmt = MagicMock()
        mock_stmt.where.return_value = mock_stmt
        mock_stmt.order_by.return_value = mock_stmt
        mock_stmt.limit.return_value = mock_stmt

        params = CursorParams(limit=3)
        mock_id_col = MagicMock()
        mock_id_col.key = "id"
        mock_order_col = MagicMock()
        mock_order_col.key = "created_at"

        page = await paginate(
            mock_session, mock_stmt, params,
            id_col=mock_id_col, order_col=mock_order_col,
        )

        assert page.has_more is True
        assert page.next_cursor is not None
        assert len(page.items) == 3  # Trimmed to limit

    @pytest.mark.asyncio
    async def test_empty_result(self):
        """Empty result should return empty page."""
        from engine.core.pagination import paginate

        mock_result = MagicMock()
        mock_result.scalars.return_value.all.return_value = []

        mock_session = AsyncMock()
        mock_session.execute = AsyncMock(return_value=mock_result)

        mock_stmt = MagicMock()
        mock_stmt.where.return_value = mock_stmt
        mock_stmt.order_by.return_value = mock_stmt
        mock_stmt.limit.return_value = mock_stmt

        params = CursorParams(limit=20)
        mock_id_col = MagicMock()
        mock_id_col.key = "id"
        mock_order_col = MagicMock()
        mock_order_col.key = "created_at"

        page = await paginate(
            mock_session, mock_stmt, params,
            id_col=mock_id_col, order_col=mock_order_col,
        )

        assert page.items == []
        assert page.has_more is False
        assert page.next_cursor is None
        assert page.prev_cursor is None

    @pytest.mark.asyncio
    async def test_with_cursor_param(self):
        """Test that cursor is applied to filter results."""
        from engine.core.pagination import paginate

        mock_item = MagicMock()
        mock_item.id = str(uuid.uuid4())
        mock_item.created_at = datetime(2025, 1, 1, tzinfo=timezone.utc)

        mock_result = MagicMock()
        mock_result.scalars.return_value.all.return_value = [mock_item]

        mock_session = AsyncMock()
        mock_session.execute = AsyncMock(return_value=mock_result)

        mock_stmt = MagicMock()
        mock_stmt.where.return_value = mock_stmt
        mock_stmt.order_by.return_value = mock_stmt
        mock_stmt.limit.return_value = mock_stmt

        cursor_token = encode_cursor({"v": "2025-01-02T00:00:00", "id": "prev-id"})
        params = CursorParams(cursor=cursor_token, limit=10)

        mock_id_col = MagicMock()
        mock_id_col.key = "id"
        mock_order_col = MagicMock()
        mock_order_col.key = "created_at"

        page = await paginate(
            mock_session, mock_stmt, params,
            id_col=mock_id_col, order_col=mock_order_col,
        )

        assert len(page.items) == 1
        # Should have a prev_cursor since we provided a cursor
        assert page.prev_cursor is not None

    @pytest.mark.asyncio
    async def test_asc_direction(self):
        """Test ascending sort direction."""
        from engine.core.pagination import paginate

        items = [MagicMock(id="1", created_at=datetime(2025, 1, 1, tzinfo=timezone.utc))]
        mock_result = MagicMock()
        mock_result.scalars.return_value.all.return_value = items

        mock_session = AsyncMock()
        mock_session.execute = AsyncMock(return_value=mock_result)

        mock_stmt = MagicMock()
        mock_stmt.where.return_value = mock_stmt
        mock_stmt.order_by.return_value = mock_stmt
        mock_stmt.limit.return_value = mock_stmt

        params = CursorParams(limit=10, direction="asc")
        mock_id_col = MagicMock()
        mock_id_col.key = "id"
        mock_order_col = MagicMock()
        mock_order_col.key = "created_at"

        page = await paginate(
            mock_session, mock_stmt, params,
            id_col=mock_id_col, order_col=mock_order_col,
        )

        assert len(page.items) == 1
