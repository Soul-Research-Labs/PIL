"""Tests for trend analytics API (engine/api/routes/analytics.py).

Covers:
- Schema validation (AnalyticsSummary, TimeSeriesPoint, ScoreTrend, etc.)
- _trunc_expr helper
- _default_range helper
- Endpoint response shapes (mocked DB)
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from pydantic import ValidationError

from engine.api.routes.analytics import (
    AnalyticsSummary,
    CategoryCount,
    MTTRMetrics,
    ScoreTrend,
    SeverityDistribution,
    TimeGranularity,
    TimeSeriesPoint,
    _default_range,
    _trunc_expr,
)


# ── Schema validation ───────────────────────────────────────────────────


class TestSchemas:
    """Test Pydantic model validation for analytics schemas."""

    def test_time_series_point(self):
        p = TimeSeriesPoint(timestamp="2025-01-01", value=42)
        assert p.timestamp == "2025-01-01"
        assert p.value == 42

    def test_time_series_point_float_value(self):
        p = TimeSeriesPoint(timestamp="2025-01-01", value=3.14)
        assert p.value == 3.14

    def test_severity_distribution(self):
        sd = SeverityDistribution(
            timestamp="2025-01-01",
            critical=2,
            high=5,
            medium=10,
            low=3,
            informational=1,
        )
        assert sd.critical == 2
        assert sd.informational == 1

    def test_severity_distribution_defaults(self):
        sd = SeverityDistribution(timestamp="2025-01-01")
        assert sd.critical == 0
        assert sd.high == 0
        assert sd.medium == 0

    def test_category_count(self):
        cc = CategoryCount(category="reentrancy", count=15, trend=0.25)
        assert cc.category == "reentrancy"
        assert cc.trend == 0.25

    def test_category_count_default_trend(self):
        cc = CategoryCount(category="test", count=1)
        assert cc.trend == 0.0

    def test_score_trend(self):
        st = ScoreTrend(timestamp="2025-01-01", score=85.5, scan_id="scan-001")
        assert st.score == 85.5
        assert st.scan_id == "scan-001"

    def test_mttr_metrics(self):
        m = MTTRMetrics(overall_hours=24.5, by_severity={"critical": 4.0, "high": 12.0}, sample_size=50)
        assert m.overall_hours == 24.5
        assert m.by_severity["critical"] == 4.0

    def test_mttr_metrics_defaults(self):
        m = MTTRMetrics(overall_hours=0, sample_size=0)
        assert m.by_severity == {}

    def test_analytics_summary(self):
        summary = AnalyticsSummary(
            total_scans=100,
            total_findings=500,
            avg_security_score=72.3,
            scans_trend=[TimeSeriesPoint(timestamp="2025-01-01", value=10)],
            score_trend=[ScoreTrend(timestamp="2025-01-01", score=75, scan_id="s1")],
            period_start="2025-01-01",
            period_end="2025-01-31",
        )
        assert summary.total_scans == 100
        assert len(summary.scans_trend) == 1
        assert len(summary.score_trend) == 1

    def test_analytics_summary_defaults(self):
        summary = AnalyticsSummary()
        assert summary.total_scans == 0
        assert summary.total_findings == 0
        assert summary.avg_security_score == 0.0
        assert summary.scans_trend == []
        assert summary.severity_trend == []
        assert summary.top_categories == []
        assert summary.score_trend == []
        assert summary.period_start == ""
        assert summary.period_end == ""

    def test_time_granularity_enum(self):
        assert TimeGranularity.DAILY == "daily"
        assert TimeGranularity.WEEKLY == "weekly"
        assert TimeGranularity.MONTHLY == "monthly"


# ── Helpers ──────────────────────────────────────────────────────────────


class TestHelpers:
    """Test analytics helper functions."""

    def test_default_range_30_days(self):
        start, end = _default_range(30)
        diff = end - start
        assert 29 <= diff.days <= 30

    def test_default_range_7_days(self):
        start, end = _default_range(7)
        diff = end - start
        assert 6 <= diff.days <= 7

    def test_default_range_365_days(self):
        start, end = _default_range(365)
        diff = end - start
        assert 364 <= diff.days <= 365

    def test_default_range_returns_utc(self):
        start, end = _default_range()
        assert start.tzinfo is not None
        assert end.tzinfo is not None

    def test_trunc_expr_daily(self):
        """_trunc_expr should use date_trunc('day', ...)."""
        mock_col = MagicMock()
        result = _trunc_expr(mock_col, TimeGranularity.DAILY)
        # The result should be a SQLAlchemy expression
        assert result is not None

    def test_trunc_expr_weekly(self):
        mock_col = MagicMock()
        result = _trunc_expr(mock_col, TimeGranularity.WEEKLY)
        assert result is not None

    def test_trunc_expr_monthly(self):
        mock_col = MagicMock()
        result = _trunc_expr(mock_col, TimeGranularity.MONTHLY)
        assert result is not None


# ── Endpoint integration tests (mocked DB) ──────────────────────────────


class TestAnalyticsEndpoints:
    """Test analytics endpoints with mocked session."""

    @pytest.mark.asyncio
    async def test_summary_endpoint(self):
        """Test that get_analytics_summary returns valid AnalyticsSummary."""
        from engine.api.routes.analytics import get_analytics_summary

        mock_session = AsyncMock()

        # Mock total_scans query
        mock_scalar_result = MagicMock()
        mock_scalar_result.scalar.return_value = 42

        # Mock volume query
        mock_volume_row = MagicMock()
        mock_volume_row.period = datetime(2025, 1, 1, tzinfo=timezone.utc)
        mock_volume_row.cnt = 5
        mock_volume_result = MagicMock()
        mock_volume_result.all.return_value = [mock_volume_row]

        # Mock score query
        mock_score_row = MagicMock()
        mock_score_row.created_at = datetime(2025, 1, 1, tzinfo=timezone.utc)
        mock_score_row.security_score = 80.0
        mock_score_row.id = "scan-1"
        mock_score_result = MagicMock()
        mock_score_result.all.return_value = [mock_score_row]

        # session.execute returns different results for different queries
        call_count = 0
        async def mock_execute(query):
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                return mock_scalar_result  # total scans
            elif call_count == 2:
                return mock_scalar_result  # avg score
            elif call_count == 3:
                return mock_volume_result  # volume trend
            elif call_count == 4:
                return mock_score_result   # score trend
            return MagicMock()

        mock_session.execute = mock_execute

        mock_user = MagicMock()

        result = await get_analytics_summary(
            days=30,
            granularity=TimeGranularity.DAILY,
            project_id=None,
            session=mock_session,
            user=mock_user,
        )

        assert isinstance(result, AnalyticsSummary)
        assert result.total_scans == 42

    @pytest.mark.asyncio
    async def test_scan_volume_endpoint(self):
        """Test get_scan_volume returns list of TimeSeriesPoints."""
        from engine.api.routes.analytics import get_scan_volume

        mock_row = MagicMock()
        mock_row.period = datetime(2025, 1, 1, tzinfo=timezone.utc)
        mock_row.cnt = 10

        mock_result = MagicMock()
        mock_result.all.return_value = [mock_row]

        mock_session = AsyncMock()
        mock_session.execute = AsyncMock(return_value=mock_result)

        mock_user = MagicMock()

        result = await get_scan_volume(
            days=30,
            granularity=TimeGranularity.DAILY,
            session=mock_session,
            user=mock_user,
        )

        assert len(result) == 1
        assert result[0].value == 10

    @pytest.mark.asyncio
    async def test_score_trend_endpoint(self):
        """Test get_score_trend returns list of ScoreTrend."""
        from engine.api.routes.analytics import get_score_trend

        mock_row = MagicMock()
        mock_row.created_at = datetime(2025, 1, 1, tzinfo=timezone.utc)
        mock_row.security_score = 85.0
        mock_row.id = "scan-abc"

        mock_result = MagicMock()
        mock_result.all.return_value = [mock_row]

        mock_session = AsyncMock()
        mock_session.execute = AsyncMock(return_value=mock_result)

        mock_user = MagicMock()

        result = await get_score_trend(
            days=90,
            project_id=None,
            session=mock_session,
            user=mock_user,
        )

        assert len(result) == 1
        assert result[0].score == 85.0
        assert result[0].scan_id == "scan-abc"

    @pytest.mark.asyncio
    async def test_cache_stats_endpoint(self):
        """Test get_cache_stats returns dict."""
        from engine.api.routes.analytics import get_cache_stats

        with patch("engine.api.routes.analytics.get_cache") as mock_gc:
            mock_cache = AsyncMock()
            mock_cache.stats = AsyncMock(return_value={"enabled": True, "hits": 100, "misses": 20})
            mock_gc.return_value = mock_cache

            mock_user = MagicMock()
            result = await get_cache_stats(user=mock_user)

            assert result["enabled"] is True
            assert result["hits"] == 100
