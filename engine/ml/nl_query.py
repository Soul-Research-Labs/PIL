"""Natural-language scan querying — translates free-form English into
structured database queries against findings, scans, and projects.

Architecture:
    1. QueryParser      — LLM-based NL → structured query translation
    2. QueryExecutor    — runs structured query against SQLAlchemy models
    3. ResultFormatter  — formats results for API / chat display
    4. NLQueryEngine    — end-to-end orchestrator
"""

from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Any

logger = logging.getLogger(__name__)


# ── Types ────────────────────────────────────────────────────────────────────


class QueryTarget(str, Enum):
    """Queryable entity types."""
    FINDINGS = "findings"
    SCANS = "scans"
    PROJECTS = "projects"
    METRICS = "metrics"


class SortOrder(str, Enum):
    ASC = "asc"
    DESC = "desc"


@dataclass
class StructuredQuery:
    """Intermediate representation of a parsed NL query."""
    target: QueryTarget = QueryTarget.FINDINGS
    filters: dict[str, Any] = field(default_factory=dict)
    sort_by: str = ""
    sort_order: SortOrder = SortOrder.DESC
    limit: int = 20
    offset: int = 0
    aggregation: str = ""        # count, avg, sum, group_by
    group_by: str = ""
    time_range_start: str = ""   # ISO date
    time_range_end: str = ""
    free_text: str = ""          # fallback text search
    original_query: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "target": self.target.value,
            "filters": self.filters,
            "sort_by": self.sort_by,
            "sort_order": self.sort_order.value,
            "limit": self.limit,
            "offset": self.offset,
            "aggregation": self.aggregation,
            "group_by": self.group_by,
            "time_range_start": self.time_range_start,
            "time_range_end": self.time_range_end,
            "free_text": self.free_text,
        }


@dataclass
class QueryResult:
    """Result of executing a natural-language query."""
    structured_query: StructuredQuery
    data: list[dict[str, Any]] = field(default_factory=list)
    total_count: int = 0
    summary: str = ""
    execution_time_ms: float = 0.0


# ── Query parser ─────────────────────────────────────────────────────────────


# LLM system prompt for NL → structured query translation
NL_QUERY_SYSTEM_PROMPT = """You are a query translator for a smart-contract security scanner database.
Convert natural-language questions into structured JSON queries.

Available targets: findings, scans, projects, metrics

Available filter fields by target:
- findings: severity (critical|high|medium|low|informational), category, status (open|confirmed|dismissed|fixed), detector_id, title (partial match), project_id, scan_id, chain
- scans: status (queued|running|completed|failed), project_id, created_after, created_before
- projects: name (partial match), chain
- metrics: (use aggregation: count, avg, group_by)

Respond ONLY with valid JSON matching this schema:
{
  "target": "findings|scans|projects|metrics",
  "filters": {"field": "value", ...},
  "sort_by": "field_name",
  "sort_order": "asc|desc",
  "limit": 20,
  "aggregation": "count|avg|group_by|none",
  "group_by": "field_name",
  "time_range_start": "ISO date or empty",
  "time_range_end": "ISO date or empty"
}
"""


class QueryParser:
    """Parses natural-language queries into StructuredQuery.

    Uses LLM when available, falls back to regex patterns.
    """

    def __init__(self, llm_client: Any | None = None) -> None:
        self._llm = llm_client

    async def parse(self, nl_query: str) -> StructuredQuery:
        """Parse a natural-language query string."""
        # Try LLM-based parsing first
        if self._llm is not None:
            try:
                return await self._llm_parse(nl_query)
            except Exception as e:
                logger.warning("LLM query parsing failed, using heuristic: %s", e)

        return self._heuristic_parse(nl_query)

    async def _llm_parse(self, nl_query: str) -> StructuredQuery:
        """Use LLM to translate NL → structured query."""
        response = await self._llm.chat(
            system=NL_QUERY_SYSTEM_PROMPT,
            user=nl_query,
            temperature=0.0,
            max_tokens=500,
        )

        # Extract JSON from response
        text = response if isinstance(response, str) else str(response)
        json_match = re.search(r'\{[^{}]*\}', text, re.DOTALL)
        if not json_match:
            raise ValueError("No JSON found in LLM response")

        data = json.loads(json_match.group())
        return self._dict_to_query(data, nl_query)

    def _heuristic_parse(self, nl_query: str) -> StructuredQuery:
        """Regex/keyword-based fallback parser."""
        q = nl_query.lower().strip()
        sq = StructuredQuery(original_query=nl_query)

        # Detect target
        if any(w in q for w in ["scan", "analysis", "run"]):
            sq.target = QueryTarget.SCANS
        elif any(w in q for w in ["project", "repo", "contract"]):
            sq.target = QueryTarget.PROJECTS
        elif any(w in q for w in ["metric", "statistic", "count", "how many", "total"]):
            sq.target = QueryTarget.METRICS
        else:
            sq.target = QueryTarget.FINDINGS

        # Severity filter
        for sev in ["critical", "high", "medium", "low", "informational"]:
            if sev in q:
                sq.filters["severity"] = sev
                break

        # Status filter
        for status in ["open", "confirmed", "dismissed", "fixed", "running", "completed", "failed"]:
            if status in q:
                sq.filters["status"] = status
                break

        # Category filter
        categories = [
            "reentrancy", "access_control", "arithmetic", "flash_loan",
            "oracle_manipulation", "governance", "delegatecall",
            "storage", "mev", "upgradeable",
        ]
        for cat in categories:
            if cat.replace("_", " ") in q or cat in q:
                sq.filters["category"] = cat
                break

        # Chain filter
        for chain in ["ethereum", "polygon", "arbitrum", "optimism", "bsc", "solana", "aptos", "sui"]:
            if chain in q:
                sq.filters["chain"] = chain
                break

        # Time range
        sq.time_range_start, sq.time_range_end = self._parse_time_range(q)

        # Aggregation
        if "how many" in q or "count" in q or "total" in q:
            sq.aggregation = "count"
        if "group by" in q or "per" in q or "breakdown" in q:
            sq.aggregation = "group_by"
            # Guess group_by field
            if "severity" in q:
                sq.group_by = "severity"
            elif "category" in q:
                sq.group_by = "category"
            elif "project" in q:
                sq.group_by = "project_id"
            elif "detector" in q:
                sq.group_by = "detector_id"

        # Sort
        if "latest" in q or "recent" in q or "newest" in q:
            sq.sort_by = "created_at"
            sq.sort_order = SortOrder.DESC
        elif "oldest" in q or "earliest" in q:
            sq.sort_by = "created_at"
            sq.sort_order = SortOrder.ASC
        elif "worst" in q or "most severe" in q or "highest" in q:
            sq.sort_by = "severity"
            sq.sort_order = SortOrder.DESC

        # Limit
        limit_match = re.search(r'(?:top|first|last|show)\s+(\d+)', q)
        if limit_match:
            sq.limit = min(100, int(limit_match.group(1)))

        sq.free_text = nl_query
        return sq

    @staticmethod
    def _parse_time_range(query: str) -> tuple[str, str]:
        """Extract time range from query text."""
        now = datetime.now(timezone.utc)
        start, end = "", ""

        if "today" in query:
            start = now.replace(hour=0, minute=0, second=0).isoformat()
        elif "yesterday" in query:
            yesterday = now - timedelta(days=1)
            start = yesterday.replace(hour=0, minute=0, second=0).isoformat()
            end = now.replace(hour=0, minute=0, second=0).isoformat()
        elif "this week" in query or "past week" in query or "last week" in query:
            start = (now - timedelta(days=7)).isoformat()
        elif "this month" in query or "past month" in query or "last month" in query:
            start = (now - timedelta(days=30)).isoformat()
        elif "last 24 hours" in query or "past 24 hours" in query:
            start = (now - timedelta(hours=24)).isoformat()

        # Explicit "last N days"
        m = re.search(r'last\s+(\d+)\s+days?', query)
        if m:
            start = (now - timedelta(days=int(m.group(1)))).isoformat()

        return start, end

    @staticmethod
    def _dict_to_query(data: dict[str, Any], original: str) -> StructuredQuery:
        """Convert a JSON dict to a StructuredQuery."""
        target_str = data.get("target", "findings")
        try:
            target = QueryTarget(target_str)
        except ValueError:
            target = QueryTarget.FINDINGS

        return StructuredQuery(
            target=target,
            filters=data.get("filters", {}),
            sort_by=data.get("sort_by", ""),
            sort_order=SortOrder(data.get("sort_order", "desc")),
            limit=min(100, data.get("limit", 20)),
            offset=data.get("offset", 0),
            aggregation=data.get("aggregation", ""),
            group_by=data.get("group_by", ""),
            time_range_start=data.get("time_range_start", ""),
            time_range_end=data.get("time_range_end", ""),
            free_text=original,
            original_query=original,
        )


# ── Query executor ───────────────────────────────────────────────────────────


class QueryExecutor:
    """Executes StructuredQuery against the database.

    Operates with raw SQLAlchemy async sessions. In production,
    org-scoping is applied via TenantQueryHelper.
    """

    def __init__(self, session_factory: Any = None) -> None:
        self._session_factory = session_factory

    async def execute(self, sq: StructuredQuery, org_id: str | None = None) -> QueryResult:
        """Execute a structured query. Returns QueryResult."""
        import time
        start = time.monotonic()

        if self._session_factory is None:
            # Return empty result when no DB connection
            return QueryResult(
                structured_query=sq,
                data=[],
                total_count=0,
                summary="No database connection available.",
                execution_time_ms=0.0,
            )

        try:
            async with self._session_factory() as session:
                data, total = await self._run_query(session, sq, org_id)

            elapsed = (time.monotonic() - start) * 1000
            result = QueryResult(
                structured_query=sq,
                data=data,
                total_count=total,
                execution_time_ms=round(elapsed, 2),
            )
            result.summary = ResultFormatter.summarise(result)
            return result

        except Exception as e:
            logger.error("Query execution failed: %s", e)
            return QueryResult(
                structured_query=sq,
                summary=f"Query failed: {e}",
                execution_time_ms=(time.monotonic() - start) * 1000,
            )

    async def _run_query(
        self,
        session: Any,
        sq: StructuredQuery,
        org_id: str | None,
    ) -> tuple[list[dict[str, Any]], int]:
        """Build and execute the SQLAlchemy query."""
        from sqlalchemy import select, func, text, and_

        # Import models lazily to avoid circular imports
        from engine.models.scan import Finding, Scan, Project

        model_map = {
            QueryTarget.FINDINGS: Finding,
            QueryTarget.SCANS: Scan,
            QueryTarget.PROJECTS: Project,
            QueryTarget.METRICS: Finding,  # metrics run aggregates on findings
        }

        model = model_map[sq.target]
        stmt = select(model)

        # Org scoping
        if org_id and hasattr(model, "org_id"):
            stmt = stmt.where(model.org_id == org_id)

        # Apply filters
        for field_name, value in sq.filters.items():
            col = getattr(model, field_name, None)
            if col is not None:
                if isinstance(value, str) and "%" in value:
                    stmt = stmt.where(col.ilike(value))
                else:
                    stmt = stmt.where(col == value)

        # Time range
        if sq.time_range_start and hasattr(model, "created_at"):
            stmt = stmt.where(model.created_at >= sq.time_range_start)
        if sq.time_range_end and hasattr(model, "created_at"):
            stmt = stmt.where(model.created_at <= sq.time_range_end)

        # Aggregation
        if sq.aggregation == "count":
            count_stmt = select(func.count()).select_from(stmt.subquery())
            result = await session.execute(count_stmt)
            total = result.scalar() or 0
            return [{"count": total}], 1

        if sq.aggregation == "group_by" and sq.group_by:
            col = getattr(model, sq.group_by, None)
            if col is not None:
                group_stmt = (
                    select(col, func.count().label("count"))
                    .select_from(model)
                    .group_by(col)
                    .order_by(func.count().desc())
                )
                result = await session.execute(group_stmt)
                rows = [{"group": str(r[0]), "count": r[1]} for r in result.all()]
                return rows, len(rows)

        # Sort
        if sq.sort_by:
            col = getattr(model, sq.sort_by, None)
            if col is not None:
                if sq.sort_order == SortOrder.ASC:
                    stmt = stmt.order_by(col.asc())
                else:
                    stmt = stmt.order_by(col.desc())

        # Count total
        count_stmt = select(func.count()).select_from(stmt.subquery())
        count_result = await session.execute(count_stmt)
        total = count_result.scalar() or 0

        # Pagination
        stmt = stmt.limit(sq.limit).offset(sq.offset)

        result = await session.execute(stmt)
        rows = result.scalars().all()

        # Serialise to dicts
        data = []
        for row in rows:
            if hasattr(row, "__table__"):
                d = {c.name: getattr(row, c.name) for c in row.__table__.columns}
                # Convert non-JSON-serializable types
                for k, v in d.items():
                    if isinstance(v, datetime):
                        d[k] = v.isoformat()
                    elif hasattr(v, "value"):
                        d[k] = v.value
                data.append(d)

        return data, total


# ── Result formatting ────────────────────────────────────────────────────────


class ResultFormatter:
    """Formats query results into human-readable summaries."""

    @staticmethod
    def summarise(result: QueryResult) -> str:
        """Generate a one-line summary of the query result."""
        sq = result.structured_query
        target = sq.target.value

        if sq.aggregation == "count":
            count_val = result.data[0].get("count", 0) if result.data else 0
            return f"Found {count_val} {target} matching your query."

        if sq.aggregation == "group_by":
            groups = len(result.data)
            return f"Grouped {target} into {groups} categories by {sq.group_by}."

        filters_desc = ""
        if sq.filters:
            parts = [f"{k}={v}" for k, v in sq.filters.items()]
            filters_desc = f" (filters: {', '.join(parts)})"

        return (
            f"Showing {len(result.data)} of {result.total_count} {target}"
            f"{filters_desc} in {result.execution_time_ms:.0f}ms."
        )

    @staticmethod
    def to_markdown_table(result: QueryResult, max_rows: int = 20) -> str:
        """Render results as a Markdown table."""
        if not result.data:
            return "_No results found._"

        rows = result.data[:max_rows]
        headers = list(rows[0].keys())

        # Header row
        lines = [
            "| " + " | ".join(headers) + " |",
            "| " + " | ".join("---" for _ in headers) + " |",
        ]

        for row in rows:
            cells = [str(row.get(h, ""))[:50] for h in headers]
            lines.append("| " + " | ".join(cells) + " |")

        if len(result.data) > max_rows:
            lines.append(f"\n_…and {len(result.data) - max_rows} more rows._")

        return "\n".join(lines)


# ── Engine ───────────────────────────────────────────────────────────────────


class NLQueryEngine:
    """End-to-end natural-language querying engine.

    Usage:
        engine = NLQueryEngine(llm_client=llm, session_factory=db)
        result = await engine.query("show me all critical reentrancy findings from last week")
    """

    def __init__(
        self,
        llm_client: Any | None = None,
        session_factory: Any = None,
    ) -> None:
        self._parser = QueryParser(llm_client=llm_client)
        self._executor = QueryExecutor(session_factory=session_factory)

    async def query(
        self,
        nl_query: str,
        org_id: str | None = None,
    ) -> QueryResult:
        """Parse and execute a natural-language query."""
        logger.info("NL query: %s", nl_query)

        sq = await self._parser.parse(nl_query)
        logger.info("Parsed query: %s", sq.to_dict())

        result = await self._executor.execute(sq, org_id=org_id)
        logger.info("Query returned %d results (%s)", result.total_count, result.summary)

        return result

    async def query_with_followup(
        self,
        nl_query: str,
        previous_query: StructuredQuery | None = None,
        org_id: str | None = None,
    ) -> QueryResult:
        """Handle follow-up queries that refine previous results.

        Supports patterns like:
            "now show me only the critical ones"
            "filter those by reentrancy"
        """
        if previous_query and self._is_followup(nl_query):
            # Merge with previous query
            sq = await self._parser.parse(nl_query)
            merged = self._merge_queries(previous_query, sq)
            return await self._executor.execute(merged, org_id=org_id)

        return await self.query(nl_query, org_id=org_id)

    @staticmethod
    def _is_followup(query: str) -> bool:
        """Detect if a query is a refinement of the previous one."""
        q = query.lower()
        return any(w in q for w in [
            "those", "them", "these", "that", "filter", "narrow",
            "only the", "among", "from those", "of those",
        ])

    @staticmethod
    def _merge_queries(prev: StructuredQuery, new: StructuredQuery) -> StructuredQuery:
        """Merge a follow-up query into the previous query context."""
        merged = StructuredQuery(
            target=new.target if new.target != QueryTarget.FINDINGS else prev.target,
            filters={**prev.filters, **new.filters},
            sort_by=new.sort_by or prev.sort_by,
            sort_order=new.sort_order,
            limit=new.limit,
            offset=0,
            aggregation=new.aggregation or prev.aggregation,
            group_by=new.group_by or prev.group_by,
            time_range_start=new.time_range_start or prev.time_range_start,
            time_range_end=new.time_range_end or prev.time_range_end,
            original_query=new.original_query,
        )
        return merged
