"""API routes for natural-language scan querying."""

from __future__ import annotations

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel, Field
from typing import Any

from engine.api.middleware.auth import get_current_user
from engine.models.user import User

router = APIRouter()


# ── Schemas ──────────────────────────────────────────────────────────────────


class NLQueryRequest(BaseModel):
    """Natural-language query request body."""
    query: str = Field(..., min_length=3, max_length=500, description="Free-form question")
    org_id: str | None = Field(None, description="Optional org scope")


class StructuredQueryResponse(BaseModel):
    target: str
    filters: dict[str, Any] = {}
    sort_by: str = ""
    sort_order: str = "desc"
    limit: int = 20
    aggregation: str = ""
    group_by: str = ""
    time_range_start: str = ""
    time_range_end: str = ""


class NLQueryResponse(BaseModel):
    """Response with parsed query, data, and human-readable summary."""
    structured_query: StructuredQueryResponse
    data: list[dict[str, Any]] = []
    total_count: int = 0
    summary: str = ""
    execution_time_ms: float = 0.0
    markdown_table: str = ""


class NLQueryFollowUpRequest(BaseModel):
    """Follow-up query that refines previous results."""
    query: str = Field(..., min_length=3, max_length=500)
    previous_query: StructuredQueryResponse | None = None
    org_id: str | None = None


class FeedbackRequest(BaseModel):
    """Feedback on a query result for improving NL parsing."""
    original_query: str
    was_correct: bool
    corrected_query: dict[str, Any] | None = None
    comment: str = ""


# ── Endpoints ────────────────────────────────────────────────────────────────


@router.post("", response_model=NLQueryResponse)
async def natural_language_query(body: NLQueryRequest, user: User = Depends(get_current_user)):
    """Execute a natural-language query against findings/scans/projects.

    Examples:
        - "show me all critical reentrancy findings from last week"
        - "how many high-severity findings per project?"
        - "latest 10 failed scans"
    """
    from engine.ml.nl_query import NLQueryEngine, ResultFormatter

    engine = NLQueryEngine()
    result = await engine.query(body.query, org_id=body.org_id)

    sq = result.structured_query
    return NLQueryResponse(
        structured_query=StructuredQueryResponse(
            target=sq.target.value,
            filters=sq.filters,
            sort_by=sq.sort_by,
            sort_order=sq.sort_order.value,
            limit=sq.limit,
            aggregation=sq.aggregation,
            group_by=sq.group_by,
            time_range_start=sq.time_range_start,
            time_range_end=sq.time_range_end,
        ),
        data=result.data,
        total_count=result.total_count,
        summary=result.summary,
        execution_time_ms=result.execution_time_ms,
        markdown_table=ResultFormatter.to_markdown_table(result),
    )


@router.post("/followup", response_model=NLQueryResponse)
async def followup_query(body: NLQueryFollowUpRequest, user: User = Depends(get_current_user)):
    """Refine previous query results with a follow-up question.

    Examples (after previous query):
        - "now show me only the critical ones"
        - "filter those by reentrancy category"
    """
    from engine.ml.nl_query import NLQueryEngine, StructuredQuery, QueryTarget, SortOrder, ResultFormatter

    engine = NLQueryEngine()

    prev = None
    if body.previous_query:
        p = body.previous_query
        prev = StructuredQuery(
            target=QueryTarget(p.target),
            filters=p.filters,
            sort_by=p.sort_by,
            sort_order=SortOrder(p.sort_order),
            limit=p.limit,
            aggregation=p.aggregation,
            group_by=p.group_by,
            time_range_start=p.time_range_start,
            time_range_end=p.time_range_end,
        )

    result = await engine.query_with_followup(body.query, previous_query=prev, org_id=body.org_id)

    sq = result.structured_query
    return NLQueryResponse(
        structured_query=StructuredQueryResponse(
            target=sq.target.value,
            filters=sq.filters,
            sort_by=sq.sort_by,
            sort_order=sq.sort_order.value,
            limit=sq.limit,
            aggregation=sq.aggregation,
            group_by=sq.group_by,
            time_range_start=sq.time_range_start,
            time_range_end=sq.time_range_end,
        ),
        data=result.data,
        total_count=result.total_count,
        summary=result.summary,
        execution_time_ms=result.execution_time_ms,
        markdown_table=ResultFormatter.to_markdown_table(result),
    )


@router.post("/feedback", status_code=204)
async def query_feedback(body: FeedbackRequest, user: User = Depends(get_current_user)):
    """Submit feedback on query accuracy to improve NL parsing."""
    import logging
    logger = logging.getLogger(__name__)
    logger.info(
        "NL query feedback: correct=%s query='%s' comment='%s'",
        body.was_correct,
        body.original_query[:80],
        body.comment[:200],
    )
    # Feedback is stored for prompt tuning in the feedback loop
    return None


@router.get("/examples")
async def query_examples(user: User = Depends(get_current_user)):
    """Return example queries to help users discover capabilities."""
    return {
        "examples": [
            {
                "query": "show me all critical findings from last week",
                "description": "Filter findings by severity and time range",
            },
            {
                "query": "how many reentrancy bugs per project?",
                "description": "Aggregate findings by category and project",
            },
            {
                "query": "latest 5 failed scans",
                "description": "Recent scan failures",
            },
            {
                "query": "top 10 high-severity open findings on Ethereum",
                "description": "Combined severity, status, and chain filter",
            },
            {
                "query": "breakdown of findings by severity this month",
                "description": "Severity distribution over time",
            },
            {
                "query": "which projects have the most critical issues?",
                "description": "Group critical findings by project",
            },
        ],
    }
