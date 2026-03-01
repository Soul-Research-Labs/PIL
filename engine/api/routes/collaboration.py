"""Team collaboration API — comments, assignments, SLA tracking.

Routes
------
Comments:
    GET    /findings/{finding_id}/comments        — list comments
    POST   /findings/{finding_id}/comments        — add comment
    PATCH  /comments/{comment_id}                 — edit comment
    DELETE /comments/{comment_id}                 — soft-delete comment

Assignments:
    GET    /findings/{finding_id}/assignments      — list assignments
    POST   /findings/{finding_id}/assignments      — assign finding
    PATCH  /assignments/{assignment_id}            — update status
    DELETE /assignments/{assignment_id}            — unassign

SLA:
    GET    /sla/policies                           — list org SLA policies
    POST   /sla/policies                           — create policy
    GET    /sla/status/{finding_id}                — SLA status for a finding
"""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

from engine.api.middleware.auth import get_current_user
from engine.models.user import User

router = APIRouter()


# ── Pydantic schemas ─────────────────────────────────────────────────────────

# Comments

class CommentCreate(BaseModel):
    body: str = Field(..., min_length=1, max_length=10_000)
    parent_id: str | None = None


class CommentUpdate(BaseModel):
    body: str = Field(..., min_length=1, max_length=10_000)


class CommentResponse(BaseModel):
    id: str
    finding_id: str
    author_id: str
    author_name: str | None = None
    parent_id: str | None = None
    body: str
    mentions: list[str] = []
    reactions: dict[str, list[str]] = {}
    created_at: str
    edited_at: str | None = None


# Assignments

class AssignmentCreate(BaseModel):
    assignee_id: str
    role: str = "owner"  # owner | reviewer | observer
    due_date: str | None = None
    note: str | None = None


class AssignmentUpdate(BaseModel):
    status: str | None = None  # assigned | in_progress | review | done | declined
    due_date: str | None = None
    note: str | None = None


class AssignmentResponse(BaseModel):
    id: str
    finding_id: str
    assignee_id: str
    assignee_name: str | None = None
    assigned_by_id: str
    role: str
    status: str
    due_date: str | None = None
    completed_at: str | None = None
    note: str | None = None
    created_at: str


# SLA

class SLAPolicyCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=200)
    is_default: bool = False
    triage_critical_mins: int = 60
    triage_high_mins: int = 240
    triage_medium_mins: int = 1440
    triage_low_mins: int = 10_080
    remediate_critical_mins: int = 1440
    remediate_high_mins: int = 10_080
    remediate_medium_mins: int = 43_200
    remediate_low_mins: int = 129_600
    escalation_rules: dict[str, Any] = {}


class SLAPolicyResponse(BaseModel):
    id: str
    name: str
    is_default: bool
    triage_critical_mins: int
    triage_high_mins: int
    triage_medium_mins: int
    triage_low_mins: int
    remediate_critical_mins: int
    remediate_high_mins: int
    remediate_medium_mins: int
    remediate_low_mins: int
    escalation_rules: dict[str, Any] = {}
    created_at: str


class SLAStatusResponse(BaseModel):
    finding_id: str
    severity: str
    policy_name: str
    # Triage
    triage_deadline: str | None = None
    triaged_at: str | None = None
    triage_breached: bool = False
    triage_remaining_mins: int | None = None
    # Remediation
    remediation_deadline: str | None = None
    remediated_at: str | None = None
    remediation_breached: bool = False
    remediation_remaining_mins: int | None = None


# ── In-memory stores (production: wire to DB via SQLAlchemy) ─────────────────

_comments: dict[str, dict] = {}   # comment_id → comment data
_assignments: dict[str, dict] = {}
_sla_policies: dict[str, dict] = {}
_sla_trackers: dict[str, dict] = {}  # finding_id → tracker


# ── Comment endpoints ────────────────────────────────────────────────────────


@router.get(
    "/findings/{finding_id}/comments",
    response_model=list[CommentResponse],
    summary="List comments on a finding",
)
async def list_comments(finding_id: str, user: User = Depends(get_current_user)):
    results = [
        c for c in _comments.values()
        if c["finding_id"] == finding_id and c.get("deleted_at") is None
    ]
    results.sort(key=lambda c: c["created_at"])
    return results


@router.post(
    "/findings/{finding_id}/comments",
    response_model=CommentResponse,
    status_code=201,
    summary="Add a comment to a finding",
)
async def create_comment(finding_id: str, payload: CommentCreate, user: User = Depends(get_current_user)):
    # Extract @mentions
    import re
    mentions = re.findall(r"@(\w+)", payload.body)

    comment_id = str(uuid.uuid4())
    now = datetime.now(timezone.utc).isoformat()

    comment = {
        "id": comment_id,
        "finding_id": finding_id,
        "author_id": str(user.id),
        "author_name": None,
        "parent_id": payload.parent_id,
        "body": payload.body,
        "mentions": mentions,
        "reactions": {},
        "created_at": now,
        "edited_at": None,
    }
    _comments[comment_id] = comment
    return comment


@router.patch(
    "/comments/{comment_id}",
    response_model=CommentResponse,
    summary="Edit a comment",
)
async def update_comment(comment_id: str, payload: CommentUpdate, user: User = Depends(get_current_user)):
    comment = _comments.get(comment_id)
    if not comment or comment.get("deleted_at"):
        raise HTTPException(404, "Comment not found")

    comment["body"] = payload.body
    comment["edited_at"] = datetime.now(timezone.utc).isoformat()

    import re
    comment["mentions"] = re.findall(r"@(\w+)", payload.body)

    return comment


@router.delete(
    "/comments/{comment_id}",
    status_code=204,
    summary="Soft-delete a comment",
)
async def delete_comment(comment_id: str, user: User = Depends(get_current_user)):
    comment = _comments.get(comment_id)
    if not comment:
        raise HTTPException(404, "Comment not found")
    comment["deleted_at"] = datetime.now(timezone.utc).isoformat()


# ── Assignment endpoints ─────────────────────────────────────────────────────


@router.get(
    "/findings/{finding_id}/assignments",
    response_model=list[AssignmentResponse],
    summary="List assignments for a finding",
)
async def list_assignments(finding_id: str, user: User = Depends(get_current_user)):
    results = [
        a for a in _assignments.values()
        if a["finding_id"] == finding_id
    ]
    return results


@router.post(
    "/findings/{finding_id}/assignments",
    response_model=AssignmentResponse,
    status_code=201,
    summary="Assign a finding to a team member",
)
async def create_assignment(finding_id: str, payload: AssignmentCreate, user: User = Depends(get_current_user)):
    assignment_id = str(uuid.uuid4())
    now = datetime.now(timezone.utc).isoformat()

    assignment = {
        "id": assignment_id,
        "finding_id": finding_id,
        "assignee_id": payload.assignee_id,
        "assignee_name": None,
        "assigned_by_id": str(user.id),
        "role": payload.role,
        "status": "assigned",
        "due_date": payload.due_date,
        "completed_at": None,
        "note": payload.note,
        "created_at": now,
    }
    _assignments[assignment_id] = assignment
    return assignment


@router.patch(
    "/assignments/{assignment_id}",
    response_model=AssignmentResponse,
    summary="Update assignment status",
)
async def update_assignment(assignment_id: str, payload: AssignmentUpdate, user: User = Depends(get_current_user)):
    assignment = _assignments.get(assignment_id)
    if not assignment:
        raise HTTPException(404, "Assignment not found")

    if payload.status:
        assignment["status"] = payload.status
        if payload.status == "done":
            assignment["completed_at"] = datetime.now(timezone.utc).isoformat()
    if payload.due_date is not None:
        assignment["due_date"] = payload.due_date
    if payload.note is not None:
        assignment["note"] = payload.note

    return assignment


@router.delete(
    "/assignments/{assignment_id}",
    status_code=204,
    summary="Remove an assignment",
)
async def delete_assignment(assignment_id: str, user: User = Depends(get_current_user)):
    if assignment_id not in _assignments:
        raise HTTPException(404, "Assignment not found")
    del _assignments[assignment_id]


# ── SLA Policy endpoints ────────────────────────────────────────────────────


@router.get(
    "/sla/policies",
    response_model=list[SLAPolicyResponse],
    summary="List SLA policies",
)
async def list_sla_policies(user: User = Depends(get_current_user)):
    return list(_sla_policies.values())


@router.post(
    "/sla/policies",
    response_model=SLAPolicyResponse,
    status_code=201,
    summary="Create an SLA policy",
)
async def create_sla_policy(payload: SLAPolicyCreate, user: User = Depends(get_current_user)):
    policy_id = str(uuid.uuid4())
    now = datetime.now(timezone.utc).isoformat()

    policy = {
        "id": policy_id,
        **payload.model_dump(),
        "created_at": now,
    }
    _sla_policies[policy_id] = policy
    return policy


@router.get(
    "/sla/status/{finding_id}",
    response_model=SLAStatusResponse,
    summary="Get SLA compliance status for a finding",
)
async def get_sla_status(finding_id: str):
    tracker = _sla_trackers.get(finding_id)
    if not tracker:
        # Auto-create a tracker using the default policy
        default_policy = next(
            (p for p in _sla_policies.values() if p.get("is_default")),
            None,
        )
        if not default_policy:
            raise HTTPException(404, "No SLA policy configured")

        now = datetime.now(timezone.utc)
        severity = "MEDIUM"  # would look up finding severity in production

        triage_mins = default_policy.get(f"triage_{severity.lower()}_mins", 1440)
        remediate_mins = default_policy.get(f"remediate_{severity.lower()}_mins", 43_200)

        tracker = {
            "finding_id": finding_id,
            "severity": severity,
            "policy_name": default_policy["name"],
            "triage_deadline": (now + timedelta(minutes=triage_mins)).isoformat(),
            "triaged_at": None,
            "triage_breached": False,
            "remediation_deadline": (now + timedelta(minutes=remediate_mins)).isoformat(),
            "remediated_at": None,
            "remediation_breached": False,
        }
        _sla_trackers[finding_id] = tracker

    # Compute remaining time
    now = datetime.now(timezone.utc)
    triage_remaining = None
    if tracker["triage_deadline"] and not tracker["triaged_at"]:
        deadline = datetime.fromisoformat(tracker["triage_deadline"])
        remaining = (deadline - now).total_seconds() / 60
        triage_remaining = max(0, int(remaining))
        if remaining <= 0:
            tracker["triage_breached"] = True

    remediation_remaining = None
    if tracker["remediation_deadline"] and not tracker["remediated_at"]:
        deadline = datetime.fromisoformat(tracker["remediation_deadline"])
        remaining = (deadline - now).total_seconds() / 60
        remediation_remaining = max(0, int(remaining))
        if remaining <= 0:
            tracker["remediation_breached"] = True

    return {
        **tracker,
        "triage_remaining_mins": triage_remaining,
        "remediation_remaining_mins": remediation_remaining,
    }
