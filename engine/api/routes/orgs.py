"""Organization management routes.

Routes:
    POST   /api/v1/orgs              — Create organization
    GET    /api/v1/orgs              — List user's organizations
    GET    /api/v1/orgs/{slug}       — Get organization by slug
    PATCH  /api/v1/orgs/{slug}       — Update organization
    DELETE /api/v1/orgs/{slug}       — Delete organization
    POST   /api/v1/orgs/{slug}/members — Invite member
    GET    /api/v1/orgs/{slug}/members — List members
    PATCH  /api/v1/orgs/{slug}/members/{user_id} — Update member role
    DELETE /api/v1/orgs/{slug}/members/{user_id} — Remove member
    GET    /api/v1/orgs/{slug}/usage  — Org usage stats (SaaS billing)
"""

from __future__ import annotations

import re
import uuid

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from engine.api.middleware.auth import get_current_user
from engine.core.database import get_db
from engine.models.scan import Finding, Project, Scan
from engine.models.user import OrgMembership, Organization, User

router = APIRouter()


# ── Schemas ──────────────────────────────────────────────────────────────────


class OrgCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=200)
    slug: str = Field(..., min_length=1, max_length=200, pattern=r"^[a-z0-9][a-z0-9-]*$")
    logo_url: str | None = None


class OrgUpdate(BaseModel):
    name: str | None = None
    logo_url: str | None = None


class OrgResponse(BaseModel):
    id: str
    name: str
    slug: str
    logo_url: str | None = None
    member_count: int = 0
    project_count: int = 0
    created_at: str | None = None


class MemberInvite(BaseModel):
    email: str
    role: str = Field(default="viewer", pattern=r"^(admin|editor|viewer)$")


class MemberResponse(BaseModel):
    user_id: str
    username: str
    email: str | None = None
    role: str
    joined_at: str | None = None


class MemberRoleUpdate(BaseModel):
    role: str = Field(..., pattern=r"^(admin|editor|viewer)$")


class OrgUsageResponse(BaseModel):
    org_id: str
    slug: str
    plan: str = "free"
    projects: int = 0
    scans_this_month: int = 0
    findings_total: int = 0
    storage_bytes: int = 0
    members: int = 0
    limits: dict = {}


# ── Routes ───────────────────────────────────────────────────────────────────


@router.post("", status_code=201, response_model=OrgResponse)
async def create_org(
    body: OrgCreate,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Create a new organization and make the current user its admin."""
    # Check slug uniqueness
    existing = await db.execute(
        select(Organization).where(Organization.slug == body.slug)
    )
    if existing.scalar_one_or_none():
        raise HTTPException(status_code=409, detail=f"Slug '{body.slug}' is already taken")

    org = Organization(name=body.name, slug=body.slug, logo_url=body.logo_url)
    db.add(org)
    await db.flush()

    # Creator becomes admin
    membership = OrgMembership(user_id=user.id, org_id=org.id, role="admin")
    db.add(membership)
    await db.commit()

    return OrgResponse(
        id=str(org.id),
        name=org.name,
        slug=org.slug,
        logo_url=org.logo_url,
        member_count=1,
        project_count=0,
        created_at=org.created_at.isoformat() if org.created_at else None,
    )


@router.get("", response_model=list[OrgResponse])
async def list_orgs(
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """List organizations the current user belongs to."""
    result = await db.execute(
        select(Organization)
        .join(OrgMembership, OrgMembership.org_id == Organization.id)
        .where(OrgMembership.user_id == user.id)
    )
    orgs = result.scalars().all()

    responses = []
    for org in orgs:
        mem_count = await db.scalar(
            select(func.count()).select_from(OrgMembership).where(OrgMembership.org_id == org.id)
        )
        proj_count = await db.scalar(
            select(func.count()).select_from(Project).where(Project.org_id == org.id)
        )
        responses.append(OrgResponse(
            id=str(org.id),
            name=org.name,
            slug=org.slug,
            logo_url=org.logo_url,
            member_count=mem_count or 0,
            project_count=proj_count or 0,
            created_at=org.created_at.isoformat() if org.created_at else None,
        ))

    return responses


@router.get("/{slug}", response_model=OrgResponse)
async def get_org(
    slug: str,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Get organization details by slug (must be a member)."""
    org = await _get_org_for_user(slug, user.id, db)
    mem_count = await db.scalar(
        select(func.count()).select_from(OrgMembership).where(OrgMembership.org_id == org.id)
    )
    proj_count = await db.scalar(
        select(func.count()).select_from(Project).where(Project.org_id == org.id)
    )
    return OrgResponse(
        id=str(org.id),
        name=org.name,
        slug=org.slug,
        logo_url=org.logo_url,
        member_count=mem_count or 0,
        project_count=proj_count or 0,
        created_at=org.created_at.isoformat() if org.created_at else None,
    )


@router.patch("/{slug}", response_model=OrgResponse)
async def update_org(
    slug: str,
    body: OrgUpdate,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Update organization details (admin only)."""
    org = await _get_org_for_user(slug, user.id, db, require_role="admin")
    if body.name is not None:
        org.name = body.name
    if body.logo_url is not None:
        org.logo_url = body.logo_url
    await db.commit()
    return OrgResponse(
        id=str(org.id), name=org.name, slug=org.slug, logo_url=org.logo_url,
        created_at=org.created_at.isoformat() if org.created_at else None,
    )


@router.delete("/{slug}", status_code=204)
async def delete_org(
    slug: str,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Delete organization (admin only). Cascades to all projects/scans."""
    org = await _get_org_for_user(slug, user.id, db, require_role="admin")
    await db.delete(org)
    await db.commit()


# ── Member management ────────────────────────────────────────────────────────


@router.post("/{slug}/members", status_code=201, response_model=MemberResponse)
async def invite_member(
    slug: str,
    body: MemberInvite,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Invite a user to the organization by email (admin only)."""
    org = await _get_org_for_user(slug, user.id, db, require_role="admin")

    # Find user by email
    target_result = await db.execute(
        select(User).where(User.email == body.email)
    )
    target = target_result.scalar_one_or_none()
    if not target:
        raise HTTPException(status_code=404, detail="User with that email not found")

    # Check not already a member
    existing = await db.execute(
        select(OrgMembership).where(
            OrgMembership.org_id == org.id,
            OrgMembership.user_id == target.id,
        )
    )
    if existing.scalar_one_or_none():
        raise HTTPException(status_code=409, detail="User is already a member")

    membership = OrgMembership(user_id=target.id, org_id=org.id, role=body.role)
    db.add(membership)
    await db.commit()

    return MemberResponse(
        user_id=str(target.id),
        username=target.username,
        email=target.email,
        role=body.role,
        joined_at=membership.created_at.isoformat() if membership.created_at else None,
    )


@router.get("/{slug}/members", response_model=list[MemberResponse])
async def list_members(
    slug: str,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """List all members of an organization."""
    org = await _get_org_for_user(slug, user.id, db)

    result = await db.execute(
        select(OrgMembership, User)
        .join(User, User.id == OrgMembership.user_id)
        .where(OrgMembership.org_id == org.id)
    )
    rows = result.all()

    return [
        MemberResponse(
            user_id=str(mem.user_id),
            username=u.username,
            email=u.email,
            role=mem.role,
            joined_at=mem.created_at.isoformat() if mem.created_at else None,
        )
        for mem, u in rows
    ]


@router.patch("/{slug}/members/{user_id}", response_model=MemberResponse)
async def update_member_role(
    slug: str,
    user_id: uuid.UUID,
    body: MemberRoleUpdate,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Update a member's role (admin only)."""
    org = await _get_org_for_user(slug, user.id, db, require_role="admin")

    result = await db.execute(
        select(OrgMembership).where(
            OrgMembership.org_id == org.id,
            OrgMembership.user_id == user_id,
        )
    )
    membership = result.scalar_one_or_none()
    if not membership:
        raise HTTPException(status_code=404, detail="Member not found")

    membership.role = body.role
    await db.commit()

    target = await db.get(User, user_id)
    return MemberResponse(
        user_id=str(user_id),
        username=target.username if target else "",
        email=target.email if target else None,
        role=membership.role,
        joined_at=membership.created_at.isoformat() if membership.created_at else None,
    )


@router.delete("/{slug}/members/{user_id}", status_code=204)
async def remove_member(
    slug: str,
    user_id: uuid.UUID,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Remove a member from the organization (admin only, cannot remove self)."""
    org = await _get_org_for_user(slug, user.id, db, require_role="admin")

    if user_id == user.id:
        raise HTTPException(status_code=400, detail="Cannot remove yourself. Transfer ownership first.")

    result = await db.execute(
        select(OrgMembership).where(
            OrgMembership.org_id == org.id,
            OrgMembership.user_id == user_id,
        )
    )
    membership = result.scalar_one_or_none()
    if not membership:
        raise HTTPException(status_code=404, detail="Member not found")

    await db.delete(membership)
    await db.commit()


# ── Usage / billing ──────────────────────────────────────────────────────────


@router.get("/{slug}/usage", response_model=OrgUsageResponse)
async def get_org_usage(
    slug: str,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Get organization usage statistics for SaaS billing."""
    org = await _get_org_for_user(slug, user.id, db)

    proj_count = await db.scalar(
        select(func.count()).select_from(Project).where(Project.org_id == org.id)
    ) or 0

    scan_count = await db.scalar(
        select(func.count())
        .select_from(Scan)
        .join(Project, Project.id == Scan.project_id)
        .where(Project.org_id == org.id)
    ) or 0

    finding_count = await db.scalar(
        select(func.count())
        .select_from(Finding)
        .join(Scan, Scan.id == Finding.scan_id)
        .join(Project, Project.id == Scan.project_id)
        .where(Project.org_id == org.id)
    ) or 0

    mem_count = await db.scalar(
        select(func.count()).select_from(OrgMembership).where(OrgMembership.org_id == org.id)
    ) or 0

    # SaaS tier limits
    plan_limits = {
        "free": {"projects": 3, "scans_per_month": 50, "members": 5},
        "pro": {"projects": 25, "scans_per_month": 500, "members": 25},
        "enterprise": {"projects": -1, "scans_per_month": -1, "members": -1},
    }

    return OrgUsageResponse(
        org_id=str(org.id),
        slug=org.slug,
        plan="free",  # TODO: read from subscription model
        projects=proj_count,
        scans_this_month=scan_count,
        findings_total=finding_count,
        members=mem_count,
        limits=plan_limits.get("free", {}),
    )


# ── Helpers ──────────────────────────────────────────────────────────────────


async def _get_org_for_user(
    slug: str,
    user_id: uuid.UUID,
    db: AsyncSession,
    require_role: str | None = None,
) -> Organization:
    """Fetch org by slug and verify user membership."""
    result = await db.execute(
        select(Organization).where(Organization.slug == slug)
    )
    org = result.scalar_one_or_none()
    if not org:
        raise HTTPException(status_code=404, detail="Organization not found")

    mem_result = await db.execute(
        select(OrgMembership).where(
            OrgMembership.org_id == org.id,
            OrgMembership.user_id == user_id,
        )
    )
    membership = mem_result.scalar_one_or_none()
    if not membership:
        raise HTTPException(status_code=403, detail="Not a member of this organization")

    if require_role and membership.role != require_role:
        raise HTTPException(status_code=403, detail=f"Requires '{require_role}' role")

    return org
