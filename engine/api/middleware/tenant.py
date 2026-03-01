"""Multi-tenant isolation middleware.

Provides:
- Tenant context extraction from JWT claims or X-Org-Slug header
- Dependency injection for current organization
- Tenant-scoped query helpers for org-level data isolation
"""

from __future__ import annotations

import logging
import uuid
from contextvars import ContextVar
from typing import Annotated

from fastapi import Depends, Header, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from engine.api.middleware.auth import get_current_user
from engine.core.database import get_db
from engine.models.user import OrgMembership, Organization, User

logger = logging.getLogger(__name__)

# ── Context variable for the current tenant ──────────────────────────────────

_current_org_id: ContextVar[uuid.UUID | None] = ContextVar("current_org_id", default=None)
_current_org_role: ContextVar[str | None] = ContextVar("current_org_role", default=None)


def get_current_org_id() -> uuid.UUID | None:
    """Read the current tenant org ID from context."""
    return _current_org_id.get()


def get_current_org_role() -> str | None:
    """Read the current user's role in the active org."""
    return _current_org_role.get()


# ── Tenant resolution dependencies ──────────────────────────────────────────


async def resolve_org(
    request: Request,
    user: User = Depends(get_current_user),
    x_org_slug: str | None = Header(None),
    db: AsyncSession = Depends(get_db),
) -> Organization:
    """Resolve the active organization for the current request.

    Resolution order:
    1. ``X-Org-Slug`` header (explicit org switch)
    2. ``org_id`` claim in JWT payload
    3. User's single org (if they belong to exactly one)

    Returns the Organization object and sets context vars for downstream use.

    Raises:
        HTTPException 400 — user belongs to multiple orgs but none specified
        HTTPException 403 — user is not a member of the requested org
        HTTPException 404 — requested org does not exist
    """
    org: Organization | None = None

    # ── Strategy 1: X-Org-Slug header ────────────────────────────────────
    if x_org_slug:
        result = await db.execute(
            select(Organization).where(Organization.slug == x_org_slug)
        )
        org = result.scalar_one_or_none()
        if not org:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Organization '{x_org_slug}' not found",
            )

    # ── Strategy 2: Single org fallback ──────────────────────────────────
    if not org:
        memberships_result = await db.execute(
            select(OrgMembership).where(OrgMembership.user_id == user.id)
        )
        memberships = memberships_result.scalars().all()

        if len(memberships) == 0:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="User does not belong to any organization. Create one first.",
            )
        if len(memberships) == 1:
            org = await db.get(Organization, memberships[0].org_id)
        else:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="User belongs to multiple organizations. Specify X-Org-Slug header.",
            )

    # ── Verify membership ────────────────────────────────────────────────
    mem_result = await db.execute(
        select(OrgMembership).where(
            OrgMembership.user_id == user.id,
            OrgMembership.org_id == org.id,  # type: ignore[union-attr]
        )
    )
    membership = mem_result.scalar_one_or_none()

    if not membership:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="You are not a member of this organization",
        )

    # Set context vars for downstream helpers
    _current_org_id.set(org.id)  # type: ignore[union-attr]
    _current_org_role.set(membership.role)

    logger.debug(
        "Tenant resolved: org=%s role=%s user=%s",
        org.slug,  # type: ignore[union-attr]
        membership.role,
        user.username,
    )
    return org  # type: ignore[return-value]


async def require_org_admin(
    org: Organization = Depends(resolve_org),
) -> Organization:
    """Dependency that requires the user to be an org admin."""
    role = get_current_org_role()
    if role != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin role required for this operation",
        )
    return org


async def require_org_editor(
    org: Organization = Depends(resolve_org),
) -> Organization:
    """Dependency that requires at least editor role."""
    role = get_current_org_role()
    if role not in ("admin", "editor"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Editor or admin role required for this operation",
        )
    return org


# ── Tenant-scoped query helpers ──────────────────────────────────────────────


def scope_to_org(query, org_id: uuid.UUID):
    """Add a WHERE clause to restrict a query to the current organization.

    Usage:
        stmt = scope_to_org(select(Project), org.id)
    """
    return query.where(query.column_descriptions[0]["entity"].org_id == org_id)


class TenantQueryHelper:
    """Helper class for tenant-scoped database operations.

    Wraps common CRUD patterns with automatic org_id filtering.
    """

    def __init__(self, db: AsyncSession, org_id: uuid.UUID) -> None:
        self._db = db
        self._org_id = org_id

    async def list_projects(self):
        """List all projects belonging to the current org."""
        from engine.models.scan import Project

        result = await self._db.execute(
            select(Project).where(Project.org_id == self._org_id)
        )
        return result.scalars().all()

    async def get_project(self, project_id: uuid.UUID):
        """Get a project only if it belongs to the current org."""
        from engine.models.scan import Project

        result = await self._db.execute(
            select(Project).where(
                Project.id == project_id,
                Project.org_id == self._org_id,
            )
        )
        project = result.scalar_one_or_none()
        if not project:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Project not found in this organization",
            )
        return project

    async def list_scans(self, project_id: uuid.UUID):
        """List scans for a project in this org (verifies project ownership)."""
        from engine.models.scan import Project, Scan

        project = await self.get_project(project_id)
        result = await self._db.execute(
            select(Scan)
            .where(Scan.project_id == project.id)
            .order_by(Scan.created_at.desc())
        )
        return result.scalars().all()

    async def list_findings(self, scan_id: uuid.UUID):
        """List findings for a scan in this org (verifies chain of ownership)."""
        from engine.models.scan import Finding, Scan

        scan_result = await self._db.execute(
            select(Scan).where(Scan.id == scan_id)
        )
        scan = scan_result.scalar_one_or_none()
        if not scan:
            raise HTTPException(status_code=404, detail="Scan not found")

        # Verify project ownership
        await self.get_project(scan.project_id)

        result = await self._db.execute(
            select(Finding).where(Finding.scan_id == scan_id)
        )
        return result.scalars().all()
