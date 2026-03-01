"""Role-Based Access Control (RBAC) — fine-grained permission enforcement.

Provides:
- Permission enum covering all platform actions
- Role → permission mapping (org-level and project-level)
- FastAPI dependency for permission checking
- Project-level role overrides (e.g., viewer on org but editor on a project)

Roles hierarchy: admin > editor > viewer
    admin  — full access (create/delete org, manage members, all project ops)
    editor — create/run scans, manage findings, generate reports
    viewer — read-only access to projects, scans, findings, reports
"""

from __future__ import annotations

import logging
import uuid
from enum import Enum
from typing import Any, Callable

from fastapi import Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from engine.api.middleware.auth import get_current_user
from engine.core.database import get_db
from engine.models.user import OrgMembership, User

logger = logging.getLogger(__name__)


# ── Permissions ──────────────────────────────────────────────────────────────


class Permission(str, Enum):
    # Organization
    ORG_READ = "org:read"
    ORG_UPDATE = "org:update"
    ORG_DELETE = "org:delete"
    ORG_MANAGE_MEMBERS = "org:manage_members"
    ORG_VIEW_BILLING = "org:view_billing"
    ORG_MANAGE_BILLING = "org:manage_billing"

    # Project
    PROJECT_CREATE = "project:create"
    PROJECT_READ = "project:read"
    PROJECT_UPDATE = "project:update"
    PROJECT_DELETE = "project:delete"
    PROJECT_MANAGE_SETTINGS = "project:manage_settings"

    # Scan
    SCAN_CREATE = "scan:create"
    SCAN_READ = "scan:read"
    SCAN_DELETE = "scan:delete"
    SCAN_CANCEL = "scan:cancel"

    # Finding
    FINDING_READ = "finding:read"
    FINDING_UPDATE_STATUS = "finding:update_status"
    FINDING_ASSIGN = "finding:assign"
    FINDING_COMMENT = "finding:comment"
    FINDING_EXPORT = "finding:export"

    # Report
    REPORT_GENERATE = "report:generate"
    REPORT_READ = "report:read"
    REPORT_PUBLISH = "report:publish"
    REPORT_DELETE = "report:delete"

    # Soul Fuzzer
    CAMPAIGN_CREATE = "campaign:create"
    CAMPAIGN_READ = "campaign:read"
    CAMPAIGN_CANCEL = "campaign:cancel"

    # Webhook / Integration
    WEBHOOK_CREATE = "webhook:create"
    WEBHOOK_READ = "webhook:read"
    WEBHOOK_UPDATE = "webhook:update"
    WEBHOOK_DELETE = "webhook:delete"

    # Audit
    AUDIT_READ = "audit:read"
    AUDIT_EXPORT = "audit:export"

    # Admin
    ADMIN_COMPLIANCE = "admin:compliance"
    ADMIN_PLUGINS = "admin:plugins"
    ADMIN_SETTINGS = "admin:settings"


# ── Role → Permission Map ───────────────────────────────────────────────────

ROLE_PERMISSIONS: dict[str, set[Permission]] = {
    "viewer": {
        Permission.ORG_READ,
        Permission.PROJECT_READ,
        Permission.SCAN_READ,
        Permission.FINDING_READ,
        Permission.FINDING_COMMENT,
        Permission.REPORT_READ,
        Permission.CAMPAIGN_READ,
        Permission.WEBHOOK_READ,
    },
    "editor": {
        # Inherits all viewer permissions plus:
        Permission.ORG_READ,
        Permission.PROJECT_CREATE,
        Permission.PROJECT_READ,
        Permission.PROJECT_UPDATE,
        Permission.PROJECT_MANAGE_SETTINGS,
        Permission.SCAN_CREATE,
        Permission.SCAN_READ,
        Permission.SCAN_DELETE,
        Permission.SCAN_CANCEL,
        Permission.FINDING_READ,
        Permission.FINDING_UPDATE_STATUS,
        Permission.FINDING_ASSIGN,
        Permission.FINDING_COMMENT,
        Permission.FINDING_EXPORT,
        Permission.REPORT_GENERATE,
        Permission.REPORT_READ,
        Permission.REPORT_PUBLISH,
        Permission.CAMPAIGN_CREATE,
        Permission.CAMPAIGN_READ,
        Permission.CAMPAIGN_CANCEL,
        Permission.WEBHOOK_CREATE,
        Permission.WEBHOOK_READ,
        Permission.WEBHOOK_UPDATE,
        Permission.AUDIT_READ,
    },
    "admin": {p for p in Permission},  # All permissions
}


# ── Permission checking ─────────────────────────────────────────────────────


async def _get_user_org_role(
    user_id: uuid.UUID,
    org_id: uuid.UUID,
    db: AsyncSession,
) -> str | None:
    """Get the user's role in an organization."""
    result = await db.execute(
        select(OrgMembership.role).where(
            OrgMembership.user_id == user_id,
            OrgMembership.org_id == org_id,
        )
    )
    return result.scalar_one_or_none()


def has_permission(role: str, permission: Permission) -> bool:
    """Check if a role grants a specific permission."""
    perms = ROLE_PERMISSIONS.get(role, set())
    return permission in perms


class RequirePermission:
    """FastAPI dependency that enforces a specific permission.

    Usage:
        @router.post("/scans")
        async def create_scan(
            _auth: None = Depends(RequirePermission(Permission.SCAN_CREATE, org_param="org_id")),
        ):
            ...
    """

    def __init__(
        self,
        permission: Permission,
        org_param: str = "org_id",
    ) -> None:
        self._permission = permission
        self._org_param = org_param

    async def __call__(
        self,
        user: User = Depends(get_current_user),
        db: AsyncSession = Depends(get_db),
        **kwargs: Any,
    ) -> User:
        """Resolve org from request and verify permission."""
        from engine.api.middleware.tenant import get_current_org_id

        org_id = get_current_org_id()
        if not org_id:
            # If no tenant context, check if permission is global
            if self._permission in {Permission.AUDIT_READ, Permission.ADMIN_COMPLIANCE}:
                return user
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Organization context required. Set X-Org-Slug header.",
            )

        role = await _get_user_org_role(user.id, org_id, db)
        if role is None:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Not a member of this organization",
            )

        if not has_permission(role, self._permission):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Permission denied: {self._permission.value} requires role '{_min_role(self._permission)}'",
            )

        return user


def require_permission(permission: Permission) -> Callable:
    """Convenience wrapper for RequirePermission dependency.

    Usage:
        @router.delete("/projects/{id}")
        async def delete_project(
            id: str,
            user: User = Depends(require_permission(Permission.PROJECT_DELETE)),
        ):
            ...
    """
    dep = RequirePermission(permission)
    return Depends(dep)


# ── Helpers ──────────────────────────────────────────────────────────────────


def _min_role(permission: Permission) -> str:
    """Find the least-privileged role that grants a permission."""
    for role in ("viewer", "editor", "admin"):
        if has_permission(role, permission):
            return role
    return "admin"


def get_permissions_for_role(role: str) -> list[str]:
    """Return list of permission strings for a given role."""
    perms = ROLE_PERMISSIONS.get(role, set())
    return sorted(p.value for p in perms)


def check_project_access(
    user_role: str,
    project_role: str | None,
    permission: Permission,
) -> bool:
    """Check permission considering project-level role override.

    If the user has a project-level role, it takes precedence over
    their org-level role for that specific project.
    """
    effective_role = project_role or user_role
    return has_permission(effective_role, permission)
