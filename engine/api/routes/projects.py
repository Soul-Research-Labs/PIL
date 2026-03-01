"""Project management endpoints."""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from engine.core.database import get_db
from engine.models.scan import Project
from engine.models.user import OrgMembership, User
from engine.api.middleware.auth import get_current_user

router = APIRouter()


# ── Schemas ──────────────────────────────────────────────────────────────────


class ProjectCreate(BaseModel):
    """Schema for creating a project."""

    name: str
    description: str | None = None
    source_type: str  # github_repo, contract_address, file_upload
    github_repo_url: str | None = None
    contract_address: str | None = None
    chain: str | None = None
    auto_scan_on_push: bool = True


class ProjectResponse(BaseModel):
    """Schema for project response."""

    id: uuid.UUID
    name: str
    description: str | None
    source_type: str
    github_repo_url: str | None
    contract_address: str | None
    chain: str | None
    auto_scan_on_push: bool

    model_config = {"from_attributes": True}


# ── Helper ───────────────────────────────────────────────────────────────────


async def _get_user_org_id(user: User, db: AsyncSession) -> uuid.UUID:
    """Resolve the user's primary organization ID."""
    result = await db.execute(
        select(OrgMembership.org_id).where(OrgMembership.user_id == user.id).limit(1)
    )
    org_id = result.scalar_one_or_none()
    return org_id or user.id  # fallback to user.id as pseudo-org


# ── Routes ───────────────────────────────────────────────────────────────────


@router.get("/", response_model=list[ProjectResponse])
async def list_projects(
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> list[Project]:
    """List all projects for the current user's organization."""
    org_id = await _get_user_org_id(user, db)
    result = await db.execute(
        select(Project).where(Project.org_id == org_id).limit(50)
    )
    return list(result.scalars().all())


@router.post("/", response_model=ProjectResponse, status_code=201)
async def create_project(
    payload: ProjectCreate,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> Project:
    """Create a new project."""
    org_id = await _get_user_org_id(user, db)
    project = Project(
        org_id=org_id,
        name=payload.name,
        description=payload.description,
        source_type=payload.source_type,
        github_repo_url=payload.github_repo_url,
        contract_address=payload.contract_address,
        chain=payload.chain,
        auto_scan_on_push=payload.auto_scan_on_push,
    )
    db.add(project)
    await db.flush()
    await db.refresh(project)
    return project


@router.get("/{project_id}", response_model=ProjectResponse)
async def get_project(
    project_id: uuid.UUID,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> Project:
    """Get a project by ID."""
    org_id = await _get_user_org_id(user, db)
    project = await db.get(Project, project_id)
    if not project or project.org_id != org_id:
        raise HTTPException(status_code=404, detail="Project not found")
    return project


@router.delete("/{project_id}", status_code=204)
async def delete_project(
    project_id: uuid.UUID,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> None:
    """Delete a project by ID."""
    org_id = await _get_user_org_id(user, db)
    project = await db.get(Project, project_id)
    if not project or project.org_id != org_id:
        raise HTTPException(status_code=404, detail="Project not found")
    await db.delete(project)
