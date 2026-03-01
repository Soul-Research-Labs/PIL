"""Authentication & token management routes.

Routes:
    POST /api/v1/auth/register       — Register new user
    POST /api/v1/auth/login          — Login with credentials
    POST /api/v1/auth/refresh        — Refresh access token
    POST /api/v1/auth/github         — GitHub OAuth callback
    GET  /api/v1/auth/me             — Get current user
    POST /api/v1/auth/api-keys       — Create API key
    GET  /api/v1/auth/api-keys       — List API keys
    DELETE /api/v1/auth/api-keys/{id}— Revoke API key
"""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, EmailStr
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from engine.core.database import get_db
from engine.api.middleware.auth import (
    create_access_token,
    create_refresh_token,
    decode_token,
    encrypt_token,
    generate_api_key,
    get_current_user,
    hash_api_key,
    hash_password,
    verify_password,
)
from engine.models.user import APIKey, Organization, OrgMembership, User

router = APIRouter()


# ── Schemas ──────────────────────────────────────────────────────────────────


class RegisterRequest(BaseModel):
    username: str
    email: EmailStr
    password: str

    @classmethod
    def _validate_password(cls, v: str) -> str:  # noqa: N805
        if len(v) < 8:
            raise ValueError("Password must be at least 8 characters")
        if not any(c.isupper() for c in v):
            raise ValueError("Password must contain at least one uppercase letter")
        if not any(c.isdigit() for c in v):
            raise ValueError("Password must contain at least one digit")
        return v

    def model_post_init(self, __context: object) -> None:
        self._validate_password(self.password)


class LoginRequest(BaseModel):
    email: str
    password: str


class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"


class RefreshRequest(BaseModel):
    refresh_token: str


class GitHubAuthRequest(BaseModel):
    github_id: int
    username: str
    email: str | None = None
    avatar_url: str | None = None
    access_token: str


class UserResponse(BaseModel):
    id: uuid.UUID
    username: str
    email: str | None
    display_name: str | None
    avatar_url: str | None
    is_active: bool

    model_config = {"from_attributes": True}


class APIKeyCreate(BaseModel):
    name: str


class APIKeyResponse(BaseModel):
    id: uuid.UUID
    name: str
    key: str | None = None  # Only returned on creation
    is_active: bool
    created_at: str

    model_config = {"from_attributes": True}


# ── Routes ───────────────────────────────────────────────────────────────────


@router.post("/register", response_model=TokenResponse, status_code=201)
async def register(
    payload: RegisterRequest,
    db: AsyncSession = Depends(get_db),
) -> TokenResponse:
    """Register a new user account."""
    # Check for existing user
    result = await db.execute(
        select(User).where((User.email == payload.email) | (User.username == payload.username))
    )
    if result.scalar_one_or_none():
        raise HTTPException(status_code=409, detail="User with this email or username already exists")

    # Create user with hashed password
    user = User(
        username=payload.username,
        email=payload.email,
        display_name=payload.username,
        password_hash=hash_password(payload.password),
    )
    db.add(user)
    await db.flush()
    await db.refresh(user)

    # Create default personal organization
    org = Organization(name=f"{payload.username}'s Workspace", slug=payload.username)
    db.add(org)
    await db.flush()
    await db.refresh(org)

    membership = OrgMembership(user_id=user.id, org_id=org.id, role="admin")
    db.add(membership)

    return TokenResponse(
        access_token=create_access_token(str(user.id)),
        refresh_token=create_refresh_token(str(user.id)),
    )


@router.post("/login", response_model=TokenResponse)
async def login(
    payload: LoginRequest,
    db: AsyncSession = Depends(get_db),
) -> TokenResponse:
    """Login with email and password."""
    result = await db.execute(select(User).where(User.email == payload.email))
    user = result.scalar_one_or_none()
    if not user or not user.is_active:
        raise HTTPException(status_code=401, detail="Invalid credentials")

    # Verify password (skip for GitHub-only accounts with no password)
    if not user.password_hash or not verify_password(payload.password, user.password_hash):
        raise HTTPException(status_code=401, detail="Invalid credentials")

    return TokenResponse(
        access_token=create_access_token(str(user.id)),
        refresh_token=create_refresh_token(str(user.id)),
    )


@router.post("/refresh", response_model=TokenResponse)
async def refresh_token(
    payload: RefreshRequest,
    db: AsyncSession = Depends(get_db),
) -> TokenResponse:
    """Refresh an expired access token."""
    decoded = decode_token(payload.refresh_token)
    if decoded.get("type") != "refresh":
        raise HTTPException(status_code=401, detail="Invalid refresh token")

    user_id = decoded.get("sub")
    user = await db.get(User, uuid.UUID(user_id))
    if not user or not user.is_active:
        raise HTTPException(status_code=401, detail="User not found or inactive")

    return TokenResponse(
        access_token=create_access_token(str(user.id)),
        refresh_token=create_refresh_token(str(user.id)),
    )


@router.post("/github", response_model=TokenResponse)
async def github_auth(
    payload: GitHubAuthRequest,
    db: AsyncSession = Depends(get_db),
) -> TokenResponse:
    """Authenticate via GitHub OAuth — creates user on first login.

    The client must supply a valid GitHub access_token. We verify it
    server-side by calling the GitHub /user API to confirm identity.
    """
    # V-009 FIX: Validate the access_token against GitHub to prevent spoofing
    import httpx
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            gh_resp = await client.get(
                "https://api.github.com/user",
                headers={"Authorization": f"Bearer {payload.access_token}"},
            )
            if gh_resp.status_code != 200:
                raise HTTPException(status_code=401, detail="Invalid GitHub access token")
            gh_user = gh_resp.json()
            if gh_user.get("id") != payload.github_id:
                raise HTTPException(
                    status_code=401,
                    detail="GitHub token does not match the provided github_id",
                )
    except httpx.RequestError:
        raise HTTPException(status_code=502, detail="Failed to verify GitHub token")

    result = await db.execute(select(User).where(User.github_id == payload.github_id))
    user = result.scalar_one_or_none()

    if not user:
        # Create new user from GitHub profile
        user = User(
            username=payload.username,
            email=payload.email,
            display_name=payload.username,
            avatar_url=payload.avatar_url,
            github_id=payload.github_id,
            github_access_token=encrypt_token(payload.access_token),
        )
        db.add(user)
        await db.flush()
        await db.refresh(user)

        # Create default org
        org = Organization(name=f"{payload.username}'s Workspace", slug=payload.username)
        db.add(org)
        await db.flush()
        membership = OrgMembership(user_id=user.id, org_id=org.id, role="admin")
        db.add(membership)
    else:
        # Update GitHub token
        user.github_access_token = encrypt_token(payload.access_token)
        if payload.avatar_url:
            user.avatar_url = payload.avatar_url

    return TokenResponse(
        access_token=create_access_token(str(user.id)),
        refresh_token=create_refresh_token(str(user.id)),
    )


@router.get("/me", response_model=UserResponse)
async def get_me(user: User = Depends(get_current_user)) -> User:
    """Get the currently authenticated user."""
    return user


class UpdateProfileRequest(BaseModel):
    display_name: str | None = None
    email: EmailStr | None = None


@router.patch("/me", response_model=UserResponse)
async def update_me(
    payload: UpdateProfileRequest,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> User:
    """Update the current user's profile."""
    if payload.display_name is not None:
        user.display_name = payload.display_name
    if payload.email is not None:
        # Check uniqueness
        existing = await db.execute(
            select(User).where(User.email == payload.email, User.id != user.id)
        )
        if existing.scalar_one_or_none():
            raise HTTPException(status_code=409, detail="Email already in use")
        user.email = payload.email
    return user


@router.post("/api-keys", response_model=APIKeyResponse, status_code=201)
async def create_api_key(
    payload: APIKeyCreate,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> dict:
    """Create a new API key. The raw key is only returned once."""
    raw_key, key_hash = generate_api_key()

    api_key = APIKey(
        user_id=user.id,
        name=payload.name,
        key_hash=key_hash,
    )
    db.add(api_key)
    await db.flush()
    await db.refresh(api_key)

    return {
        "id": api_key.id,
        "name": api_key.name,
        "key": raw_key,
        "is_active": api_key.is_active,
        "created_at": api_key.created_at.isoformat(),
    }


@router.get("/api-keys", response_model=list[APIKeyResponse])
async def list_api_keys(
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> list[dict]:
    """List all API keys for the current user."""
    result = await db.execute(
        select(APIKey).where(APIKey.user_id == user.id).order_by(APIKey.created_at.desc())
    )
    keys = result.scalars().all()
    return [
        {
            "id": k.id,
            "name": k.name,
            "key": None,
            "is_active": k.is_active,
            "created_at": k.created_at.isoformat(),
        }
        for k in keys
    ]


@router.delete("/api-keys/{key_id}", status_code=204)
async def revoke_api_key(
    key_id: uuid.UUID,
    user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> None:
    """Revoke an API key."""
    result = await db.execute(
        select(APIKey).where(APIKey.id == key_id, APIKey.user_id == user.id)
    )
    api_key = result.scalar_one_or_none()
    if not api_key:
        raise HTTPException(status_code=404, detail="API key not found")

    api_key.is_active = False
