"""Authentication & authorization middleware.

Provides:
- JWT Bearer token verification
- API key authentication
- Current user dependency injection
- Optional auth (for public endpoints)
"""

from __future__ import annotations

import logging
import uuid
from datetime import datetime, timedelta, timezone
from typing import Annotated

import jwt
from fastapi import Depends, Header, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from passlib.context import CryptContext
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from engine.core.config import get_settings
from engine.core.database import get_db
from engine.models.user import APIKey, User

logger = logging.getLogger(__name__)

# ── Password hashing ─────────────────────────────────────────────────────────

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

bearer_scheme = HTTPBearer(auto_error=False)


def hash_password(password: str) -> str:
    """Hash a plaintext password."""
    return pwd_context.hash(password)


def verify_password(plain: str, hashed: str) -> bool:
    """Verify a plaintext password against a hash."""
    return pwd_context.verify(plain, hashed)


# ── JWT Tokens ───────────────────────────────────────────────────────────────

ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60
REFRESH_TOKEN_EXPIRE_DAYS = 30


def create_access_token(user_id: str, extra: dict | None = None) -> str:
    """Create a JWT access token."""
    settings = get_settings()
    now = datetime.now(timezone.utc)
    payload = {
        "sub": user_id,
        "iat": now,
        "exp": now + timedelta(minutes=settings.jwt_access_token_expire_minutes),
        "type": "access",
    }
    if extra:
        payload.update(extra)
    return jwt.encode(payload, settings.secret_key, algorithm=ALGORITHM)


def create_refresh_token(user_id: str) -> str:
    """Create a JWT refresh token."""
    settings = get_settings()
    now = datetime.now(timezone.utc)
    payload = {
        "sub": user_id,
        "iat": now,
        "exp": now + timedelta(days=settings.jwt_refresh_token_expire_days),
        "type": "refresh",
    }
    return jwt.encode(payload, settings.secret_key, algorithm=ALGORITHM)


def decode_token(token: str) -> dict:
    """Decode and verify a JWT token. Raises HTTPException on failure."""
    settings = get_settings()
    try:
        payload = jwt.decode(token, settings.secret_key, algorithms=[ALGORITHM])
        return payload
    except jwt.ExpiredSignatureError:
        logger.warning("Auth failure: expired token")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token has expired",
        )
    except jwt.InvalidTokenError:
        logger.warning("Auth failure: invalid token")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token",
        )


# ── API Key hashing ──────────────────────────────────────────────────────────

import base64
import hashlib
import hmac as hmac_mod

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes


def _get_fernet() -> Fernet:
    """Derive a Fernet key from the application secret_key using HKDF."""
    settings = get_settings()
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=b"zaseon-fernet-v1",
        info=b"encryption-key",
    )
    key_bytes = hkdf.derive(settings.secret_key.encode())
    return Fernet(base64.urlsafe_b64encode(key_bytes))


def encrypt_token(plaintext: str) -> str:
    """Encrypt a token (e.g. GitHub OAuth token) for database storage."""
    return _get_fernet().encrypt(plaintext.encode()).decode()


def decrypt_token(ciphertext: str) -> str:
    """Decrypt a stored token. Returns empty string on failure."""
    try:
        return _get_fernet().decrypt(ciphertext.encode()).decode()
    except (InvalidToken, Exception):
        logger.warning("Token decryption failed — token may be corrupted or key rotated")
        return ""


def hash_api_key(raw_key: str) -> str:
    """HMAC-SHA256 hash of an API key for storage (salted with server secret)."""
    settings = get_settings()
    return hmac_mod.new(
        settings.secret_key.encode(),
        raw_key.encode(),
        hashlib.sha256,
    ).hexdigest()


def generate_api_key() -> tuple[str, str]:
    """Generate (raw_key, key_hash) pair."""
    raw = f"zsk_{uuid.uuid4().hex}"
    return raw, hash_api_key(raw)


# ── Dependencies ─────────────────────────────────────────────────────────────


async def _get_user_from_token(token: str, db: AsyncSession) -> User:
    """Resolve a JWT token to a User object."""
    payload = decode_token(token)
    user_id = payload.get("sub")
    if not user_id:
        raise HTTPException(status_code=401, detail="Invalid token payload")

    try:
        uid = uuid.UUID(user_id)
    except ValueError:
        raise HTTPException(status_code=401, detail="Invalid user ID in token")

    user = await db.get(User, uid)
    if not user or not user.is_active:
        raise HTTPException(status_code=401, detail="User not found or inactive")
    return user


async def _get_user_from_api_key(key: str, db: AsyncSession) -> User:
    """Resolve an API key to a User object."""
    key_hash = hash_api_key(key)
    result = await db.execute(
        select(APIKey).where(APIKey.key_hash == key_hash, APIKey.is_active.is_(True))
    )
    api_key = result.scalar_one_or_none()
    if not api_key:
        raise HTTPException(status_code=401, detail="Invalid API key")

    user = await db.get(User, api_key.user_id)
    if not user or not user.is_active:
        raise HTTPException(status_code=401, detail="User not found or inactive")
    return user


async def get_current_user(
    credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(bearer_scheme)] = None,
    x_api_key: str | None = Header(None),
    db: AsyncSession = Depends(get_db),
) -> User:
    """Require authentication via JWT Bearer token or X-API-Key header.

    Usage in routes:
        @router.get("/protected")
        async def protected(user: User = Depends(get_current_user)):
            ...
    """
    # Try Bearer token first
    if credentials and credentials.credentials:
        return await _get_user_from_token(credentials.credentials, db)

    # Fall back to API key
    if x_api_key:
        return await _get_user_from_api_key(x_api_key, db)

    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Authentication required — provide Bearer token or X-API-Key header",
        headers={"WWW-Authenticate": "Bearer"},
    )


async def get_current_user_optional(
    credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(bearer_scheme)] = None,
    x_api_key: str | None = Header(None),
    db: AsyncSession = Depends(get_db),
) -> User | None:
    """Optional authentication — returns None if no credentials provided.

    Usage in routes for public endpoints that optionally use auth:
        @router.get("/public")
        async def public(user: User | None = Depends(get_current_user_optional)):
            ...
    """
    if not credentials and not x_api_key:
        return None

    try:
        return await get_current_user(credentials, x_api_key, db)
    except HTTPException:
        return None
