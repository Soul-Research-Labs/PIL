"""Integration test fixtures — provides a real (SQLite-async) database session,
an authenticated ``httpx.AsyncClient`` bound to the FastAPI app, and helper
factories for creating test users, projects, and scans.

Usage in a test file:

    @pytest.mark.asyncio
    async def test_list_projects(auth_client: AsyncClient):
        resp = await auth_client.get("/api/v1/projects/")
        assert resp.status_code == 200
"""

from __future__ import annotations

import uuid
from typing import AsyncGenerator

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import (
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

# Reset engine BEFORE importing models/app so nothing binds to Postgres.
from engine.core import database as _db_mod

_db_mod.reset_engine()

from engine.models.base import Base
from engine.models.user import User
from engine.api.middleware.auth import create_access_token, hash_password
from engine.core.database import get_db
from engine.api.main import create_app

# ---------------------------------------------------------------------------
# In-memory SQLite engine shared across the whole test session
# ---------------------------------------------------------------------------

TEST_DB_URL = "sqlite+aiosqlite:///:memory:"

_test_engine = create_async_engine(TEST_DB_URL, echo=False)
_test_session_factory = async_sessionmaker(
    _test_engine, class_=AsyncSession, expire_on_commit=False
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest_asyncio.fixture(scope="session", autouse=True)
async def _create_tables():
    """Create all tables once per test-session, drop at teardown."""
    async with _test_engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield
    async with _test_engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
    await _test_engine.dispose()


@pytest_asyncio.fixture
async def db_session() -> AsyncGenerator[AsyncSession, None]:
    """Yield a transactional session that rolls back after each test."""
    async with _test_session_factory() as session:
        async with session.begin():
            yield session
            await session.rollback()


@pytest_asyncio.fixture
async def test_user(db_session: AsyncSession) -> User:
    """Create and return a fresh test user."""
    user = User(
        id=uuid.uuid4(),
        username=f"testuser-{uuid.uuid4().hex[:8]}",
        email=f"test-{uuid.uuid4().hex[:8]}@zaseon.dev",
        display_name="Test User",
        password_hash=hash_password("password123"),
        is_active=True,
    )
    db_session.add(user)
    await db_session.flush()
    return user


@pytest_asyncio.fixture
async def auth_token(test_user: User) -> str:
    """Return a valid JWT for the test user."""
    return create_access_token(str(test_user.id))


@pytest_asyncio.fixture
async def app():
    """Create a fresh app for testing."""
    return create_app()


@pytest_asyncio.fixture
async def auth_client(
    app,
    db_session: AsyncSession,
    auth_token: str,
) -> AsyncGenerator[AsyncClient, None]:
    """Yield an httpx AsyncClient authenticated with the test user's JWT.

    The ``get_db`` dependency is overridden to use our test session so
    every request shares the same transactional session (and rollback).
    """

    async def _override_get_db():
        yield db_session

    app.dependency_overrides[get_db] = _override_get_db

    transport = ASGITransport(app=app)
    async with AsyncClient(
        transport=transport,
        base_url="http://testserver",
        headers={"Authorization": f"Bearer {auth_token}"},
    ) as client:
        yield client

    app.dependency_overrides.clear()


@pytest_asyncio.fixture
async def anon_client(app) -> AsyncGenerator[AsyncClient, None]:
    """Yield an unauthenticated httpx AsyncClient."""

    async def _override_get_db():
        # Provide a session even for anon requests (some routes may need DB)
        async with _test_session_factory() as session:
            yield session

    app.dependency_overrides[get_db] = _override_get_db

    transport = ASGITransport(app=app)
    async with AsyncClient(
        transport=transport,
        base_url="http://testserver",
    ) as client:
        yield client

    app.dependency_overrides.clear()
