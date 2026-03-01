"""User, organization, and auth models."""

from __future__ import annotations

import uuid

from sqlalchemy import Boolean, ForeignKey, String, Text
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from engine.models.base import Base, TimestampMixin, UUIDMixin


class User(Base, UUIDMixin, TimestampMixin):
    """A platform user (authenticated via GitHub or wallet)."""

    __tablename__ = "users"

    email: Mapped[str] = mapped_column(String(320), unique=True, nullable=True)
    username: Mapped[str] = mapped_column(String(100), unique=True, nullable=False)
    display_name: Mapped[str] = mapped_column(String(200), nullable=True)
    avatar_url: Mapped[str | None] = mapped_column(Text, nullable=True)
    password_hash: Mapped[str | None] = mapped_column(Text, nullable=True)

    # GitHub auth
    github_id: Mapped[int | None] = mapped_column(nullable=True, unique=True)
    github_access_token: Mapped[str | None] = mapped_column(Text, nullable=True)

    # Wallet auth (SIWE)
    wallet_address: Mapped[str | None] = mapped_column(String(42), nullable=True, unique=True)

    is_active: Mapped[bool] = mapped_column(Boolean, default=True)

    # Relationships
    org_memberships: Mapped[list["OrgMembership"]] = relationship(back_populates="user")
    api_keys: Mapped[list["APIKey"]] = relationship(back_populates="user")


class Organization(Base, UUIDMixin, TimestampMixin):
    """An organization that owns projects and scans."""

    __tablename__ = "organizations"

    name: Mapped[str] = mapped_column(String(200), nullable=False)
    slug: Mapped[str] = mapped_column(String(200), unique=True, nullable=False)
    logo_url: Mapped[str | None] = mapped_column(Text, nullable=True)

    # Relationships
    memberships: Mapped[list["OrgMembership"]] = relationship(back_populates="organization")
    projects: Mapped[list["Project"]] = relationship(back_populates="organization")


class OrgMembership(Base, UUIDMixin, TimestampMixin):
    """Many-to-many linking users to organizations with roles."""

    __tablename__ = "org_memberships"

    user_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id"), nullable=False
    )
    org_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("organizations.id"), nullable=False
    )
    role: Mapped[str] = mapped_column(
        String(20), default="viewer"
    )  # admin, editor, viewer

    user: Mapped["User"] = relationship(back_populates="org_memberships")
    organization: Mapped["Organization"] = relationship(back_populates="memberships")


class APIKey(Base, UUIDMixin, TimestampMixin):
    """API key for programmatic access."""

    __tablename__ = "api_keys"

    user_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id"), nullable=False
    )
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    key_hash: Mapped[str] = mapped_column(String(128), nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)

    user: Mapped["User"] = relationship(back_populates="api_keys")
