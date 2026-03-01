"""Tests for database models — schema definitions and relationships."""

from __future__ import annotations

import uuid

import pytest

from engine.models.base import Base, TimestampMixin, UUIDMixin
from engine.models.scan import Finding, Project, Report, Scan
from engine.models.user import APIKey, OrgMembership, Organization, User


class TestBaseModel:
    """Verify SQLAlchemy base and mixins."""

    def test_base_exists(self):
        assert Base is not None

    def test_uuid_mixin_has_id(self):
        assert hasattr(UUIDMixin, "id")

    def test_timestamp_mixin_has_created_at(self):
        assert hasattr(TimestampMixin, "created_at")

    def test_timestamp_mixin_has_updated_at(self):
        assert hasattr(TimestampMixin, "updated_at")


class TestUserModels:
    """Verify user and org models."""

    def test_user_table_name(self):
        assert User.__tablename__ == "users"

    def test_user_has_email(self):
        assert hasattr(User, "email")

    def test_user_has_wallet_address(self):
        assert hasattr(User, "wallet_address")

    def test_user_has_github_id(self):
        assert hasattr(User, "github_id")

    def test_organization_table_name(self):
        assert Organization.__tablename__ == "organizations"

    def test_organization_has_slug(self):
        assert hasattr(Organization, "slug")

    def test_org_membership_table_name(self):
        assert OrgMembership.__tablename__ == "org_memberships"

    def test_org_membership_has_role(self):
        assert hasattr(OrgMembership, "role")

    def test_api_key_table_name(self):
        assert APIKey.__tablename__ == "api_keys"


class TestScanModels:
    """Verify scan-related models."""

    def test_project_table_name(self):
        assert Project.__tablename__ == "projects"

    def test_project_has_source_type(self):
        assert hasattr(Project, "source_type")

    def test_scan_table_name(self):
        assert Scan.__tablename__ == "scans"

    def test_scan_has_status(self):
        assert hasattr(Scan, "status")

    def test_scan_has_security_score(self):
        assert hasattr(Scan, "security_score")

    def test_finding_table_name(self):
        assert Finding.__tablename__ == "findings"

    def test_finding_has_severity(self):
        assert hasattr(Finding, "severity")

    def test_finding_has_cwe(self):
        assert hasattr(Finding, "cwe_id")

    def test_finding_has_poc_script(self):
        assert hasattr(Finding, "poc_script")

    def test_finding_has_remediation(self):
        assert hasattr(Finding, "remediation")

    def test_finding_has_patch_diff(self):
        assert hasattr(Finding, "patch_diff")

    def test_report_table_name(self):
        assert Report.__tablename__ == "reports"

    def test_report_has_format(self):
        assert hasattr(Report, "format")

    def test_report_has_verification_hash(self):
        assert hasattr(Report, "verification_hash")


class TestModelRelationships:
    """Verify relationship declarations exist."""

    def test_project_has_scans_relationship(self):
        assert hasattr(Project, "scans")

    def test_scan_has_findings_relationship(self):
        assert hasattr(Scan, "findings")

    def test_scan_has_reports_relationship(self):
        assert hasattr(Scan, "reports")

    def test_user_has_org_memberships(self):
        assert hasattr(User, "org_memberships")

    def test_user_has_api_keys(self):
        assert hasattr(User, "api_keys")

    def test_org_has_projects(self):
        assert hasattr(Organization, "projects")
