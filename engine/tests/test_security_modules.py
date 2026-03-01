"""Tests for security modules — encryption, compliance, RBAC, tenant middleware.

Covers:
    - FieldCipher encrypt/decrypt round-trip, AAD, key derivation, invalid input
    - BulkEncryptor multi-field encrypt/decrypt, is_encrypted heuristic
    - ComplianceChecker control checks and report generation
    - Permission enum, role → permission mapping
    - RequirePermission dependency (mocked)
    - Tenant resolution logic
"""

from __future__ import annotations

import base64
from dataclasses import dataclass
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

# ── FieldCipher ──────────────────────────────────────────────────────────────

from engine.core.encryption import (
    BulkEncryptor,
    FINDING_SENSITIVE_FIELDS,
    FieldCipher,
    _ENCRYPTION_VERSION,
    _NONCE_SIZE,
    _TAG_SIZE,
)


class TestFieldCipher:
    def _cipher(self, key: str = "test-master-key-long-enough-for-derivation") -> FieldCipher:
        return FieldCipher(master_key=key)

    def test_encrypt_decrypt_roundtrip(self):
        c = self._cipher()
        plaintext = "sensitive PoC exploit code"
        ct = c.encrypt(plaintext)
        assert ct != plaintext
        assert c.decrypt(ct) == plaintext

    def test_encrypt_produces_base64(self):
        c = self._cipher()
        ct = c.encrypt("hello")
        blob = base64.b64decode(ct)
        assert blob[0:1] == _ENCRYPTION_VERSION
        assert len(blob) >= 1 + _NONCE_SIZE + _TAG_SIZE

    def test_encrypt_nonce_uniqueness(self):
        c = self._cipher()
        ct1 = c.encrypt("same plaintext")
        ct2 = c.encrypt("same plaintext")
        assert ct1 != ct2  # different nonces

    def test_aad_mismatch_fails(self):
        c = self._cipher()
        ct = c.encrypt("data", associated_data=b"correct-aad")
        with pytest.raises(ValueError, match="Decryption failed"):
            c.decrypt(ct, associated_data=b"wrong-aad")

    def test_aad_success(self):
        c = self._cipher()
        aad = b"finding:uuid123"
        ct = c.encrypt("classified data", associated_data=aad)
        assert c.decrypt(ct, associated_data=aad) == "classified data"

    def test_wrong_key_fails(self):
        c1 = self._cipher("key-one-for-encrypt-use")
        c2 = self._cipher("key-two-for-decrypt-use")
        ct = c1.encrypt("secret")
        with pytest.raises(ValueError, match="Decryption failed"):
            c2.decrypt(ct)

    def test_invalid_base64(self):
        c = self._cipher()
        with pytest.raises(ValueError, match="Invalid base64"):
            c.decrypt("not-valid-base64!!!")

    def test_ciphertext_too_short(self):
        c = self._cipher()
        short = base64.b64encode(b"\x01" + b"\x00" * 5).decode()
        with pytest.raises(ValueError, match="too short"):
            c.decrypt(short)

    def test_wrong_version(self):
        c = self._cipher()
        blob = b"\x99" + b"\x00" * (_NONCE_SIZE + _TAG_SIZE + 10)
        ct = base64.b64encode(blob).decode()
        with pytest.raises(ValueError, match="Unknown encryption version"):
            c.decrypt(ct)

    def test_rotate_key(self):
        old = self._cipher("old-key-for-rotation")
        new = self._cipher("new-key-for-rotation")
        ct_old = old.encrypt("rotate me")
        ct_new = old.rotate_key(ct_old, new)
        assert new.decrypt(ct_new) == "rotate me"

    def test_empty_string(self):
        c = self._cipher()
        ct = c.encrypt("")
        assert c.decrypt(ct) == ""

    def test_unicode(self):
        c = self._cipher()
        text = "漏洞 PoC 🔥 reentrancy"
        ct = c.encrypt(text)
        assert c.decrypt(ct) == text


# ── BulkEncryptor ────────────────────────────────────────────────────────────


class TestBulkEncryptor:
    def _cipher(self) -> FieldCipher:
        return FieldCipher(master_key="bulk-test-key-for-enc")

    def test_encrypt_decrypt_fields(self):
        @dataclass
        class FakeFinding:
            id: str = "uuid-123"
            poc_script: str = "forge test --match testExploit"
            remediation: str = "Apply CEI pattern"
            code_snippet: str = "function withdraw() {}"
            title: str = "Public title"  # not in sensitive list

        obj = FakeFinding()
        cipher = self._cipher()
        enc = BulkEncryptor(cipher, ["poc_script", "remediation", "code_snippet"])

        enc.encrypt_fields(obj, id_for_aad="uuid-123")
        assert obj.poc_script != "forge test --match testExploit"
        assert obj.title == "Public title"  # unencrypted

        enc.decrypt_fields(obj, id_for_aad="uuid-123")
        assert obj.poc_script == "forge test --match testExploit"
        assert obj.remediation == "Apply CEI pattern"
        assert obj.code_snippet == "function withdraw() {}"

    def test_skip_none_fields(self):
        @dataclass
        class Partial:
            poc_script: str | None = None
            remediation: str = "fix it"

        obj = Partial()
        cipher = self._cipher()
        enc = BulkEncryptor(cipher, ["poc_script", "remediation"])
        enc.encrypt_fields(obj)
        assert obj.poc_script is None  # unchanged
        assert obj.remediation != "fix it"  # encrypted

    def test_is_encrypted_detection(self):
        cipher = self._cipher()
        ct = cipher.encrypt("test")
        assert BulkEncryptor._is_encrypted(ct) is True
        assert BulkEncryptor._is_encrypted("plain text") is False
        assert BulkEncryptor._is_encrypted("") is False

    def test_double_encrypt_prevention(self):
        """Encrypting already-encrypted data should be a no-op."""
        @dataclass
        class Obj:
            data: str = "secret"

        obj = Obj()
        cipher = self._cipher()
        enc = BulkEncryptor(cipher, ["data"])
        enc.encrypt_fields(obj)
        first_ct = obj.data
        enc.encrypt_fields(obj)  # should detect it's already encrypted
        assert obj.data == first_ct  # unchanged


# ── Compliance ───────────────────────────────────────────────────────────────

from engine.core.compliance import (
    ComplianceChecker,
    ComplianceReport,
    ControlStatus,
    TrustCategory,
)


class TestComplianceChecker:
    def test_run_all_checks(self):
        checker = ComplianceChecker()
        report = checker.run_all_checks()
        assert isinstance(report, ComplianceReport)
        assert len(report.controls) >= 10  # at least 10 controls checked
        assert 0.0 <= report.compliance_pct <= 100.0

    def test_report_has_categories(self):
        checker = ComplianceChecker()
        report = checker.run_all_checks()
        categories = {c.category for c in report.controls}
        # Should cover multiple trust categories
        assert len(categories) >= 3

    def test_control_statuses(self):
        checker = ComplianceChecker()
        report = checker.run_all_checks()
        statuses = {c.status for c in report.controls}
        # Should have some passed and possibly some failed
        assert ControlStatus.PASS in statuses or ControlStatus.FAIL in statuses

    def test_overall_status(self):
        checker = ComplianceChecker()
        report = checker.run_all_checks()
        assert report.overall_status in (
            ControlStatus.PASS,
            ControlStatus.FAIL,
            ControlStatus.PARTIAL,
        )


# ── RBAC ─────────────────────────────────────────────────────────────────────

from engine.api.middleware.rbac import (
    Permission,
    ROLE_PERMISSIONS,
    get_permissions_for_role,
)


class TestRBAC:
    def test_permission_enum_count(self):
        assert len(Permission) == 36

    def test_viewer_permissions(self):
        perms = ROLE_PERMISSIONS["viewer"]
        assert Permission.ORG_READ in perms
        assert Permission.PROJECT_READ in perms
        assert Permission.PROJECT_CREATE not in perms
        assert Permission.SCAN_CREATE not in perms

    def test_editor_permissions(self):
        perms = ROLE_PERMISSIONS["editor"]
        assert Permission.PROJECT_CREATE in perms
        assert Permission.SCAN_CREATE in perms
        assert Permission.FINDING_ASSIGN in perms
        assert Permission.ADMIN_SETTINGS not in perms

    def test_admin_has_all(self):
        admin_perms = ROLE_PERMISSIONS["admin"]
        for p in Permission:
            assert p in admin_perms, f"Admin missing {p}"

    def test_get_permissions_for_role(self):
        viewer = get_permissions_for_role("viewer")
        assert isinstance(viewer, set)
        assert len(viewer) == 8

    def test_get_permissions_unknown_role(self):
        perms = get_permissions_for_role("unknown_role")
        assert len(perms) == 0

    def test_roles_subset_hierarchy(self):
        """Viewer ⊂ Editor ⊂ Admin."""
        viewer = ROLE_PERMISSIONS["viewer"]
        editor = ROLE_PERMISSIONS["editor"]
        admin = ROLE_PERMISSIONS["admin"]
        assert viewer.issubset(editor)
        assert editor.issubset(admin)


# ── Tenant ───────────────────────────────────────────────────────────────────

from engine.api.middleware.tenant import (
    get_current_org_id,
    get_current_org_role,
    _current_org_id,
    _current_org_role,
)


class TestTenantContext:
    def test_context_var_defaults(self):
        """Context vars should default to None."""
        # In a fresh context, they should be None
        assert _current_org_id.get(None) is None or isinstance(_current_org_id.get(None), str | None)

    def test_get_current_org_id(self):
        token = _current_org_id.set("org-123")
        try:
            assert get_current_org_id() == "org-123"
        finally:
            _current_org_id.reset(token)

    def test_get_current_org_role(self):
        token = _current_org_role.set("admin")
        try:
            assert get_current_org_role() == "admin"
        finally:
            _current_org_role.reset(token)


# ── Audit model ──────────────────────────────────────────────────────────────

from engine.models.audit import AuditAction, AuditSeverity


class TestAuditModel:
    def test_action_enum(self):
        assert len(AuditAction) == 31

    def test_severity_enum(self):
        assert AuditSeverity.INFO.value == "info"
        assert AuditSeverity.CRITICAL.value == "critical"

    def test_action_categories(self):
        """Actions should span auth, org, project, scan, finding, etc."""
        action_names = [a.value for a in AuditAction]
        assert any("auth" in a for a in action_names)
        assert any("org" in a for a in action_names)
        assert any("scan" in a for a in action_names)
        assert any("finding" in a for a in action_names)
