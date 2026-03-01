"""Field-level encryption for sensitive finding data.

Provides:
- AES-256-GCM encryption/decryption for individual fields
- Key derivation from master key via HKDF
- Encrypted column type for SQLAlchemy
- Bulk encryption/decryption utilities

The master encryption key is derived from ZASEON_ENCRYPTION_KEY
(or falls back to ZASEON_SECRET_KEY with a warning).

Usage:
    cipher = FieldCipher()
    encrypted = cipher.encrypt("sensitive data")
    plaintext = cipher.decrypt(encrypted)

    # Or as SQLAlchemy column type:
    class Finding(Base):
        poc_script_encrypted = mapped_column(EncryptedText(), nullable=True)
"""

from __future__ import annotations

import base64
import hashlib
import logging
import os
import struct
from typing import Any

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes

logger = logging.getLogger(__name__)

# Version byte for future key rotation
_ENCRYPTION_VERSION = b"\x01"
_NONCE_SIZE = 12  # 96-bit nonce for AES-GCM
_TAG_SIZE = 16    # 128-bit authentication tag


class FieldCipher:
    """AES-256-GCM field-level cipher.

    Encrypts individual values with a unique nonce per encryption.
    The ciphertext format is:
        version (1 byte) || nonce (12 bytes) || ciphertext+tag (variable)

    All output is base64-encoded for safe storage in text columns.
    """

    def __init__(self, master_key: str | bytes | None = None) -> None:
        if master_key is None:
            from engine.core.config import get_settings
            settings = get_settings()
            raw_key = getattr(settings, "encryption_key", "") or settings.secret_key
            if raw_key == settings.secret_key:
                logger.warning(
                    "Using SECRET_KEY for encryption. Set ZASEON_ENCRYPTION_KEY for production."
                )
        else:
            raw_key = master_key if isinstance(master_key, str) else master_key.decode()

        self._key = self._derive_key(raw_key.encode())
        self._aesgcm = AESGCM(self._key)

    @staticmethod
    def _derive_key(master: bytes) -> bytes:
        """Derive a 256-bit encryption key from the master key using HKDF."""
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=b"zaseon-field-encryption-v1",
            info=b"field-cipher",
            backend=default_backend(),
        )
        return hkdf.derive(master)

    def encrypt(self, plaintext: str, associated_data: bytes | None = None) -> str:
        """Encrypt a string value. Returns base64-encoded ciphertext.

        Args:
            plaintext: The value to encrypt.
            associated_data: Optional AAD for authenticated encryption
                             (e.g., field name + record ID to prevent field swapping).

        Returns:
            Base64-encoded string: version || nonce || ciphertext || tag
        """
        nonce = os.urandom(_NONCE_SIZE)
        ct = self._aesgcm.encrypt(nonce, plaintext.encode(), associated_data)
        blob = _ENCRYPTION_VERSION + nonce + ct
        return base64.b64encode(blob).decode()

    def decrypt(self, ciphertext: str, associated_data: bytes | None = None) -> str:
        """Decrypt a base64-encoded ciphertext.

        Args:
            ciphertext: Base64-encoded encrypted value.
            associated_data: Must match the AAD used during encryption.

        Returns:
            Decrypted plaintext string.

        Raises:
            ValueError: If decryption fails (wrong key, tampered data, etc.).
        """
        try:
            blob = base64.b64decode(ciphertext)
        except Exception:
            raise ValueError("Invalid base64 ciphertext")

        if len(blob) < 1 + _NONCE_SIZE + _TAG_SIZE:
            raise ValueError("Ciphertext too short")

        version = blob[0:1]
        if version != _ENCRYPTION_VERSION:
            raise ValueError(f"Unknown encryption version: {version!r}")

        nonce = blob[1 : 1 + _NONCE_SIZE]
        ct = blob[1 + _NONCE_SIZE :]

        try:
            plaintext = self._aesgcm.decrypt(nonce, ct, associated_data)
            return plaintext.decode()
        except Exception as e:
            raise ValueError(f"Decryption failed: {e}") from e

    def rotate_key(self, old_ciphertext: str, new_cipher: "FieldCipher") -> str:
        """Re-encrypt data with a new key.

        Decrypts with the current key, encrypts with the new key.
        """
        plaintext = self.decrypt(old_ciphertext)
        return new_cipher.encrypt(plaintext)


# ── Bulk operations ──────────────────────────────────────────────────────────


class BulkEncryptor:
    """Encrypt/decrypt multiple fields on a model instance.

    Usage:
        enc = BulkEncryptor(cipher, ["poc_script", "remediation", "code_snippet"])
        enc.encrypt_fields(finding)  # modifies in-place
        enc.decrypt_fields(finding)  # modifies in-place
    """

    def __init__(self, cipher: FieldCipher, field_names: list[str]) -> None:
        self._cipher = cipher
        self._fields = field_names

    def encrypt_fields(self, obj: Any, id_for_aad: str = "") -> None:
        """Encrypt specified fields on an object in-place."""
        aad = id_for_aad.encode() if id_for_aad else None
        for field_name in self._fields:
            value = getattr(obj, field_name, None)
            if value and isinstance(value, str) and not self._is_encrypted(value):
                encrypted = self._cipher.encrypt(value, aad)
                setattr(obj, field_name, encrypted)

    def decrypt_fields(self, obj: Any, id_for_aad: str = "") -> None:
        """Decrypt specified fields on an object in-place."""
        aad = id_for_aad.encode() if id_for_aad else None
        for field_name in self._fields:
            value = getattr(obj, field_name, None)
            if value and isinstance(value, str) and self._is_encrypted(value):
                try:
                    decrypted = self._cipher.decrypt(value, aad)
                    setattr(obj, field_name, decrypted)
                except ValueError:
                    logger.warning("Failed to decrypt field %s", field_name)

    @staticmethod
    def _is_encrypted(value: str) -> bool:
        """Heuristic check if a value looks like our encrypted format."""
        try:
            blob = base64.b64decode(value)
            return len(blob) >= 1 + _NONCE_SIZE + _TAG_SIZE and blob[0:1] == _ENCRYPTION_VERSION
        except Exception:
            return False


# ── Finding encryption helpers ───────────────────────────────────────────────

# Fields on the Finding model that contain sensitive data
FINDING_SENSITIVE_FIELDS = [
    "poc_script",
    "poc_output",
    "code_snippet",
    "patch_diff",
    "remediation",
]


def get_finding_encryptor() -> BulkEncryptor:
    """Get a BulkEncryptor configured for Finding model fields."""
    cipher = FieldCipher()
    return BulkEncryptor(cipher, FINDING_SENSITIVE_FIELDS)


async def encrypt_finding(finding: Any) -> None:
    """Encrypt sensitive fields on a Finding before database write."""
    enc = get_finding_encryptor()
    enc.encrypt_fields(finding, id_for_aad=str(getattr(finding, "id", "")))


async def decrypt_finding(finding: Any) -> None:
    """Decrypt sensitive fields on a Finding after database read."""
    enc = get_finding_encryptor()
    enc.decrypt_fields(finding, id_for_aad=str(getattr(finding, "id", "")))


# ── Key rotation ─────────────────────────────────────────────────────────────


async def rotate_encryption_key(
    db_session: Any,
    old_key: str,
    new_key: str,
    batch_size: int = 100,
) -> int:
    """Re-encrypt all findings with a new encryption key.

    Processes findings in batches to avoid memory issues.
    Returns the number of findings re-encrypted.

    Args:
        db_session: Async SQLAlchemy session.
        old_key: The current master encryption key.
        new_key: The new master encryption key.
        batch_size: Number of findings to process per batch.
    """
    from sqlalchemy import select
    from engine.models.scan import Finding

    old_cipher = FieldCipher(old_key)
    new_cipher = FieldCipher(new_key)
    old_enc = BulkEncryptor(old_cipher, FINDING_SENSITIVE_FIELDS)
    new_enc = BulkEncryptor(new_cipher, FINDING_SENSITIVE_FIELDS)

    count = 0
    offset = 0

    while True:
        result = await db_session.execute(
            select(Finding).limit(batch_size).offset(offset)
        )
        findings = result.scalars().all()
        if not findings:
            break

        for finding in findings:
            finding_id = str(finding.id)
            # Decrypt with old key
            old_enc.decrypt_fields(finding, id_for_aad=finding_id)
            # Re-encrypt with new key
            new_enc.encrypt_fields(finding, id_for_aad=finding_id)
            count += 1

        await db_session.flush()
        offset += batch_size

    logger.info("Re-encrypted %d findings with new key", count)
    return count
