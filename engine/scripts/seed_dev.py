#!/usr/bin/env python3
"""
Seed the development database with sample data.

Usage:
    # From engine/ directory (with venv activated):
    python -m engine.scripts.seed_dev

    # Or via Make:
    make seed
"""

from __future__ import annotations

import asyncio
import uuid
from datetime import datetime, timedelta, timezone

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from engine.core.config import get_settings
from engine.core.database import get_session_factory
from engine.api.middleware.auth import hash_password
from engine.models import (
    User,
    Organization,
    OrgMembership,
    Project,
    Scan,
    Finding,
)


async def seed() -> None:
    """Insert sample development data."""
    settings = get_settings()
    print(f"Seeding database: {settings.database_url.split('@')[-1]}")

    async with get_session_factory()() as db:
        # Check if already seeded
        result = await db.execute(text("SELECT count(*) FROM users"))
        count = result.scalar()
        if count and count > 0:
            print(f"Database already has {count} user(s). Skipping seed.")
            print("To re-seed, truncate the tables first: make db-reset")
            return

        now = datetime.now(timezone.utc)

        # ── User ─────────────────────────────────────────────────────
        user_id = uuid.uuid4()
        user = User(
            id=user_id,
            email="dev@zaseon.io",
            username="devuser",
            display_name="Dev User",
            password_hash=hash_password("password123"),
            is_active=True,
        )
        db.add(user)

        # ── Organization ─────────────────────────────────────────────
        org_id = uuid.uuid4()
        org = Organization(
            id=org_id,
            name="ZASEON Dev Org",
            slug="zaseon-dev",
        )
        db.add(org)

        membership = OrgMembership(
            id=uuid.uuid4(),
            user_id=user_id,
            org_id=org_id,
            role="admin",
        )
        db.add(membership)

        # ── Projects ─────────────────────────────────────────────────
        proj1_id = uuid.uuid4()
        proj1 = Project(
            id=proj1_id,
            org_id=org_id,
            name="DeFi Vault Protocol",
            description="A Solidity vault implementation with yield strategies",
            source_type="github_repo",
            github_repo_url="https://github.com/example/defi-vault",
            auto_scan_on_push=True,
        )
        db.add(proj1)

        proj2_id = uuid.uuid4()
        proj2 = Project(
            id=proj2_id,
            org_id=org_id,
            name="NFT Marketplace",
            description="ERC-721 marketplace with auction support",
            source_type="github_repo",
            github_repo_url="https://github.com/example/nft-marketplace",
            auto_scan_on_push=True,
        )
        db.add(proj2)

        proj3_id = uuid.uuid4()
        proj3 = Project(
            id=proj3_id,
            org_id=org_id,
            name="Token Bridge",
            description="Cross-chain token bridge",
            source_type="contract_address",
            contract_address="0x1234567890abcdef1234567890abcdef12345678",
            chain="ethereum",
        )
        db.add(proj3)

        # ── Scans ────────────────────────────────────────────────────
        scan1_id = uuid.uuid4()
        scan1 = Scan(
            id=scan1_id,
            project_id=proj1_id,
            scan_type="SMART_CONTRACT",
            status="COMPLETED",
            trigger="manual",
            security_score=65.0,
            threat_score=35.0,
            total_lines_scanned=4520,
            findings_count=7,
            branch="main",
            commit_sha="a1b2c3d4e5f6",
            started_at=now - timedelta(hours=2, minutes=30),
            completed_at=now - timedelta(hours=2),
        )
        db.add(scan1)

        scan2_id = uuid.uuid4()
        scan2 = Scan(
            id=scan2_id,
            project_id=proj2_id,
            scan_type="SMART_CONTRACT",
            status="COMPLETED",
            trigger="manual",
            security_score=88.0,
            threat_score=12.0,
            total_lines_scanned=2100,
            findings_count=3,
            branch="main",
            commit_sha="e4f5g6h7i8j9",
            started_at=now - timedelta(days=1, hours=3),
            completed_at=now - timedelta(days=1, hours=2, minutes=40),
        )
        db.add(scan2)

        scan3_id = uuid.uuid4()
        scan3 = Scan(
            id=scan3_id,
            project_id=proj1_id,
            scan_type="SMART_CONTRACT",
            status="COMPLETED",
            trigger="webhook",
            security_score=72.0,
            threat_score=28.0,
            total_lines_scanned=4600,
            findings_count=5,
            branch="feat/staking",
            commit_sha="k0l1m2n3o4p5",
            started_at=now - timedelta(hours=6),
            completed_at=now - timedelta(hours=5, minutes=45),
        )
        db.add(scan3)

        # ── Findings ─────────────────────────────────────────────────
        findings_data = [
            # Scan 1 findings (DeFi Vault)
            {
                "scan_id": scan1_id,
                "title": "Reentrancy vulnerability in withdraw()",
                "description": "The withdraw function makes an external call to msg.sender before updating the user's balance. An attacker can recursively call withdraw() to drain the vault.",
                "severity": "CRITICAL",
                "status": "OPEN",
                "category": "Reentrancy",
                "cwe_id": "CWE-841",
                "scwe_id": "SCWE-001",
                "file_path": "src/Vault.sol",
                "start_line": 145,
                "end_line": 162,
                "code_snippet": "function withdraw(uint256 amount) external {\n    require(balances[msg.sender] >= amount);\n    (bool success, ) = msg.sender.call{value: amount}(\"\");\n    require(success);\n    balances[msg.sender] -= amount;\n}",
                "remediation": "Apply the checks-effects-interactions pattern. Update the balance before making the external call, or use a ReentrancyGuard modifier.",
                "cvss_score": 9.8,
            },
            {
                "scan_id": scan1_id,
                "title": "Unchecked return value in token transfer",
                "description": "The transfer() call return value is not checked. Some ERC-20 tokens return false on failure instead of reverting.",
                "severity": "HIGH",
                "status": "OPEN",
                "category": "Token Handling",
                "cwe_id": "CWE-252",
                "scwe_id": "SCWE-004",
                "file_path": "src/Vault.sol",
                "start_line": 89,
                "end_line": 92,
                "code_snippet": "token.transfer(recipient, amount);",
                "remediation": "Use SafeERC20.safeTransfer() from OpenZeppelin or check the return value explicitly.",
                "cvss_score": 7.5,
            },
            {
                "scan_id": scan1_id,
                "title": "Missing zero-address validation",
                "description": "Constructor does not validate that the token address is non-zero, which could lead to a non-functional contract.",
                "severity": "MEDIUM",
                "status": "OPEN",
                "category": "Input Validation",
                "cwe_id": "CWE-20",
                "file_path": "src/Vault.sol",
                "start_line": 32,
                "end_line": 36,
                "code_snippet": "constructor(address _token) {\n    token = IERC20(_token);\n}",
                "remediation": "Add require(_token != address(0), \"Invalid token address\");",
                "cvss_score": 5.0,
            },
            {
                "scan_id": scan1_id,
                "title": "Use of block.timestamp for time comparison",
                "description": "block.timestamp can be manipulated by miners within a ~15 second window.",
                "severity": "LOW",
                "status": "ACCEPTED",
                "category": "Timestamp Dependence",
                "cwe_id": "CWE-829",
                "file_path": "src/Vault.sol",
                "start_line": 110,
                "end_line": 112,
                "code_snippet": "require(block.timestamp >= lockEndTime[msg.sender]);",
                "remediation": "This is acceptable for time windows > 15 minutes. Document the assumption.",
                "cvss_score": 2.0,
            },
            # Scan 2 findings (NFT Marketplace)
            {
                "scan_id": scan2_id,
                "title": "Front-running risk in bid acceptance",
                "description": "The acceptBid function can be front-run by miners or MEV bots to insert a higher bid before the acceptance transaction.",
                "severity": "HIGH",
                "status": "CONFIRMED",
                "category": "Front-Running",
                "cwe_id": "CWE-362",
                "file_path": "src/Marketplace.sol",
                "start_line": 203,
                "end_line": 220,
                "code_snippet": "function acceptBid(uint256 tokenId, uint256 bidIndex) external { ... }",
                "remediation": "Use a commit-reveal scheme or process bids in a batch with a time delay.",
                "cvss_score": 6.5,
            },
            {
                "scan_id": scan2_id,
                "title": "Gas optimization: use uint256 instead of uint8 for loop counter",
                "description": "Using uint8 for a loop counter incurs extra gas due to masking operations.",
                "severity": "GAS",
                "status": "OPEN",
                "category": "Gas Optimization",
                "file_path": "src/Marketplace.sol",
                "start_line": 156,
                "end_line": 158,
                "code_snippet": "for (uint8 i = 0; i < bids.length; i++) {",
                "remediation": "Change uint8 to uint256 for the loop counter.",
                "gas_saved": 200,
            },
            # Scan 3 findings
            {
                "scan_id": scan3_id,
                "title": "Unlocked pragma version",
                "description": "The pragma is set to ^0.8.0, allowing compilation with any 0.8.x version. This could introduce unexpected behavior with newer compiler versions.",
                "severity": "INFO",
                "status": "OPEN",
                "category": "Best Practices",
                "file_path": "src/Vault.sol",
                "start_line": 1,
                "end_line": 1,
                "code_snippet": "pragma solidity ^0.8.0;",
                "remediation": "Lock to a specific version: pragma solidity 0.8.20;",
            },
        ]

        for fd in findings_data:
            finding = Finding(
                id=uuid.uuid4(),
                scan_id=fd["scan_id"],
                title=fd["title"],
                description=fd["description"],
                severity=fd["severity"],
                status=fd.get("status", "OPEN"),
                category=fd.get("category", ""),
                cwe_id=fd.get("cwe_id", ""),
                scwe_id=fd.get("scwe_id", ""),
                file_path=fd["file_path"],
                start_line=fd["start_line"],
                end_line=fd["end_line"],
                code_snippet=fd.get("code_snippet", ""),
                remediation=fd.get("remediation", ""),
                cvss_score=fd.get("cvss_score", 0.0),
                gas_saved=fd.get("gas_saved"),
            )
            db.add(finding)

        await db.commit()

        print("✓ Seed completed successfully!")
        print(f"  - 1 user (dev@zaseon.io / password123)")
        print(f"  - 1 organization (zaseon-dev)")
        print(f"  - 3 projects")
        print(f"  - 3 scans (all completed)")
        print(f"  - {len(findings_data)} findings")


if __name__ == "__main__":
    asyncio.run(seed())
