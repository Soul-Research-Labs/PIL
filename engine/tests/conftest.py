"""Shared fixtures for the ZASEON engine test suite."""

from __future__ import annotations

import asyncio
import uuid
from datetime import datetime, timezone
from typing import Any, AsyncGenerator
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from pydantic import BaseModel

from engine.core.types import (
    CVSSVector,
    FindingSchema,
    FindingStatus,
    GasOptimization,
    Location,
    ScanResult,
    ScanStatus,
    ScanType,
    SecurityScore,
    Severity,
)


# ── Event Loop ───────────────────────────────────────────────────────────────


@pytest.fixture(scope="session")
def event_loop():
    """Create a session-scoped event loop for async tests."""
    loop = asyncio.new_event_loop()
    yield loop
    loop.close()


# ── Core Types Fixtures ──────────────────────────────────────────────────────


@pytest.fixture
def sample_location() -> Location:
    """Return a sample code location."""
    return Location(
        file_path="contracts/SoulZKSLock.sol",
        start_line=42,
        end_line=55,
        start_col=4,
        end_col=80,
        snippet="function verifyProof(bytes calldata proof) external {",
    )


@pytest.fixture
def sample_cvss() -> CVSSVector:
    """Return a sample CVSS vector."""
    return CVSSVector(
        vector_string="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        base_score=9.8,
        attack_vector="Network",
        attack_complexity="Low",
        privileges_required="None",
        user_interaction="None",
        scope="Unchanged",
        confidentiality="High",
        integrity="High",
        availability="High",
    )


@pytest.fixture
def sample_finding(sample_location: Location, sample_cvss: CVSSVector) -> FindingSchema:
    """Return a sample finding."""
    return FindingSchema(
        id=str(uuid.uuid4()),
        title="ZK Proof Replay Attack",
        description="ZK proofs can be replayed across chains without nonce binding.",
        severity=Severity.CRITICAL,
        status=FindingStatus.CONFIRMED,
        confidence=0.95,
        category="zk-vulnerability",
        cwe_id="CWE-294",
        scwe_id="SCWE-050",
        location=sample_location,
        cvss=sample_cvss,
        poc_script="forge test --match-test testZKReplay",
        remediation="Add chain-specific nonce to ZK proof inputs.",
        detected_at=datetime.now(timezone.utc),
    )


@pytest.fixture
def sample_findings(sample_finding: FindingSchema) -> list[FindingSchema]:
    """Return a list of sample findings with various severities."""
    findings = [sample_finding]

    # High severity
    findings.append(
        FindingSchema(
            id=str(uuid.uuid4()),
            title="PC³ Privacy Leak in Cross-Chain Message",
            description="Cross-chain messages expose sender identity via timing analysis.",
            severity=Severity.HIGH,
            status=FindingStatus.CONFIRMED,
            confidence=0.88,
            category="privacy",
            location=Location(
                file_path="contracts/SoulPC3.sol",
                start_line=100,
                end_line=120,
                snippet="function sendCrossChain(...) external {",
            ),
        )
    )

    # Medium severity
    findings.append(
        FindingSchema(
            id=str(uuid.uuid4()),
            title="Unbounded Gas in EASC Loop",
            description="EASC adaptive loop has no iteration cap, risking OOG.",
            severity=Severity.MEDIUM,
            status=FindingStatus.DETECTED,
            confidence=0.75,
            category="gas-efficiency",
            location=Location(
                file_path="contracts/SoulEASC.sol",
                start_line=200,
                end_line=215,
                snippet="while (adaptiveCondition()) {",
            ),
        )
    )

    # Low severity
    findings.append(
        FindingSchema(
            id=str(uuid.uuid4()),
            title="Missing Event Emission in PBP Update",
            description="PBP privacy budget updates do not emit events.",
            severity=Severity.LOW,
            status=FindingStatus.DETECTED,
            confidence=0.99,
            category="best-practice",
            location=Location(
                file_path="contracts/SoulPBP.sol",
                start_line=80,
                end_line=85,
                snippet="function updateBudget(uint256 newBudget) external {",
            ),
        )
    )

    # Informational
    findings.append(
        FindingSchema(
            id=str(uuid.uuid4()),
            title="Solidity Version Pragma Not Pinned",
            description="Pragma uses >=0.8.0 instead of a pinned version.",
            severity=Severity.INFORMATIONAL,
            status=FindingStatus.DETECTED,
            confidence=1.0,
            category="best-practice",
            location=Location(
                file_path="contracts/SoulCDNA.sol",
                start_line=1,
                end_line=1,
                snippet="pragma solidity >=0.8.0;",
            ),
        )
    )

    return findings


@pytest.fixture
def sample_gas_optimization(sample_location: Location) -> GasOptimization:
    """Return a sample gas optimization."""
    return GasOptimization(
        location=sample_location,
        description="Use calldata instead of memory for read-only struct.",
        suggestion="Change `memory` to `calldata` for proof parameter.",
        estimated_gas_saved=2100,
        category="calldata-optimization",
    )


@pytest.fixture
def sample_scan_result(
    sample_findings: list[FindingSchema],
    sample_gas_optimization: GasOptimization,
) -> ScanResult:
    """Return a sample scan result."""
    return ScanResult(
        scan_id=str(uuid.uuid4()),
        scan_type=ScanType.SMART_CONTRACT,
        status=ScanStatus.COMPLETED,
        findings=sample_findings,
        gas_optimizations=[sample_gas_optimization],
        security_score=47.0,
        threat_score=53.0,
        total_lines_scanned=1500,
        scan_duration_seconds=42.5,
    )


# ── Mock Solidity Source ─────────────────────────────────────────────────────


MOCK_ZK_SLOCK_SOURCE = """\
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/access/Ownable.sol";

contract SoulZKSLock is Ownable {
    mapping(bytes32 => bool) public usedProofs;
    mapping(address => uint256) public lockedBalances;

    event ProofVerified(bytes32 indexed proofHash, address indexed user);
    event FundsLocked(address indexed user, uint256 amount);

    function verifyProof(bytes calldata proof) external {
        bytes32 proofHash = keccak256(proof);
        require(!usedProofs[proofHash], "Proof already used");
        usedProofs[proofHash] = true;
        emit ProofVerified(proofHash, msg.sender);
    }

    function lockFunds() external payable {
        require(msg.value > 0, "Must send ETH");
        lockedBalances[msg.sender] += msg.value;
        emit FundsLocked(msg.sender, msg.value);
    }

    function withdraw(uint256 amount) external {
        require(lockedBalances[msg.sender] >= amount, "Insufficient balance");
        lockedBalances[msg.sender] -= amount;
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok, "Transfer failed");
    }
}
"""


MOCK_PC3_SOURCE = """\
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract SoulPC3 {
    struct CrossChainMessage {
        uint256 sourceChainId;
        uint256 destChainId;
        bytes32 commitment;
        bytes proof;
    }

    mapping(bytes32 => bool) public processedMessages;

    function sendCrossChain(CrossChainMessage calldata msg_) external {
        bytes32 msgHash = keccak256(abi.encode(msg_));
        require(!processedMessages[msgHash], "Already processed");
        processedMessages[msgHash] = true;
    }
}
"""


@pytest.fixture
def mock_solidity_source() -> str:
    """Return mock ZK-SLock Solidity source code."""
    return MOCK_ZK_SLOCK_SOURCE


@pytest.fixture
def mock_pc3_source() -> str:
    """Return mock PC3 Solidity source code."""
    return MOCK_PC3_SOURCE


# ── LLM Mock ────────────────────────────────────────────────────────────────


@pytest.fixture
def mock_llm_client():
    """Return a mock LLM client that returns predictable responses."""
    client = AsyncMock()
    client.analyze = AsyncMock(
        return_value={
            "findings": [
                {
                    "title": "Reentrancy in withdraw",
                    "severity": "high",
                    "description": "State updated after external call.",
                    "location": {"file": "SoulZKSLock.sol", "line": 30},
                    "remediation": "Use checks-effects-interactions pattern.",
                }
            ]
        }
    )
    client.analyze_batch = AsyncMock(return_value=[])
    return client


# ── Soul Protocol Model Mock ────────────────────────────────────────────────


@pytest.fixture
def mock_protocol_model():
    """Return a mock Soul protocol model."""
    model = MagicMock()
    model.contracts = {
        "ZKSLock": MagicMock(
            name="ZKSLock",
            category="zk-privacy",
            functions=["verifyProof", "lockFunds", "withdraw"],
            state_variables=["usedProofs", "lockedBalances"],
        ),
        "PC3": MagicMock(
            name="PC3",
            category="cross-chain",
            functions=["sendCrossChain"],
            state_variables=["processedMessages"],
        ),
    }
    model.invariants = [
        {"name": "proof_uniqueness", "contract": "ZKSLock", "property": "No proof reuse"},
        {"name": "balance_conservation", "contract": "ZKSLock", "property": "Sum invariant"},
    ]
    model.get_contract_names = MagicMock(return_value=["ZKSLock", "PC3"])
    model.get_invariants_for_contract = MagicMock(return_value=model.invariants[:1])
    return model


# ── Forge Executor Mock ──────────────────────────────────────────────────────


@pytest.fixture
def mock_forge_result():
    """Return a mock Forge execution result."""
    return {
        "success": True,
        "gas_used": 45_000,
        "traces": [
            {"op": "CALL", "from": "0xabc", "to": "0xdef", "value": 1000},
            {"op": "SSTORE", "slot": "0x1", "value": "0x2"},
        ],
        "logs": [
            {"event": "ProofVerified", "args": {"proofHash": "0x123", "user": "0xabc"}},
        ],
        "returndata": "0x",
        "reverted": False,
    }


# ── Campaign Config Mock ────────────────────────────────────────────────────


@pytest.fixture
def sample_campaign_config() -> dict[str, Any]:
    """Return a sample fuzzer campaign configuration."""
    return {
        "target_contracts": ["contracts/SoulZKSLock.sol"],
        "mode": "deep",
        "max_iterations": 10_000,
        "max_duration": 120,
        "enable_symbolic": True,
        "enable_concolic": True,
        "enable_differential": True,
        "enable_forge": True,
        "enable_llm": True,
        "enable_bytecode": True,
        "enable_taint": True,
        "enable_gas_profiling": True,
        "enable_invariant_synthesis": True,
        "enable_state_replay": True,
        "enable_exploit_composition": True,
        "parallel_workers": 2,
        "mutation_weights": {
            "bitflip": 1.0,
            "arithmetic": 1.0,
            "boundary": 1.5,
            "havoc": 0.8,
            "soul_zk_proof": 2.0,
            "soul_cross_chain": 2.0,
        },
    }
