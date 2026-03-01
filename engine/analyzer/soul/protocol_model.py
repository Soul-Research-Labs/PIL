"""Soul Protocol state model — comprehensive model of Soul's contract architecture.

Maps every core contract, key state variables, critical functions,
access control patterns, and inter-contract dependencies for
protocol-aware fuzzing and invariant verification.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


# ── Soul Protocol Contract Categories ────────────────────────────────────────


class SoulContractCategory(str, Enum):
    """Categories of Soul Protocol contracts."""

    CORE = "core"
    PRIMITIVES = "primitives"
    BRIDGE = "bridge"
    PRIVACY = "privacy"
    SECURITY = "security"
    CROSSCHAIN = "crosschain"
    COMPLIANCE = "compliance"
    GOVERNANCE = "governance"
    RELAYER = "relayer"
    VERIFIERS = "verifiers"
    LIBRARIES = "libraries"
    UPGRADEABLE = "upgradeable"


class SoulPrimitive(str, Enum):
    """Soul v2 cryptographic primitives."""

    ZK_SLOCK = "zk_bound_state_locks"
    PC3 = "proof_carrying_container"
    CDNA = "cross_domain_nullifier_algebra"
    EASC = "execution_agnostic_state_commitments"
    PBP = "policy_bound_proofs"


class SoulSecurityMechanism(str, Enum):
    """Security mechanisms in Soul Protocol."""

    CIRCUIT_BREAKER = "circuit_breaker"
    RATE_LIMITER = "rate_limiter"
    FLASH_LOAN_GUARD = "flash_loan_guard"
    MEV_PROTECTION = "mev_protection"
    EMERGENCY_RECOVERY = "emergency_recovery"
    KILL_SWITCH = "kill_switch"
    FRAUD_PROOF = "fraud_proof"
    WATCHTOWER = "watchtower"
    GRIEFING_PROTECTION = "griefing_protection"


# ── Soul Contract Definitions ────────────────────────────────────────────────


@dataclass
class SoulFunction:
    """A function within a Soul Protocol contract."""

    name: str
    visibility: str = "public"  # public, external, internal, private
    mutability: str = ""  # view, pure, payable, ""
    modifiers: list[str] = field(default_factory=list)
    parameters: list[dict[str, str]] = field(default_factory=list)
    returns: list[str] = field(default_factory=list)
    is_privileged: bool = False
    risk_level: str = "low"  # low, medium, high, critical
    state_writes: list[str] = field(default_factory=list)
    external_calls: list[str] = field(default_factory=list)
    events_emitted: list[str] = field(default_factory=list)


@dataclass
class SoulStateVariable:
    """A state variable in a Soul Protocol contract."""

    name: str
    type: str
    visibility: str = "private"
    is_immutable: bool = False
    is_constant: bool = False
    slot: int | None = None
    description: str = ""


@dataclass
class SoulInvariant:
    """A protocol invariant that must hold across all states."""

    id: str
    description: str
    category: str  # nullifier, state, proof, bridge, privacy, economic
    severity: str = "critical"
    contracts_involved: list[str] = field(default_factory=list)
    check_expression: str = ""  # Solidity-like expression
    fuzz_strategy: str = ""  # How to test this invariant


@dataclass
class SoulContractDef:
    """Definition of a Soul Protocol contract."""

    name: str
    category: SoulContractCategory
    file_path: str
    description: str = ""
    is_upgradeable: bool = False
    inherits: list[str] = field(default_factory=list)
    functions: list[SoulFunction] = field(default_factory=list)
    state_variables: list[SoulStateVariable] = field(default_factory=list)
    events: list[str] = field(default_factory=list)
    invariants: list[SoulInvariant] = field(default_factory=list)
    dependencies: list[str] = field(default_factory=list)  # Other Soul contracts
    security_mechanisms: list[SoulSecurityMechanism] = field(default_factory=list)


# ── Soul Protocol Model ─────────────────────────────────────────────────────


class SoulProtocolModel:
    """Complete model of the Soul Protocol architecture.

    Provides:
    - Contract definitions with functions, state, invariants
    - Inter-contract dependency graph
    - Attack surface mapping
    - Invariant catalog for fuzzing
    - Mutation strategy recommendations
    """

    def __init__(self) -> None:
        self.contracts: dict[str, SoulContractDef] = {}
        self.invariants: list[SoulInvariant] = []
        self._build_model()

    def _build_model(self) -> None:
        """Build the complete Soul Protocol model."""
        self._register_core_contracts()
        self._register_primitive_contracts()
        self._register_bridge_contracts()
        self._register_privacy_contracts()
        self._register_security_contracts()
        self._build_invariant_catalog()

    # ── Core contracts ───────────────────────────────────────────────

    def _register_core_contracts(self) -> None:
        """Register core Soul Protocol contracts."""

        # ConfidentialStateContainerV3
        self.contracts["ConfidentialStateContainerV3"] = SoulContractDef(
            name="ConfidentialStateContainerV3",
            category=SoulContractCategory.CORE,
            file_path="contracts/core/ConfidentialStateContainerV3.sol",
            description="Encrypted state container with ZK verification and nullifier protection",
            is_upgradeable=True,
            functions=[
                SoulFunction(
                    name="createContainer",
                    visibility="external",
                    mutability="payable",
                    parameters=[
                        {"name": "stateHash", "type": "bytes32"},
                        {"name": "encryptedData", "type": "bytes"},
                        {"name": "zkProof", "type": "bytes"},
                    ],
                    risk_level="critical",
                    state_writes=["containers", "containerCount"],
                    events_emitted=["ContainerCreated"],
                ),
                SoulFunction(
                    name="updateContainer",
                    visibility="external",
                    parameters=[
                        {"name": "containerId", "type": "uint256"},
                        {"name": "newStateHash", "type": "bytes32"},
                        {"name": "proof", "type": "bytes"},
                        {"name": "nullifier", "type": "bytes32"},
                    ],
                    risk_level="critical",
                    state_writes=["containers", "nullifiers"],
                    events_emitted=["ContainerUpdated"],
                ),
                SoulFunction(
                    name="verifyState",
                    visibility="external",
                    mutability="view",
                    parameters=[
                        {"name": "containerId", "type": "uint256"},
                        {"name": "proof", "type": "bytes"},
                    ],
                    risk_level="high",
                ),
                SoulFunction(
                    name="destroyContainer",
                    visibility="external",
                    parameters=[
                        {"name": "containerId", "type": "uint256"},
                        {"name": "nullifier", "type": "bytes32"},
                    ],
                    modifiers=["onlyOwnerOrAuthorized"],
                    is_privileged=True,
                    risk_level="critical",
                    state_writes=["containers"],
                    events_emitted=["ContainerDestroyed"],
                ),
            ],
            state_variables=[
                SoulStateVariable(name="containers", type="mapping(uint256 => Container)"),
                SoulStateVariable(name="containerCount", type="uint256"),
                SoulStateVariable(name="nullifiers", type="mapping(bytes32 => bool)"),
                SoulStateVariable(name="verifierRegistry", type="address"),
            ],
            events=["ContainerCreated", "ContainerUpdated", "ContainerDestroyed"],
            dependencies=["NullifierRegistryV3", "VerifierRegistryV2"],
            security_mechanisms=[
                SoulSecurityMechanism.CIRCUIT_BREAKER,
                SoulSecurityMechanism.RATE_LIMITER,
            ],
        )

        # NullifierRegistryV3
        self.contracts["NullifierRegistryV3"] = SoulContractDef(
            name="NullifierRegistryV3",
            category=SoulContractCategory.CORE,
            file_path="contracts/core/NullifierRegistryV3.sol",
            description="Nullifier registration with double-spend prevention and domain separation",
            is_upgradeable=True,
            functions=[
                SoulFunction(
                    name="registerNullifier",
                    visibility="external",
                    parameters=[
                        {"name": "nullifier", "type": "bytes32"},
                        {"name": "domain", "type": "uint256"},
                    ],
                    risk_level="critical",
                    state_writes=["nullifiers", "domainNullifiers"],
                    events_emitted=["NullifierRegistered"],
                ),
                SoulFunction(
                    name="isNullifierUsed",
                    visibility="external",
                    mutability="view",
                    parameters=[
                        {"name": "nullifier", "type": "bytes32"},
                    ],
                    risk_level="low",
                ),
                SoulFunction(
                    name="batchRegister",
                    visibility="external",
                    parameters=[
                        {"name": "nullifiers", "type": "bytes32[]"},
                        {"name": "domain", "type": "uint256"},
                    ],
                    risk_level="critical",
                    state_writes=["nullifiers"],
                    events_emitted=["NullifierBatchRegistered"],
                ),
                SoulFunction(
                    name="getDomainNullifierCount",
                    visibility="external",
                    mutability="view",
                    parameters=[{"name": "domain", "type": "uint256"}],
                    risk_level="low",
                ),
            ],
            state_variables=[
                SoulStateVariable(name="nullifiers", type="mapping(bytes32 => bool)"),
                SoulStateVariable(name="domainNullifiers", type="mapping(uint256 => mapping(bytes32 => bool))"),
                SoulStateVariable(name="nullifierCount", type="uint256"),
                SoulStateVariable(name="authorizedCallers", type="mapping(address => bool)"),
            ],
            events=["NullifierRegistered", "NullifierBatchRegistered"],
            security_mechanisms=[SoulSecurityMechanism.RATE_LIMITER],
        )

        # PrivacyRouter
        self.contracts["PrivacyRouter"] = SoulContractDef(
            name="PrivacyRouter",
            category=SoulContractCategory.CORE,
            file_path="contracts/core/PrivacyRouter.sol",
            description="Unified facade for deposit, withdraw, cross-chain, and stealth operations",
            functions=[
                SoulFunction(
                    name="deposit",
                    visibility="external",
                    mutability="payable",
                    parameters=[
                        {"name": "commitment", "type": "bytes32"},
                        {"name": "assetType", "type": "uint8"},
                    ],
                    risk_level="critical",
                    state_writes=["deposits"],
                    events_emitted=["Deposit"],
                    external_calls=["ShieldedPool.deposit"],
                ),
                SoulFunction(
                    name="withdraw",
                    visibility="external",
                    parameters=[
                        {"name": "nullifierHash", "type": "bytes32"},
                        {"name": "recipient", "type": "address"},
                        {"name": "root", "type": "bytes32"},
                        {"name": "proof", "type": "bytes"},
                    ],
                    risk_level="critical",
                    state_writes=["withdrawals"],
                    events_emitted=["Withdrawal"],
                    external_calls=["ShieldedPool.withdraw", "NullifierRegistry.registerNullifier"],
                ),
                SoulFunction(
                    name="crossChainTransfer",
                    visibility="external",
                    mutability="payable",
                    parameters=[
                        {"name": "destChainId", "type": "uint256"},
                        {"name": "stateHash", "type": "bytes32"},
                        {"name": "proof", "type": "bytes"},
                    ],
                    risk_level="critical",
                    external_calls=["ZKBoundStateLocks.createStateLock", "CrossChainProofHub.submitProof"],
                ),
                SoulFunction(
                    name="stealthSend",
                    visibility="external",
                    mutability="payable",
                    parameters=[
                        {"name": "stealthAddress", "type": "address"},
                        {"name": "amount", "type": "uint256"},
                        {"name": "ephemeralPubKey", "type": "bytes32"},
                    ],
                    risk_level="high",
                    external_calls=["StealthAddressRegistry.announce"],
                ),
            ],
            dependencies=[
                "UniversalShieldedPool",
                "NullifierRegistryV3",
                "ZKBoundStateLocks",
                "CrossChainProofHubV3",
                "StealthAddressRegistry",
            ],
            security_mechanisms=[
                SoulSecurityMechanism.CIRCUIT_BREAKER,
                SoulSecurityMechanism.RATE_LIMITER,
                SoulSecurityMechanism.FLASH_LOAN_GUARD,
                SoulSecurityMechanism.MEV_PROTECTION,
            ],
        )

        # SoulProtocolHub
        self.contracts["SoulProtocolHub"] = SoulContractDef(
            name="SoulProtocolHub",
            category=SoulContractCategory.CORE,
            file_path="contracts/core/SoulProtocolHub.sol",
            description="Central coordination hub connecting all Soul Protocol modules",
            functions=[
                SoulFunction(
                    name="registerModule",
                    visibility="external",
                    modifiers=["onlyAdmin"],
                    is_privileged=True,
                    parameters=[
                        {"name": "moduleId", "type": "bytes32"},
                        {"name": "moduleAddress", "type": "address"},
                    ],
                    risk_level="critical",
                    state_writes=["modules"],
                ),
                SoulFunction(
                    name="executeOperation",
                    visibility="external",
                    parameters=[
                        {"name": "moduleId", "type": "bytes32"},
                        {"name": "data", "type": "bytes"},
                    ],
                    risk_level="high",
                    external_calls=["target.call"],
                ),
                SoulFunction(
                    name="getModule",
                    visibility="external",
                    mutability="view",
                    parameters=[{"name": "moduleId", "type": "bytes32"}],
                    risk_level="low",
                ),
            ],
            security_mechanisms=[
                SoulSecurityMechanism.EMERGENCY_RECOVERY,
                SoulSecurityMechanism.KILL_SWITCH,
            ],
        )

    # ── Primitive contracts ──────────────────────────────────────────

    def _register_primitive_contracts(self) -> None:
        """Register Soul v2 primitive contracts."""

        # ZKBoundStateLocks
        self.contracts["ZKBoundStateLocks"] = SoulContractDef(
            name="ZKBoundStateLocks",
            category=SoulContractCategory.PRIMITIVES,
            file_path="contracts/primitives/ZKBoundStateLocks.sol",
            description="Cross-chain state locks unlocked only by ZK proofs; flagship primitive",
            functions=[
                SoulFunction(
                    name="createStateLock",
                    visibility="external",
                    mutability="payable",
                    parameters=[
                        {"name": "stateHash", "type": "bytes32"},
                        {"name": "zkRequirements", "type": "bytes32"},
                        {"name": "destChainId", "type": "uint256"},
                    ],
                    risk_level="critical",
                    state_writes=["locks", "lockCount"],
                    events_emitted=["StateLockCreated"],
                ),
                SoulFunction(
                    name="unlockWithProof",
                    visibility="external",
                    parameters=[
                        {"name": "lockId", "type": "uint256"},
                        {"name": "proof", "type": "bytes"},
                        {"name": "nullifier", "type": "bytes32"},
                    ],
                    risk_level="critical",
                    state_writes=["locks", "nullifiers"],
                    events_emitted=["StateLockUnlocked"],
                    external_calls=["verifier.verifyProof", "NullifierRegistry.registerNullifier"],
                ),
                SoulFunction(
                    name="cancelLock",
                    visibility="external",
                    modifiers=["onlyLockOwner"],
                    parameters=[{"name": "lockId", "type": "uint256"}],
                    risk_level="high",
                    state_writes=["locks"],
                    events_emitted=["StateLockCancelled"],
                ),
                SoulFunction(
                    name="getLockDetails",
                    visibility="external",
                    mutability="view",
                    parameters=[{"name": "lockId", "type": "uint256"}],
                    risk_level="low",
                ),
            ],
            state_variables=[
                SoulStateVariable(name="locks", type="mapping(uint256 => StateLock)"),
                SoulStateVariable(name="lockCount", type="uint256"),
                SoulStateVariable(name="nullifiers", type="mapping(bytes32 => bool)"),
            ],
            dependencies=["NullifierRegistryV3", "VerifierRegistryV2"],
            security_mechanisms=[
                SoulSecurityMechanism.CIRCUIT_BREAKER,
                SoulSecurityMechanism.FLASH_LOAN_GUARD,
            ],
        )

        # ProofCarryingContainer (PC³)
        self.contracts["ProofCarryingContainer"] = SoulContractDef(
            name="ProofCarryingContainer",
            category=SoulContractCategory.PRIMITIVES,
            file_path="contracts/primitives/ProofCarryingContainer.sol",
            description="Self-authenticating containers with embedded ZK proofs (PC³)",
            functions=[
                SoulFunction(
                    name="createContainer",
                    visibility="external",
                    parameters=[
                        {"name": "data", "type": "bytes"},
                        {"name": "proof", "type": "bytes"},
                        {"name": "verifierCircuit", "type": "bytes32"},
                    ],
                    risk_level="critical",
                    state_writes=["containers"],
                ),
                SoulFunction(
                    name="verifyContainer",
                    visibility="external",
                    mutability="view",
                    parameters=[{"name": "containerId", "type": "uint256"}],
                    risk_level="high",
                ),
                SoulFunction(
                    name="transferContainer",
                    visibility="external",
                    parameters=[
                        {"name": "containerId", "type": "uint256"},
                        {"name": "destChainId", "type": "uint256"},
                    ],
                    risk_level="critical",
                    external_calls=["CrossChainProofHub.relayProof"],
                ),
            ],
            dependencies=["VerifierRegistryV2", "CrossChainProofHubV3"],
        )

        # CrossDomainNullifierAlgebra (CDNA)
        self.contracts["CrossDomainNullifierAlgebra"] = SoulContractDef(
            name="CrossDomainNullifierAlgebra",
            category=SoulContractCategory.PRIMITIVES,
            file_path="contracts/primitives/CrossDomainNullifierAlgebra.sol",
            description="Domain-separated nullifiers — same secret yields different nullifier per chain",
            functions=[
                SoulFunction(
                    name="computeNullifier",
                    visibility="external",
                    mutability="view",
                    parameters=[
                        {"name": "secret", "type": "bytes32"},
                        {"name": "domain", "type": "uint256"},
                    ],
                    risk_level="high",
                ),
                SoulFunction(
                    name="verifyDomainSeparation",
                    visibility="external",
                    mutability="view",
                    parameters=[
                        {"name": "nullifierA", "type": "bytes32"},
                        {"name": "nullifierB", "type": "bytes32"},
                        {"name": "domainA", "type": "uint256"},
                        {"name": "domainB", "type": "uint256"},
                    ],
                    risk_level="critical",
                ),
                SoulFunction(
                    name="registerCrossDomainNullifier",
                    visibility="external",
                    parameters=[
                        {"name": "nullifier", "type": "bytes32"},
                        {"name": "domain", "type": "uint256"},
                        {"name": "proof", "type": "bytes"},
                    ],
                    risk_level="critical",
                    state_writes=["domainNullifiers"],
                ),
            ],
            dependencies=["NullifierRegistryV3"],
        )

        # ExecutionAgnosticStateCommitments (EASC)
        self.contracts["ExecutionAgnosticStateCommitments"] = SoulContractDef(
            name="ExecutionAgnosticStateCommitments",
            category=SoulContractCategory.PRIMITIVES,
            file_path="contracts/primitives/ExecutionAgnosticStateCommitments.sol",
            description="Backend-independent state commitments for multi-proof-system verification",
            functions=[
                SoulFunction(
                    name="createCommitment",
                    visibility="external",
                    parameters=[
                        {"name": "stateData", "type": "bytes"},
                        {"name": "proofBackend", "type": "uint8"},
                    ],
                    risk_level="critical",
                    state_writes=["commitments"],
                ),
                SoulFunction(
                    name="verifyCommitment",
                    visibility="external",
                    mutability="view",
                    parameters=[
                        {"name": "commitmentId", "type": "uint256"},
                        {"name": "proof", "type": "bytes"},
                        {"name": "proofBackend", "type": "uint8"},
                    ],
                    risk_level="critical",
                ),
                SoulFunction(
                    name="translateCommitment",
                    visibility="external",
                    parameters=[
                        {"name": "commitmentId", "type": "uint256"},
                        {"name": "targetBackend", "type": "uint8"},
                        {"name": "translationProof", "type": "bytes"},
                    ],
                    risk_level="critical",
                    external_calls=["UniversalProofTranslator.translate"],
                ),
            ],
            dependencies=["VerifierRegistryV2"],
        )

        # PolicyBoundProofs (PBP)
        self.contracts["PolicyBoundProofs"] = SoulContractDef(
            name="PolicyBoundProofs",
            category=SoulContractCategory.PRIMITIVES,
            file_path="contracts/primitives/PolicyBoundProofs.sol",
            description="ZK proofs cryptographically bound to disclosure policies",
            functions=[
                SoulFunction(
                    name="createPolicyProof",
                    visibility="external",
                    parameters=[
                        {"name": "policyId", "type": "bytes32"},
                        {"name": "proof", "type": "bytes"},
                        {"name": "disclosureLevel", "type": "uint8"},
                    ],
                    risk_level="high",
                    state_writes=["policyProofs"],
                ),
                SoulFunction(
                    name="verifyCompliance",
                    visibility="external",
                    mutability="view",
                    parameters=[
                        {"name": "proofId", "type": "uint256"},
                        {"name": "policyId", "type": "bytes32"},
                    ],
                    risk_level="high",
                ),
            ],
            dependencies=["CrossChainSanctionsOracle"],
        )

    # ── Bridge contracts ─────────────────────────────────────────────

    def _register_bridge_contracts(self) -> None:
        """Register bridge and cross-chain contracts."""

        self.contracts["CrossChainProofHubV3"] = SoulContractDef(
            name="CrossChainProofHubV3",
            category=SoulContractCategory.BRIDGE,
            file_path="contracts/bridge/CrossChainProofHubV3.sol",
            description="Proof aggregation and relay with gas-optimized batching",
            functions=[
                SoulFunction(
                    name="submitProof",
                    visibility="external",
                    parameters=[
                        {"name": "sourceChain", "type": "uint256"},
                        {"name": "proof", "type": "bytes"},
                        {"name": "publicInputs", "type": "bytes32[]"},
                    ],
                    risk_level="critical",
                    state_writes=["proofs", "proofQueue"],
                    events_emitted=["ProofSubmitted"],
                ),
                SoulFunction(
                    name="aggregateAndRelay",
                    visibility="external",
                    parameters=[
                        {"name": "proofIds", "type": "uint256[]"},
                        {"name": "destChainId", "type": "uint256"},
                    ],
                    risk_level="critical",
                    state_writes=["relayedBatches"],
                    external_calls=["bridgeAdapter.sendMessage"],
                ),
                SoulFunction(
                    name="verifyBatchProof",
                    visibility="external",
                    mutability="view",
                    parameters=[
                        {"name": "batchId", "type": "uint256"},
                        {"name": "proof", "type": "bytes"},
                    ],
                    risk_level="critical",
                ),
            ],
            dependencies=["VerifierRegistryV2"],
            security_mechanisms=[
                SoulSecurityMechanism.CIRCUIT_BREAKER,
                SoulSecurityMechanism.RATE_LIMITER,
                SoulSecurityMechanism.WATCHTOWER,
            ],
        )

        self.contracts["SoulAtomicSwapV2"] = SoulContractDef(
            name="SoulAtomicSwapV2",
            category=SoulContractCategory.BRIDGE,
            file_path="contracts/bridge/SoulAtomicSwapV2.sol",
            description="HTLC atomic swaps with stealth address support",
            functions=[
                SoulFunction(
                    name="initiateSwap",
                    visibility="external",
                    mutability="payable",
                    parameters=[
                        {"name": "hashlock", "type": "bytes32"},
                        {"name": "timelock", "type": "uint256"},
                        {"name": "recipient", "type": "address"},
                    ],
                    risk_level="critical",
                    state_writes=["swaps"],
                    events_emitted=["SwapInitiated"],
                ),
                SoulFunction(
                    name="completeSwap",
                    visibility="external",
                    parameters=[
                        {"name": "swapId", "type": "bytes32"},
                        {"name": "preimage", "type": "bytes32"},
                    ],
                    risk_level="critical",
                    state_writes=["swaps"],
                    events_emitted=["SwapCompleted"],
                ),
                SoulFunction(
                    name="refundSwap",
                    visibility="external",
                    parameters=[{"name": "swapId", "type": "bytes32"}],
                    risk_level="high",
                    state_writes=["swaps"],
                    events_emitted=["SwapRefunded"],
                ),
            ],
            security_mechanisms=[SoulSecurityMechanism.FLASH_LOAN_GUARD],
        )

    # ── Privacy contracts ────────────────────────────────────────────

    def _register_privacy_contracts(self) -> None:
        """Register privacy middleware contracts."""

        self.contracts["UniversalShieldedPool"] = SoulContractDef(
            name="UniversalShieldedPool",
            category=SoulContractCategory.PRIVACY,
            file_path="contracts/privacy/UniversalShieldedPool.sol",
            description="Multi-asset shielded pool with Poseidon Merkle tree (depth-32)",
            functions=[
                SoulFunction(
                    name="deposit",
                    visibility="external",
                    mutability="payable",
                    parameters=[
                        {"name": "commitment", "type": "bytes32"},
                    ],
                    risk_level="critical",
                    state_writes=["commitments", "merkleTree", "nextIndex"],
                    events_emitted=["Deposit"],
                ),
                SoulFunction(
                    name="withdraw",
                    visibility="external",
                    parameters=[
                        {"name": "proof", "type": "bytes"},
                        {"name": "root", "type": "bytes32"},
                        {"name": "nullifierHash", "type": "bytes32"},
                        {"name": "recipient", "type": "address"},
                        {"name": "relayer", "type": "address"},
                        {"name": "fee", "type": "uint256"},
                    ],
                    risk_level="critical",
                    state_writes=["nullifiers"],
                    events_emitted=["Withdrawal"],
                    external_calls=["recipient.transfer", "NullifierRegistry.registerNullifier"],
                ),
                SoulFunction(
                    name="isKnownRoot",
                    visibility="external",
                    mutability="view",
                    parameters=[{"name": "root", "type": "bytes32"}],
                    risk_level="low",
                ),
                SoulFunction(
                    name="getLastRoot",
                    visibility="external",
                    mutability="view",
                    risk_level="low",
                ),
            ],
            state_variables=[
                SoulStateVariable(name="commitments", type="mapping(bytes32 => bool)"),
                SoulStateVariable(name="merkleTree", type="bytes32[TREE_SIZE]"),
                SoulStateVariable(name="nextIndex", type="uint256"),
                SoulStateVariable(name="roots", type="mapping(bytes32 => bool)"),
                SoulStateVariable(name="nullifiers", type="mapping(bytes32 => bool)"),
                SoulStateVariable(name="TREE_DEPTH", type="uint256", is_constant=True),
            ],
            dependencies=["NullifierRegistryV3", "VerifierRegistryV2"],
            security_mechanisms=[
                SoulSecurityMechanism.CIRCUIT_BREAKER,
                SoulSecurityMechanism.FLASH_LOAN_GUARD,
                SoulSecurityMechanism.RATE_LIMITER,
            ],
        )

        self.contracts["StealthAddressRegistry"] = SoulContractDef(
            name="StealthAddressRegistry",
            category=SoulContractCategory.PRIVACY,
            file_path="contracts/privacy/StealthAddressRegistry.sol",
            description="Unlinkable receiving addresses for enhanced privacy",
            functions=[
                SoulFunction(
                    name="registerStealthMeta",
                    visibility="external",
                    parameters=[
                        {"name": "spendingPubKey", "type": "bytes"},
                        {"name": "viewingPubKey", "type": "bytes"},
                    ],
                    risk_level="medium",
                    state_writes=["stealthMeta"],
                ),
                SoulFunction(
                    name="announce",
                    visibility="external",
                    parameters=[
                        {"name": "stealthAddress", "type": "address"},
                        {"name": "ephemeralPubKey", "type": "bytes32"},
                        {"name": "metadata", "type": "bytes"},
                    ],
                    risk_level="low",
                    events_emitted=["Announcement"],
                ),
            ],
        )

    # ── Security contracts ───────────────────────────────────────────

    def _register_security_contracts(self) -> None:
        """Register security module contracts."""

        self.contracts["FlashLoanGuard"] = SoulContractDef(
            name="FlashLoanGuard",
            category=SoulContractCategory.SECURITY,
            file_path="contracts/security/FlashLoanGuard.sol",
            description="Flash loan attack prevention for deposit/withdraw operations",
            functions=[
                SoulFunction(
                    name="checkFlashLoan",
                    visibility="external",
                    mutability="view",
                    parameters=[{"name": "sender", "type": "address"}],
                    risk_level="high",
                ),
            ],
        )

        self.contracts["MEVProtection"] = SoulContractDef(
            name="MEVProtection",
            category=SoulContractCategory.SECURITY,
            file_path="contracts/security/MEVProtection.sol",
            description="Commit-reveal scheme for MEV resistance in privacy operations",
            functions=[
                SoulFunction(
                    name="commit",
                    visibility="external",
                    parameters=[{"name": "commitHash", "type": "bytes32"}],
                    risk_level="medium",
                    state_writes=["commits"],
                ),
                SoulFunction(
                    name="reveal",
                    visibility="external",
                    parameters=[
                        {"name": "data", "type": "bytes"},
                        {"name": "salt", "type": "bytes32"},
                    ],
                    risk_level="medium",
                    state_writes=["commits"],
                ),
            ],
        )

        self.contracts["BridgeCircuitBreaker"] = SoulContractDef(
            name="BridgeCircuitBreaker",
            category=SoulContractCategory.SECURITY,
            file_path="contracts/security/RelayCircuitBreaker.sol",
            description="Anomaly detection and auto-pause for bridge operations",
            functions=[
                SoulFunction(
                    name="checkAndTrip",
                    visibility="external",
                    parameters=[
                        {"name": "volume", "type": "uint256"},
                        {"name": "operationType", "type": "uint8"},
                    ],
                    risk_level="critical",
                    state_writes=["circuitState"],
                ),
                SoulFunction(
                    name="reset",
                    visibility="external",
                    modifiers=["onlyAdmin"],
                    is_privileged=True,
                    risk_level="critical",
                    state_writes=["circuitState"],
                ),
            ],
        )

        self.contracts["EmergencyRecovery"] = SoulContractDef(
            name="EmergencyRecovery",
            category=SoulContractCategory.SECURITY,
            file_path="contracts/security/EmergencyRecovery.sol",
            description="Emergency pause and recovery mechanisms",
            functions=[
                SoulFunction(
                    name="pause",
                    visibility="external",
                    modifiers=["onlyGuardian"],
                    is_privileged=True,
                    risk_level="critical",
                ),
                SoulFunction(
                    name="unpause",
                    visibility="external",
                    modifiers=["onlyAdmin"],
                    is_privileged=True,
                    risk_level="critical",
                ),
                SoulFunction(
                    name="emergencyWithdraw",
                    visibility="external",
                    modifiers=["onlyGuardian", "whenPaused"],
                    is_privileged=True,
                    risk_level="critical",
                    state_writes=["emergencyFunds"],
                ),
            ],
        )

    # ── Invariant catalog ────────────────────────────────────────────

    def _build_invariant_catalog(self) -> None:
        """Build the complete invariant catalog for Soul Protocol.

        These invariants are the primary targets for mutation-feedback
        fuzzing. Each invariant defines:
          - What must always hold
          - Which contracts are involved
          - How to test it (fuzz strategy)
        """

        self.invariants = [
            # ── Nullifier invariants ───────────────────────────────
            SoulInvariant(
                id="SOUL-INV-001",
                description="No nullifier can be registered twice (double-spend prevention)",
                category="nullifier",
                severity="critical",
                contracts_involved=["NullifierRegistryV3", "UniversalShieldedPool"],
                check_expression="!nullifiers[nullifier] before register; nullifiers[nullifier] after",
                fuzz_strategy="replay_nullifier",
            ),
            SoulInvariant(
                id="SOUL-INV-002",
                description="Domain-separated nullifiers must be unique per domain",
                category="nullifier",
                severity="critical",
                contracts_involved=["CrossDomainNullifierAlgebra", "NullifierRegistryV3"],
                check_expression="computeNullifier(secret, domainA) != computeNullifier(secret, domainB)",
                fuzz_strategy="cross_domain_nullifier_collision",
            ),
            SoulInvariant(
                id="SOUL-INV-003",
                description="Batch nullifier registration must be atomic (all-or-nothing)",
                category="nullifier",
                severity="high",
                contracts_involved=["NullifierRegistryV3"],
                check_expression="batchRegister reverts if any nullifier already used",
                fuzz_strategy="partial_batch_replay",
            ),

            # ── State lock invariants ──────────────────────────────
            SoulInvariant(
                id="SOUL-INV-010",
                description="A locked state cannot be modified without valid ZK proof",
                category="state",
                severity="critical",
                contracts_involved=["ZKBoundStateLocks"],
                check_expression="unlockWithProof requires verifier.verifyProof(proof) == true",
                fuzz_strategy="corrupt_proof_unlock",
            ),
            SoulInvariant(
                id="SOUL-INV-011",
                description="State lock can only be unlocked once (no double-unlock)",
                category="state",
                severity="critical",
                contracts_involved=["ZKBoundStateLocks", "NullifierRegistryV3"],
                check_expression="unlockWithProof registers nullifier; second call reverts",
                fuzz_strategy="double_unlock",
            ),
            SoulInvariant(
                id="SOUL-INV-012",
                description="Only lock owner can cancel a state lock",
                category="state",
                severity="high",
                contracts_involved=["ZKBoundStateLocks"],
                check_expression="cancelLock reverts if msg.sender != lock.owner",
                fuzz_strategy="unauthorized_cancel",
            ),
            SoulInvariant(
                id="SOUL-INV-013",
                description="Locked state hash must be preserved until unlock/cancel",
                category="state",
                severity="critical",
                contracts_involved=["ZKBoundStateLocks"],
                check_expression="lock.stateHash before == lock.stateHash after (until unlock)",
                fuzz_strategy="state_manipulation_between_lock_unlock",
            ),

            # ── Proof verification invariants ────────────────────
            SoulInvariant(
                id="SOUL-INV-020",
                description="Invalid ZK proofs must always be rejected",
                category="proof",
                severity="critical",
                contracts_involved=["VerifierRegistryV2", "ZKBoundStateLocks", "UniversalShieldedPool"],
                check_expression="verifyProof(invalid_proof) == false",
                fuzz_strategy="corrupt_proof_bytes",
            ),
            SoulInvariant(
                id="SOUL-INV-021",
                description="Proof verification must be deterministic (same input = same result)",
                category="proof",
                severity="critical",
                contracts_involved=["VerifierRegistryV2"],
                check_expression="verifyProof(p, inputs) result is idempotent",
                fuzz_strategy="proof_verification_consistency",
            ),
            SoulInvariant(
                id="SOUL-INV-022",
                description="Proof translation between backends must preserve validity",
                category="proof",
                severity="critical",
                contracts_involved=["ExecutionAgnosticStateCommitments"],
                check_expression="translateCommitment preserves verification outcome",
                fuzz_strategy="backend_translation_integrity",
            ),

            # ── Shielded pool invariants ─────────────────────────
            SoulInvariant(
                id="SOUL-INV-030",
                description="Shielded pool balance must equal sum of deposits minus withdrawals",
                category="economic",
                severity="critical",
                contracts_involved=["UniversalShieldedPool"],
                check_expression="pool.balance == sum(deposits) - sum(withdrawals)",
                fuzz_strategy="deposit_withdraw_balance",
            ),
            SoulInvariant(
                id="SOUL-INV-031",
                description="Merkle tree root must be updated after every deposit",
                category="state",
                severity="critical",
                contracts_involved=["UniversalShieldedPool"],
                check_expression="root_after != root_before after deposit",
                fuzz_strategy="merkle_root_consistency",
            ),
            SoulInvariant(
                id="SOUL-INV-032",
                description="Withdrawal must use a valid Merkle root (current or recent)",
                category="state",
                severity="critical",
                contracts_involved=["UniversalShieldedPool"],
                check_expression="isKnownRoot(root) == true for valid withdrawal",
                fuzz_strategy="stale_root_withdrawal",
            ),
            SoulInvariant(
                id="SOUL-INV-033",
                description="Cannot withdraw more than deposited (no value creation)",
                category="economic",
                severity="critical",
                contracts_involved=["UniversalShieldedPool"],
                check_expression="total_withdrawn <= total_deposited",
                fuzz_strategy="inflation_attack",
            ),

            # ── Bridge invariants ────────────────────────────────
            SoulInvariant(
                id="SOUL-INV-040",
                description="Cross-chain proof relay must not duplicate proofs",
                category="bridge",
                severity="critical",
                contracts_involved=["CrossChainProofHubV3"],
                check_expression="submitProof with same hash reverts",
                fuzz_strategy="duplicate_proof_relay",
            ),
            SoulInvariant(
                id="SOUL-INV-041",
                description="Atomic swap must complete or refund — never lose funds",
                category="bridge",
                severity="critical",
                contracts_involved=["SoulAtomicSwapV2"],
                check_expression="swap.state == COMPLETED || swap.state == REFUNDED",
                fuzz_strategy="swap_fund_loss",
            ),
            SoulInvariant(
                id="SOUL-INV-042",
                description="Bridge circuit breaker must activate on anomalous volume",
                category="bridge",
                severity="high",
                contracts_involved=["BridgeCircuitBreaker", "CrossChainProofHubV3"],
                check_expression="checkAndTrip triggers pause when volume > threshold",
                fuzz_strategy="circuit_breaker_bypass",
            ),

            # ── Privacy invariants ───────────────────────────────
            SoulInvariant(
                id="SOUL-INV-050",
                description="Stealth address announcements must not leak receiver identity",
                category="privacy",
                severity="critical",
                contracts_involved=["StealthAddressRegistry"],
                check_expression="announcement does not contain plaintext recipient",
                fuzz_strategy="stealth_identity_leak",
            ),
            SoulInvariant(
                id="SOUL-INV-051",
                description="Encrypted state must not be readable without valid view key",
                category="privacy",
                severity="critical",
                contracts_involved=["ConfidentialStateContainerV3"],
                check_expression="container.encryptedData is AES-256-GCM encrypted",
                fuzz_strategy="plaintext_state_exposure",
            ),

            # ── Access control invariants ────────────────────────
            SoulInvariant(
                id="SOUL-INV-060",
                description="Privileged functions must enforce access control",
                category="access_control",
                severity="critical",
                contracts_involved=["SoulProtocolHub", "EmergencyRecovery", "BridgeCircuitBreaker"],
                check_expression="onlyAdmin/onlyGuardian modifier enforced",
                fuzz_strategy="unauthorized_privilege_escalation",
            ),
            SoulInvariant(
                id="SOUL-INV-061",
                description="Emergency recovery must require multi-sig or timelock",
                category="access_control",
                severity="critical",
                contracts_involved=["EmergencyRecovery", "SoulUpgradeTimelock"],
                check_expression="emergencyWithdraw requires guardian + timelock",
                fuzz_strategy="emergency_bypass",
            ),

            # ── Rate limiting invariants ─────────────────────────
            SoulInvariant(
                id="SOUL-INV-070",
                description="Rate limiter must prevent excessive operations per window",
                category="rate_limiting",
                severity="high",
                contracts_involved=["BridgeCircuitBreaker"],
                check_expression="operations_in_window <= max_allowed",
                fuzz_strategy="rate_limit_bypass",
            ),

            # ── Flash loan invariants ────────────────────────────
            SoulInvariant(
                id="SOUL-INV-080",
                description="Flash loan guard must prevent same-block deposit+withdraw",
                category="flash_loan",
                severity="critical",
                contracts_involved=["FlashLoanGuard", "UniversalShieldedPool"],
                check_expression="withdraw reverts if deposit in same block",
                fuzz_strategy="flash_loan_deposit_withdraw",
            ),

            # ── Upgrade safety invariants ────────────────────────
            SoulInvariant(
                id="SOUL-INV-090",
                description="UUPS upgrades must preserve storage layout",
                category="upgrade",
                severity="critical",
                contracts_involved=["ConfidentialStateContainerV3", "NullifierRegistryV3"],
                check_expression="storage slots preserved across upgrade",
                fuzz_strategy="storage_collision_after_upgrade",
            ),
        ]

        # Attach invariants to contracts
        for inv in self.invariants:
            for contract_name in inv.contracts_involved:
                if contract_name in self.contracts:
                    self.contracts[contract_name].invariants.append(inv)

    # ── Query methods ────────────────────────────────────────────────

    def get_contract(self, name: str) -> SoulContractDef | None:
        """Get a contract definition by name."""
        return self.contracts.get(name)

    def get_contracts_by_category(
        self, category: SoulContractCategory
    ) -> list[SoulContractDef]:
        """Get all contracts in a category."""
        return [c for c in self.contracts.values() if c.category == category]

    def get_critical_functions(self) -> list[tuple[str, SoulFunction]]:
        """Get all critical-risk functions across the protocol."""
        result = []
        for contract in self.contracts.values():
            for func in contract.functions:
                if func.risk_level == "critical":
                    result.append((contract.name, func))
        return result

    def get_invariants_for_contract(self, name: str) -> list[SoulInvariant]:
        """Get all invariants relevant to a specific contract."""
        return [
            inv for inv in self.invariants
            if name in inv.contracts_involved
        ]

    def get_attack_surface(self) -> dict[str, Any]:
        """Get the complete attack surface of the protocol."""
        external_functions = []
        privileged_functions = []
        state_modifying = []

        for contract in self.contracts.values():
            for func in contract.functions:
                entry = {
                    "contract": contract.name,
                    "function": func.name,
                    "visibility": func.visibility,
                    "modifiers": func.modifiers,
                    "risk_level": func.risk_level,
                    "state_writes": func.state_writes,
                    "external_calls": func.external_calls,
                }
                if func.visibility in ("external", "public"):
                    external_functions.append(entry)
                if func.is_privileged:
                    privileged_functions.append(entry)
                if func.state_writes:
                    state_modifying.append(entry)

        return {
            "total_contracts": len(self.contracts),
            "total_external_functions": len(external_functions),
            "total_privileged_functions": len(privileged_functions),
            "total_state_modifying": len(state_modifying),
            "total_invariants": len(self.invariants),
            "external_functions": external_functions,
            "privileged_functions": privileged_functions,
            "state_modifying_functions": state_modifying,
            "critical_invariants": [
                {"id": inv.id, "description": inv.description, "category": inv.category}
                for inv in self.invariants if inv.severity == "critical"
            ],
        }

    def get_dependency_graph(self) -> dict[str, list[str]]:
        """Get the inter-contract dependency graph."""
        return {
            name: contract.dependencies
            for name, contract in self.contracts.items()
            if contract.dependencies
        }

    def identify_contract_category(self, source_code: str) -> list[str]:
        """Identify which Soul Protocol contracts are present in source code.

        Uses pattern matching to detect Soul-specific contract names,
        function signatures, and architectural patterns.
        """
        matches = []

        # Contract name patterns
        contract_patterns = {
            "ConfidentialStateContainer": [
                r"ConfidentialState", r"encryptedData", r"containerCount",
                r"createContainer.*stateHash.*encryptedData",
            ],
            "NullifierRegistry": [
                r"NullifierRegistry", r"registerNullifier", r"isNullifierUsed",
                r"domainNullifiers",
            ],
            "PrivacyRouter": [
                r"PrivacyRouter", r"crossChainTransfer.*destChainId",
                r"stealthSend.*ephemeralPubKey",
            ],
            "ZKBoundStateLocks": [
                r"ZKBoundStateLock", r"createStateLock", r"unlockWithProof",
                r"zkRequirements",
            ],
            "ProofCarryingContainer": [
                r"ProofCarryingContainer", r"verifierCircuit",
                r"transferContainer.*destChainId",
            ],
            "CrossDomainNullifierAlgebra": [
                r"CrossDomainNullifier", r"computeNullifier.*domain",
                r"verifyDomainSeparation",
            ],
            "ExecutionAgnosticStateCommitments": [
                r"ExecutionAgnostic", r"proofBackend",
                r"translateCommitment.*targetBackend",
            ],
            "UniversalShieldedPool": [
                r"ShieldedPool", r"merkleTree", r"isKnownRoot",
                r"nullifierHash.*recipient.*relayer",
            ],
            "CrossChainProofHub": [
                r"CrossChainProofHub", r"aggregateAndRelay",
                r"submitProof.*sourceChain",
            ],
            "SoulAtomicSwap": [
                r"AtomicSwap", r"hashlock.*timelock",
                r"completeSwap.*preimage",
            ],
            "StealthAddressRegistry": [
                r"StealthAddress", r"spendingPubKey.*viewingPubKey",
                r"ephemeralPubKey",
            ],
        }

        for contract_name, patterns in contract_patterns.items():
            for pat in patterns:
                if re.search(pat, source_code, re.IGNORECASE):
                    if contract_name not in matches:
                        matches.append(contract_name)
                    break

        return matches

    def get_fuzz_targets(self) -> list[dict[str, Any]]:
        """Get prioritized fuzzing targets based on risk assessment.

        Returns contracts and functions sorted by:
        1. Number of critical invariants
        2. Number of state writes
        3. External call count
        4. Risk level
        """
        targets = []

        for contract in self.contracts.values():
            for func in contract.functions:
                if func.visibility not in ("external", "public"):
                    continue

                # Risk score calculation
                risk_weights = {"critical": 10, "high": 7, "medium": 4, "low": 1}
                base_risk = risk_weights.get(func.risk_level, 1)

                invariant_risk = len([
                    inv for inv in contract.invariants if inv.severity == "critical"
                ]) * 5

                state_risk = len(func.state_writes) * 3
                call_risk = len(func.external_calls) * 4

                total_risk = base_risk + invariant_risk + state_risk + call_risk

                targets.append({
                    "contract": contract.name,
                    "function": func.name,
                    "category": contract.category.value,
                    "risk_score": total_risk,
                    "risk_level": func.risk_level,
                    "parameters": func.parameters,
                    "state_writes": func.state_writes,
                    "external_calls": func.external_calls,
                    "modifiers": func.modifiers,
                    "related_invariants": [
                        inv.id for inv in contract.invariants
                    ],
                })

        # Sort by risk score descending
        targets.sort(key=lambda t: t["risk_score"], reverse=True)
        return targets

    # ── Extended queries (v2 — advanced engines) ─────────────────────

    def get_taint_rules(self) -> list[dict[str, Any]]:
        """Get taint propagation rules for taint-guided mutation.

        Maps parameter names → taint sources and function names →
        taint sinks for the TaintGuidedMutator engine.
        """
        rules: list[dict[str, Any]] = []
        for contract in self.contracts.values():
            for func in contract.functions:
                if func.visibility not in ("external", "public"):
                    continue
                sources = []
                for p in func.parameters:
                    pname = p.get("name", "")
                    ptype = p.get("type", "")
                    source = "calldata"
                    if "proof" in pname.lower():
                        source = "proof_data"
                    elif "nullif" in pname.lower():
                        source = "nullifier_input"
                    elif "commit" in pname.lower():
                        source = "commitment_input"
                    elif "root" in pname.lower() or "merkle" in pname.lower():
                        source = "merkle_proof"
                    elif "bridge" in pname.lower() or "relay" in pname.lower():
                        source = "bridge_message"
                    sources.append({
                        "param": pname, "type": ptype, "taint_source": source,
                    })
                sinks = []
                for call in func.external_calls:
                    sink = "external_call"
                    if "verify" in call.lower():
                        sink = "zk_verify"
                    elif "nullifier" in call.lower():
                        sink = "nullifier_register"
                    elif "merkle" in call.lower() or "tree" in call.lower():
                        sink = "merkle_update"
                    elif "relay" in call.lower() or "bridge" in call.lower():
                        sink = "bridge_relay"
                    sinks.append({"call": call, "taint_sink": sink})
                for sw in func.state_writes:
                    sinks.append({"storage": sw, "taint_sink": "storage_write"})
                rules.append({
                    "contract": contract.name,
                    "function": func.name,
                    "sources": sources,
                    "sinks": sinks,
                    "is_payable": func.mutability == "payable",
                })
        return rules

    def get_gas_sensitive_functions(self) -> list[dict[str, Any]]:
        """Get functions susceptible to gas griefing / DoS.

        Used by the GasProfilerEngine to prioritize profiling.
        """
        sensitive: list[dict[str, Any]] = []
        for contract in self.contracts.values():
            for func in contract.functions:
                if func.visibility not in ("external", "public"):
                    continue
                # Heuristics for gas sensitivity
                has_array_param = any(
                    "[]" in p.get("type", "") for p in func.parameters
                )
                has_many_writes = len(func.state_writes) >= 2
                has_many_calls = len(func.external_calls) >= 2
                is_batch = "batch" in func.name.lower()
                is_aggregate = "aggregate" in func.name.lower()

                if any([has_array_param, has_many_writes, has_many_calls,
                        is_batch, is_aggregate]):
                    sensitive.append({
                        "contract": contract.name,
                        "function": func.name,
                        "reasons": [
                            r for cond, r in [
                                (has_array_param, "array_param"),
                                (has_many_writes, "multi_write"),
                                (has_many_calls, "multi_call"),
                                (is_batch, "batch_op"),
                                (is_aggregate, "aggregate_op"),
                            ] if cond
                        ],
                        "risk_level": func.risk_level,
                    })
        return sensitive

    def get_exploit_goals(self) -> list[dict[str, Any]]:
        """Get exploit goals with associated contracts and invariants.

        Used by the ExploitChainComposer to target compositions.
        """
        goal_map: dict[str, dict[str, Any]] = {
            "drain_funds": {
                "contracts": ["UniversalShieldedPool", "PrivacyRouter"],
                "invariants": ["SOUL-INV-030", "SOUL-INV-033", "SOUL-INV-080"],
            },
            "double_spend": {
                "contracts": ["NullifierRegistryV3", "CrossDomainNullifierAlgebra"],
                "invariants": ["SOUL-INV-001", "SOUL-INV-002", "SOUL-INV-003"],
            },
            "proof_bypass": {
                "contracts": ["ZKBoundStateLocks", "ExecutionAgnosticStateCommitments"],
                "invariants": ["SOUL-INV-010", "SOUL-INV-020", "SOUL-INV-022"],
            },
            "bridge_double_spend": {
                "contracts": ["CrossChainProofHubV3", "SoulAtomicSwapV2"],
                "invariants": ["SOUL-INV-040", "SOUL-INV-041"],
            },
            "privilege_escalation": {
                "contracts": ["SoulProtocolHub", "EmergencyRecovery"],
                "invariants": ["SOUL-INV-060", "SOUL-INV-061"],
            },
        }
        return [
            {"goal": goal, **data}
            for goal, data in goal_map.items()
        ]

    def get_state_machine_model(self) -> dict[str, Any]:
        """Get simplified state machine for StateReplayEngine.

        Models key state transitions and their constraints.
        """
        return {
            "UniversalShieldedPool": {
                "states": ["empty", "has_deposits", "withdrawing", "drained"],
                "transitions": [
                    {"from": "empty", "to": "has_deposits", "trigger": "deposit",
                     "guard": "commitment != 0"},
                    {"from": "has_deposits", "to": "has_deposits", "trigger": "deposit"},
                    {"from": "has_deposits", "to": "withdrawing", "trigger": "withdraw",
                     "guard": "validProof && !nullifierUsed && isKnownRoot"},
                    {"from": "withdrawing", "to": "has_deposits", "trigger": "withdraw_complete"},
                    {"from": "withdrawing", "to": "empty", "trigger": "withdraw_all"},
                ],
                "invariants": ["balance == deposits - withdrawals"],
            },
            "ZKBoundStateLocks": {
                "states": ["no_lock", "locked", "unlocked", "cancelled"],
                "transitions": [
                    {"from": "no_lock", "to": "locked", "trigger": "createStateLock"},
                    {"from": "locked", "to": "unlocked", "trigger": "unlockWithProof",
                     "guard": "validProof && !nullifierUsed"},
                    {"from": "locked", "to": "cancelled", "trigger": "cancelLock",
                     "guard": "msg.sender == lock.owner"},
                ],
                "invariants": [
                    "locked.stateHash == original",
                    "unlocked requires nullifier registration",
                ],
            },
            "SoulAtomicSwapV2": {
                "states": ["none", "initiated", "completed", "refunded"],
                "transitions": [
                    {"from": "none", "to": "initiated", "trigger": "initiateSwap",
                     "guard": "msg.value > 0"},
                    {"from": "initiated", "to": "completed", "trigger": "completeSwap",
                     "guard": "hash(preimage) == hashlock && block.timestamp <= timelock"},
                    {"from": "initiated", "to": "refunded", "trigger": "refundSwap",
                     "guard": "block.timestamp > timelock"},
                ],
                "invariants": ["funds_in + funds_out == 0"],
            },
        }

    def get_bytecode_analysis_hints(self) -> list[dict[str, Any]]:
        """Get hints for bytecode-level analysis.

        Provides known function selectors, storage slots, and opcode
        patterns to look for, used by EVMBytecodeAnalyzer.
        """
        hints: list[dict[str, Any]] = []
        for contract in self.contracts.values():
            func_selectors: list[dict[str, str]] = []
            for func in contract.functions:
                if func.visibility in ("external", "public"):
                    # Compute approximate selector from name + params
                    param_types = ",".join(
                        p.get("type", "") for p in func.parameters
                    )
                    sig = f"{func.name}({param_types})"
                    func_selectors.append({
                        "name": func.name,
                        "signature": sig,
                        "risk_level": func.risk_level,
                    })
            storage_slots: list[dict[str, str]] = []
            for sv in contract.state_variables:
                storage_slots.append({
                    "name": sv.name,
                    "type": sv.type,
                    "slot": str(sv.slot) if sv.slot is not None else "auto",
                })
            hints.append({
                "contract": contract.name,
                "category": contract.category.value,
                "function_selectors": func_selectors,
                "storage_slots": storage_slots,
                "security_mechanisms": [
                    m.value for m in contract.security_mechanisms
                ],
                "is_upgradeable": contract.is_upgradeable,
            })
        return hints

    def get_invariant_synthesis_seeds(self) -> list[dict[str, Any]]:
        """Get seed invariant templates for the InvariantSynthesisEngine.

        Provides known invariants + expected variable relationships
        so the synthesis engine can verify and extend them.
        """
        seeds: list[dict[str, Any]] = []
        for inv in self.invariants:
            seeds.append({
                "id": inv.id,
                "description": inv.description,
                "category": inv.category,
                "check_expression": inv.check_expression,
                "contracts": inv.contracts_involved,
                "severity": inv.severity,
            })
        return seeds
