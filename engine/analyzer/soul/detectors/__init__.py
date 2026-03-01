"""Soul Protocol-specific vulnerability detectors.

All 24 detectors organized by category:
  - Nullifier (4): SOUL-NULL-001..004
  - ZK Proof (5):  SOUL-ZK-001..005
  - Bridge (5):    SOUL-BRIDGE-001..005
  - Privacy (5):   SOUL-PRIV-001..005
  - Access Ctrl (4): SOUL-ACL-001..004
  - Economic (5):  SOUL-ECON-001..005
"""

from engine.analyzer.soul.detectors.nullifier import (
    NullifierReplayDetector,
    DomainSeparationDetector,
    BatchNullifierAtomicityDetector,
    NullifierFrontRunDetector,
)
from engine.analyzer.soul.detectors.zk_proof import (
    ProofVerificationBypassDetector,
    ProofReplayDetector,
    VerifierRegistryManipulationDetector,
    ProofTranslationIntegrityDetector,
    MissingProofExpirationDetector,
)
from engine.analyzer.soul.detectors.bridge import (
    BridgeRelayReplayDetector,
    MissingCircuitBreakerDetector,
    AtomicSwapFundLossDetector,
    CrossChainChainIdValidationDetector,
    BridgeRateLimitBypassDetector,
)
from engine.analyzer.soul.detectors.privacy import (
    ShieldedPoolInflationDetector,
    MerkleTreeIntegrityDetector,
    StealthAddressLeakDetector,
    EncryptedStateExposureDetector,
    PrivacyZoneMisconfigDetector,
)
from engine.analyzer.soul.detectors.access_control import (
    PrivilegeEscalationDetector,
    EmergencyBypassDetector,
    KillSwitchAbuseDetector,
    UpgradeSecurityDetector,
)
from engine.analyzer.soul.detectors.economic import (
    FlashLoanGuardBypassDetector,
    DustAttackDetector,
    FeeManipulationDetector,
    MEVExtractionDetector,
    GriefingAttackDetector,
)

SOUL_DETECTORS: list[type] = [
    # Nullifier
    NullifierReplayDetector,
    DomainSeparationDetector,
    BatchNullifierAtomicityDetector,
    NullifierFrontRunDetector,
    # ZK Proof
    ProofVerificationBypassDetector,
    ProofReplayDetector,
    VerifierRegistryManipulationDetector,
    ProofTranslationIntegrityDetector,
    MissingProofExpirationDetector,
    # Bridge
    BridgeRelayReplayDetector,
    MissingCircuitBreakerDetector,
    AtomicSwapFundLossDetector,
    CrossChainChainIdValidationDetector,
    BridgeRateLimitBypassDetector,
    # Privacy
    ShieldedPoolInflationDetector,
    MerkleTreeIntegrityDetector,
    StealthAddressLeakDetector,
    EncryptedStateExposureDetector,
    PrivacyZoneMisconfigDetector,
    # Access Control
    PrivilegeEscalationDetector,
    EmergencyBypassDetector,
    KillSwitchAbuseDetector,
    UpgradeSecurityDetector,
    # Economic
    FlashLoanGuardBypassDetector,
    DustAttackDetector,
    FeeManipulationDetector,
    MEVExtractionDetector,
    GriefingAttackDetector,
]

__all__ = [
    "SOUL_DETECTORS",
    # Nullifier
    "NullifierReplayDetector",
    "DomainSeparationDetector",
    "BatchNullifierAtomicityDetector",
    "NullifierFrontRunDetector",
    # ZK Proof
    "ProofVerificationBypassDetector",
    "ProofReplayDetector",
    "VerifierRegistryManipulationDetector",
    "ProofTranslationIntegrityDetector",
    "MissingProofExpirationDetector",
    # Bridge
    "BridgeRelayReplayDetector",
    "MissingCircuitBreakerDetector",
    "AtomicSwapFundLossDetector",
    "CrossChainChainIdValidationDetector",
    "BridgeRateLimitBypassDetector",
    # Privacy
    "ShieldedPoolInflationDetector",
    "MerkleTreeIntegrityDetector",
    "StealthAddressLeakDetector",
    "EncryptedStateExposureDetector",
    "PrivacyZoneMisconfigDetector",
    # Access Control
    "PrivilegeEscalationDetector",
    "EmergencyBypassDetector",
    "KillSwitchAbuseDetector",
    "UpgradeSecurityDetector",
    # Economic
    "FlashLoanGuardBypassDetector",
    "DustAttackDetector",
    "FeeManipulationDetector",
    "MEVExtractionDetector",
    "GriefingAttackDetector",
]
