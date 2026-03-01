"""Cross-Contract Property Testing for Soul Protocol.

Tests multi-contract invariants across the Soul Protocol's 6-layer architecture:
  Layer 1: ZK-SLock (state locking with ZK proofs)
  Layer 2: PC³ (Privacy-Preserving Cross-Chain Conduit)
  Layer 3: CDNA (Cross-Domain Nullifier Aggregator)
  Layer 4: EASC (Encrypted Atomic Swap Contract)
  Layer 5: PBP (Privacy Bridge Protocol)
  Layer 6: Core Infrastructure (registries, governance, upgrade)

Cross-contract properties verified:
  - End-to-end fund conservation across deposit → bridge → withdraw chains
  - Nullifier consistency across CDNA ↔ ZK-SLock ↔ PC³
  - State lock lifecycle correctness: create → lock → unlock → finalize
  - Bridge message integrity: source chain → relay → destination chain
  - Atomic swap completeness: initiate → (complete | refund), never partial
  - Privacy guarantee: no information leakage across contract boundaries
  - Access control transitivity across proxy/module boundaries
"""

from __future__ import annotations

import hashlib
import itertools
import logging
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

logger = logging.getLogger(__name__)


# ── Types ────────────────────────────────────────────────────────────────────


class PropertyType(Enum):
    """Types of cross-contract properties."""
    FUND_CONSERVATION = "fund_conservation"
    NULLIFIER_CONSISTENCY = "nullifier_consistency"
    STATE_LIFECYCLE = "state_lifecycle"
    BRIDGE_INTEGRITY = "bridge_integrity"
    SWAP_COMPLETENESS = "swap_completeness"
    PRIVACY_GUARANTEE = "privacy_guarantee"
    ACCESS_TRANSITIVITY = "access_transitivity"
    COMPOSABILITY_SAFETY = "composability_safety"
    UPGRADE_SAFETY = "upgrade_safety"
    RATE_LIMIT_CONSISTENCY = "rate_limit_consistency"


class InteractionPattern(Enum):
    """Common cross-contract interaction patterns."""
    DEPOSIT_BRIDGE_WITHDRAW = "deposit_bridge_withdraw"
    LOCK_PROVE_UNLOCK = "lock_prove_unlock"
    SWAP_INITIATE_COMPLETE = "swap_initiate_complete"
    NULLIFIER_REGISTER_VERIFY = "nullifier_register_verify"
    BRIDGE_SEND_RELAY_RECEIVE = "bridge_send_relay_receive"
    UPGRADE_MIGRATE_VERIFY = "upgrade_migrate_verify"
    MODULE_REGISTER_EXECUTE = "module_register_execute"
    BATCH_SUBMIT_AGGREGATE = "batch_submit_aggregate"


@dataclass
class ContractState:
    """State snapshot of a single contract."""
    contract_name: str
    balances: dict[str, int] = field(default_factory=dict)
    storage: dict[str, Any] = field(default_factory=dict)
    nullifiers: set[str] = field(default_factory=set)
    commitments: set[str] = field(default_factory=set)
    merkle_roots: list[str] = field(default_factory=list)
    current_root: str = ""
    paused: bool = False
    lock_count: int = 0

    def clone(self) -> ContractState:
        return ContractState(
            contract_name=self.contract_name,
            balances=dict(self.balances),
            storage=dict(self.storage),
            nullifiers=set(self.nullifiers),
            commitments=set(self.commitments),
            merkle_roots=list(self.merkle_roots),
            current_root=self.current_root,
            paused=self.paused,
            lock_count=self.lock_count,
        )


@dataclass
class SystemState:
    """Combined state of all contracts in the protocol."""
    contracts: dict[str, ContractState] = field(default_factory=dict)
    global_nullifiers: set[str] = field(default_factory=set)
    total_locked_value: int = 0
    total_bridged_value: int = 0
    pending_swaps: int = 0
    relay_queue: list[dict[str, Any]] = field(default_factory=list)
    block_number: int = 0
    timestamp: int = 0

    def clone(self) -> SystemState:
        return SystemState(
            contracts={k: v.clone() for k, v in self.contracts.items()},
            global_nullifiers=set(self.global_nullifiers),
            total_locked_value=self.total_locked_value,
            total_bridged_value=self.total_bridged_value,
            pending_swaps=self.pending_swaps,
            relay_queue=list(self.relay_queue),
            block_number=self.block_number,
            timestamp=self.timestamp,
        )


@dataclass
class TransactionStep:
    """A single step in a cross-contract interaction."""
    contract: str
    function: str
    inputs: dict[str, Any] = field(default_factory=dict)
    sender: str = ""
    value: int = 0
    chain_id: int = 1
    expected_success: bool = True
    depends_on: list[int] = field(default_factory=list)  # indices of prerequisite steps


@dataclass
class InteractionSequence:
    """A sequence of cross-contract transactions to test."""
    pattern: InteractionPattern
    steps: list[TransactionStep] = field(default_factory=list)
    properties_to_check: list[PropertyType] = field(default_factory=list)
    description: str = ""
    priority: int = 1

    @property
    def id(self) -> str:
        sig = f"{self.pattern.value}:{len(self.steps)}:{str(self.steps[:3])}"
        return hashlib.md5(sig.encode()).hexdigest()[:12]


@dataclass
class PropertyViolation:
    """A cross-contract property violation."""
    property_type: PropertyType
    title: str
    description: str
    severity: str
    sequence: InteractionSequence
    state_before: SystemState
    state_after: SystemState
    step_index: int = 0  # Which step caused the violation
    details: dict[str, Any] = field(default_factory=dict)
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> dict[str, Any]:
        return {
            "property": self.property_type.value,
            "title": self.title,
            "description": self.description,
            "severity": self.severity,
            "pattern": self.sequence.pattern.value,
            "step_index": self.step_index,
            "steps": [
                {"contract": s.contract, "function": s.function}
                for s in self.sequence.steps
            ],
            "details": self.details,
        }


@dataclass
class PropertyTestResult:
    """Result of cross-contract property testing."""
    sequences_tested: int = 0
    properties_checked: int = 0
    violations: list[PropertyViolation] = field(default_factory=list)
    violations_by_property: dict[str, int] = field(default_factory=dict)
    violations_by_severity: dict[str, int] = field(default_factory=dict)
    coverage: dict[str, float] = field(default_factory=dict)
    duration_sec: float = 0.0

    @property
    def critical_violations(self) -> list[PropertyViolation]:
        return [v for v in self.violations if v.severity == "critical"]

    def to_dict(self) -> dict[str, Any]:
        return {
            "sequences_tested": self.sequences_tested,
            "properties_checked": self.properties_checked,
            "violations_count": len(self.violations),
            "violations_by_property": self.violations_by_property,
            "violations_by_severity": self.violations_by_severity,
            "critical": len(self.critical_violations),
            "duration_sec": round(self.duration_sec, 2),
            "violations": [v.to_dict() for v in self.violations[:30]],
        }


# ── Sequence Generator ──────────────────────────────────────────────────────


class SequenceGenerator:
    """Generates cross-contract interaction sequences for property testing.

    Creates realistic multi-contract transaction sequences that test
    end-to-end protocol flows and invariants.
    """

    # Soul Protocol contract groups
    LAYER_1 = ["ZKSLock", "StateLockFactory"]
    LAYER_2 = ["PrivacyPool", "CommitmentTree", "WithdrawVerifier"]
    LAYER_3 = ["NullifierAggregator", "DomainRegistry", "BatchVerifier"]
    LAYER_4 = ["AtomicSwap", "HashTimeLock", "SwapFactory"]
    LAYER_5 = ["PrivacyBridge", "BridgeRelay", "ChainAdapter"]
    LAYER_6 = ["ModuleRegistry", "GovernanceVault", "UpgradeProxy"]

    def generate_sequences(
        self,
        target_patterns: list[InteractionPattern] | None = None,
        per_pattern: int = 10,
    ) -> list[InteractionSequence]:
        """Generate interaction sequences for testing."""
        patterns = target_patterns or list(InteractionPattern)
        sequences: list[InteractionSequence] = []

        for pattern in patterns:
            generator = self._get_pattern_generator(pattern)
            for _ in range(per_pattern):
                seq = generator()
                if seq:
                    sequences.append(seq)

        return sequences

    def _get_pattern_generator(self, pattern: InteractionPattern):
        """Get the generator function for a pattern."""
        generators = {
            InteractionPattern.DEPOSIT_BRIDGE_WITHDRAW: self._gen_deposit_bridge_withdraw,
            InteractionPattern.LOCK_PROVE_UNLOCK: self._gen_lock_prove_unlock,
            InteractionPattern.SWAP_INITIATE_COMPLETE: self._gen_swap_initiate_complete,
            InteractionPattern.NULLIFIER_REGISTER_VERIFY: self._gen_nullifier_register_verify,
            InteractionPattern.BRIDGE_SEND_RELAY_RECEIVE: self._gen_bridge_send_relay_receive,
            InteractionPattern.UPGRADE_MIGRATE_VERIFY: self._gen_upgrade_migrate_verify,
            InteractionPattern.MODULE_REGISTER_EXECUTE: self._gen_module_register_execute,
            InteractionPattern.BATCH_SUBMIT_AGGREGATE: self._gen_batch_submit_aggregate,
        }
        return generators.get(pattern, self._gen_deposit_bridge_withdraw)

    def _gen_deposit_bridge_withdraw(self) -> InteractionSequence:
        """Generate: deposit → bridge → withdraw flow."""
        import random
        import os

        amount = random.choice([10**18, 10**17, 5 * 10**18, 10**16])
        commitment = int.from_bytes(os.urandom(32), "big")
        nullifier = int.from_bytes(os.urandom(32), "big")
        dest_chain = random.choice([1, 10, 42161, 137])
        src_chain = random.choice([1, 10, 42161, 137])

        return InteractionSequence(
            pattern=InteractionPattern.DEPOSIT_BRIDGE_WITHDRAW,
            description="End-to-end cross-chain privacy transfer",
            priority=1,
            properties_to_check=[
                PropertyType.FUND_CONSERVATION,
                PropertyType.NULLIFIER_CONSISTENCY,
                PropertyType.BRIDGE_INTEGRITY,
            ],
            steps=[
                TransactionStep(
                    contract="PrivacyPool",
                    function="deposit",
                    inputs={"commitment": commitment, "amount": amount},
                    value=amount,
                    chain_id=src_chain,
                ),
                TransactionStep(
                    contract="NullifierAggregator",
                    function="registerNullifier",
                    inputs={"nullifier": nullifier, "domain": src_chain},
                    chain_id=src_chain,
                    depends_on=[0],
                ),
                TransactionStep(
                    contract="PrivacyBridge",
                    function="bridgeTransfer",
                    inputs={
                        "nullifier": nullifier,
                        "destChainId": dest_chain,
                        "amount": amount,
                        "proof": os.urandom(256),
                    },
                    chain_id=src_chain,
                    depends_on=[1],
                ),
                TransactionStep(
                    contract="BridgeRelay",
                    function="relayMessage",
                    inputs={
                        "sourceChainId": src_chain,
                        "nullifier": nullifier,
                        "amount": amount,
                    },
                    chain_id=dest_chain,
                    depends_on=[2],
                ),
                TransactionStep(
                    contract="PrivacyPool",
                    function="withdraw",
                    inputs={
                        "nullifier": nullifier,
                        "amount": amount,
                        "proof": os.urandom(256),
                        "root": int.from_bytes(os.urandom(32), "big"),
                    },
                    chain_id=dest_chain,
                    depends_on=[3],
                ),
            ],
        )

    def _gen_lock_prove_unlock(self) -> InteractionSequence:
        """Generate: create lock → submit proof → unlock flow."""
        import os

        state_hash = int.from_bytes(os.urandom(32), "big")
        proof = os.urandom(256)

        return InteractionSequence(
            pattern=InteractionPattern.LOCK_PROVE_UNLOCK,
            description="ZK state lock lifecycle",
            priority=1,
            properties_to_check=[
                PropertyType.STATE_LIFECYCLE,
                PropertyType.PRIVACY_GUARANTEE,
            ],
            steps=[
                TransactionStep(
                    contract="ZKSLock",
                    function="createStateLock",
                    inputs={"stateHash": state_hash, "timelock": 3600},
                ),
                TransactionStep(
                    contract="ZKSLock",
                    function="unlockWithProof",
                    inputs={"stateHash": state_hash, "proof": proof},
                    depends_on=[0],
                ),
            ],
        )

    def _gen_swap_initiate_complete(self) -> InteractionSequence:
        """Generate: initiate swap → complete/refund flow."""
        import os
        import random

        secret = os.urandom(32)
        hash_lock = hashlib.sha256(secret).digest()
        amount = random.choice([10**18, 5 * 10**17])

        return InteractionSequence(
            pattern=InteractionPattern.SWAP_INITIATE_COMPLETE,
            description="Atomic swap lifecycle",
            priority=2,
            properties_to_check=[
                PropertyType.SWAP_COMPLETENESS,
                PropertyType.FUND_CONSERVATION,
            ],
            steps=[
                TransactionStep(
                    contract="AtomicSwap",
                    function="initiateSwap",
                    inputs={
                        "hashLock": int.from_bytes(hash_lock, "big"),
                        "recipient": "0x" + os.urandom(20).hex(),
                        "timelock": int(time.time()) + 3600,
                    },
                    value=amount,
                ),
                TransactionStep(
                    contract="AtomicSwap",
                    function="completeSwap",
                    inputs={"secret": int.from_bytes(secret, "big")},
                    depends_on=[0],
                ),
            ],
        )

    def _gen_nullifier_register_verify(self) -> InteractionSequence:
        """Generate: register nullifier → verify uniqueness flow."""
        import os
        import random

        nullifiers = [int.from_bytes(os.urandom(32), "big") for _ in range(3)]
        domain = random.choice([1, 10, 42161])

        steps = []
        for i, nf in enumerate(nullifiers):
            steps.append(TransactionStep(
                contract="NullifierAggregator",
                function="registerNullifier",
                inputs={"nullifier": nf, "domain": domain},
            ))

        # Try to re-register (should fail)
        steps.append(TransactionStep(
            contract="NullifierAggregator",
            function="registerNullifier",
            inputs={"nullifier": nullifiers[0], "domain": domain},
            expected_success=False,
        ))

        return InteractionSequence(
            pattern=InteractionPattern.NULLIFIER_REGISTER_VERIFY,
            description="Nullifier uniqueness verification",
            priority=1,
            properties_to_check=[PropertyType.NULLIFIER_CONSISTENCY],
            steps=steps,
        )

    def _gen_bridge_send_relay_receive(self) -> InteractionSequence:
        """Generate: bridge send → relay → receive flow."""
        import os
        import random

        amount = random.choice([10**18, 10**17])
        src = random.choice([1, 10])
        dest = random.choice([42161, 137])
        proof = os.urandom(256)

        return InteractionSequence(
            pattern=InteractionPattern.BRIDGE_SEND_RELAY_RECEIVE,
            description="Cross-chain bridge transfer",
            priority=1,
            properties_to_check=[
                PropertyType.BRIDGE_INTEGRITY,
                PropertyType.FUND_CONSERVATION,
            ],
            steps=[
                TransactionStep(
                    contract="PrivacyBridge",
                    function="sendCrossChain",
                    inputs={"destChainId": dest, "amount": amount, "proof": proof},
                    chain_id=src,
                    value=amount,
                ),
                TransactionStep(
                    contract="BridgeRelay",
                    function="relayProof",
                    inputs={"sourceChainId": src, "proof": proof, "amount": amount},
                    chain_id=dest,
                    depends_on=[0],
                ),
                TransactionStep(
                    contract="PrivacyPool",
                    function="creditFromBridge",
                    inputs={"amount": amount, "relayProof": proof},
                    chain_id=dest,
                    depends_on=[1],
                ),
            ],
        )

    def _gen_upgrade_migrate_verify(self) -> InteractionSequence:
        """Generate: upgrade → migrate state → verify flow."""
        import os

        return InteractionSequence(
            pattern=InteractionPattern.UPGRADE_MIGRATE_VERIFY,
            description="Proxy upgrade safety verification",
            priority=2,
            properties_to_check=[
                PropertyType.UPGRADE_SAFETY,
                PropertyType.ACCESS_TRANSITIVITY,
            ],
            steps=[
                TransactionStep(
                    contract="UpgradeProxy",
                    function="proposeUpgrade",
                    inputs={"newImplementation": "0x" + os.urandom(20).hex()},
                    sender="admin",
                ),
                TransactionStep(
                    contract="UpgradeProxy",
                    function="executeUpgrade",
                    inputs={},
                    sender="admin",
                    depends_on=[0],
                ),
                TransactionStep(
                    contract="ModuleRegistry",
                    function="verifyIntegrity",
                    inputs={},
                    depends_on=[1],
                ),
            ],
        )

    def _gen_module_register_execute(self) -> InteractionSequence:
        """Generate: register module → execute operation flow."""
        import os

        module_addr = "0x" + os.urandom(20).hex()

        return InteractionSequence(
            pattern=InteractionPattern.MODULE_REGISTER_EXECUTE,
            description="Module registration and execution",
            priority=2,
            properties_to_check=[
                PropertyType.ACCESS_TRANSITIVITY,
                PropertyType.COMPOSABILITY_SAFETY,
            ],
            steps=[
                TransactionStep(
                    contract="ModuleRegistry",
                    function="registerModule",
                    inputs={"module": module_addr, "permissions": 7},
                    sender="admin",
                ),
                TransactionStep(
                    contract="ModuleRegistry",
                    function="executeOperation",
                    inputs={"module": module_addr, "data": os.urandom(64)},
                    depends_on=[0],
                ),
            ],
        )

    def _gen_batch_submit_aggregate(self) -> InteractionSequence:
        """Generate: batch submit → aggregate → verify flow."""
        import os

        nullifiers = [int.from_bytes(os.urandom(32), "big") for _ in range(5)]
        proofs = [os.urandom(128) for _ in range(5)]

        return InteractionSequence(
            pattern=InteractionPattern.BATCH_SUBMIT_AGGREGATE,
            description="Batch nullifier aggregation",
            priority=2,
            properties_to_check=[
                PropertyType.NULLIFIER_CONSISTENCY,
                PropertyType.COMPOSABILITY_SAFETY,
            ],
            steps=[
                TransactionStep(
                    contract="BatchVerifier",
                    function="submitBatch",
                    inputs={"nullifiers": nullifiers, "proofs": proofs},
                ),
                TransactionStep(
                    contract="NullifierAggregator",
                    function="aggregateAndRelay",
                    inputs={"batchId": 1},
                    depends_on=[0],
                ),
            ],
        )


# ── Property Checker ─────────────────────────────────────────────────────────


class PropertyChecker:
    """Checks cross-contract properties against system state.

    Each property checker takes the system state before and after
    a sequence of transactions and verifies that the property holds.
    """

    def __init__(self) -> None:
        self._checkers: dict[PropertyType, Any] = {
            PropertyType.FUND_CONSERVATION: self._check_fund_conservation,
            PropertyType.NULLIFIER_CONSISTENCY: self._check_nullifier_consistency,
            PropertyType.STATE_LIFECYCLE: self._check_state_lifecycle,
            PropertyType.BRIDGE_INTEGRITY: self._check_bridge_integrity,
            PropertyType.SWAP_COMPLETENESS: self._check_swap_completeness,
            PropertyType.PRIVACY_GUARANTEE: self._check_privacy_guarantee,
            PropertyType.ACCESS_TRANSITIVITY: self._check_access_transitivity,
            PropertyType.COMPOSABILITY_SAFETY: self._check_composability_safety,
            PropertyType.UPGRADE_SAFETY: self._check_upgrade_safety,
            PropertyType.RATE_LIMIT_CONSISTENCY: self._check_rate_limit_consistency,
        }

    def check_properties(
        self,
        sequence: InteractionSequence,
        state_before: SystemState,
        state_after: SystemState,
        execution_results: list[dict[str, Any]],
    ) -> list[PropertyViolation]:
        """Check all properties for a sequence."""
        violations: list[PropertyViolation] = []

        for prop_type in sequence.properties_to_check:
            checker = self._checkers.get(prop_type)
            if checker:
                violation = checker(sequence, state_before, state_after, execution_results)
                if violation:
                    violations.append(violation)

        return violations

    def _check_fund_conservation(
        self,
        seq: InteractionSequence,
        before: SystemState,
        after: SystemState,
        results: list[dict[str, Any]],
    ) -> PropertyViolation | None:
        """Total value in system must be conserved."""
        total_before = sum(
            sum(cs.balances.values())
            for cs in before.contracts.values()
        )
        total_after = sum(
            sum(cs.balances.values())
            for cs in after.contracts.values()
        )

        # Account for value injected/extracted
        value_in = sum(s.value for s in seq.steps)
        expected = total_before + value_in

        if abs(total_after - expected) > 1:  # Allow 1 wei rounding
            return PropertyViolation(
                property_type=PropertyType.FUND_CONSERVATION,
                title="Fund conservation violated",
                description=(
                    f"Total value changed from {total_before} + {value_in} input = {expected} "
                    f"to {total_after} (difference: {total_after - expected})"
                ),
                severity="critical",
                sequence=seq,
                state_before=before,
                state_after=after,
                details={
                    "total_before": total_before,
                    "value_injected": value_in,
                    "expected_total": expected,
                    "actual_total": total_after,
                    "difference": total_after - expected,
                },
            )
        return None

    def _check_nullifier_consistency(
        self,
        seq: InteractionSequence,
        before: SystemState,
        after: SystemState,
        results: list[dict[str, Any]],
    ) -> PropertyViolation | None:
        """Nullifiers must be globally unique and never reused."""
        # Check for duplicate nullifiers across contracts
        all_nullifiers: list[str] = []
        for cs in after.contracts.values():
            all_nullifiers.extend(cs.nullifiers)

        if len(all_nullifiers) != len(set(all_nullifiers)):
            duplicates = [n for n in all_nullifiers if all_nullifiers.count(n) > 1]
            return PropertyViolation(
                property_type=PropertyType.NULLIFIER_CONSISTENCY,
                title="Duplicate nullifiers detected",
                description=f"Found {len(duplicates)} duplicate nullifiers across contracts",
                severity="critical",
                sequence=seq,
                state_before=before,
                state_after=after,
                details={"duplicates": list(set(duplicates))[:10]},
            )

        # Check that used nullifiers from before are still present
        for nf in before.global_nullifiers:
            if nf not in after.global_nullifiers:
                return PropertyViolation(
                    property_type=PropertyType.NULLIFIER_CONSISTENCY,
                    title="Nullifier disappeared",
                    description=f"Previously registered nullifier {nf[:16]}... was removed",
                    severity="critical",
                    sequence=seq,
                    state_before=before,
                    state_after=after,
                )

        return None

    def _check_state_lifecycle(
        self,
        seq: InteractionSequence,
        before: SystemState,
        after: SystemState,
        results: list[dict[str, Any]],
    ) -> PropertyViolation | None:
        """State locks must follow valid lifecycle transitions."""
        zk_slock_before = before.contracts.get("ZKSLock", ContractState("ZKSLock"))
        zk_slock_after = after.contracts.get("ZKSLock", ContractState("ZKSLock"))

        # Lock count should not decrease (locks are immutable once created)
        if zk_slock_after.lock_count < zk_slock_before.lock_count:
            return PropertyViolation(
                property_type=PropertyType.STATE_LIFECYCLE,
                title="Lock count decreased",
                description="Number of state locks decreased, indicating possible deletion",
                severity="high",
                sequence=seq,
                state_before=before,
                state_after=after,
            )

        return None

    def _check_bridge_integrity(
        self,
        seq: InteractionSequence,
        before: SystemState,
        after: SystemState,
        results: list[dict[str, Any]],
    ) -> PropertyViolation | None:
        """Bridge messages must be delivered exactly once with correct data."""
        # Check for unmatched relay messages
        relay_count = sum(
            1 for s in seq.steps
            if "relay" in s.function.lower()
        )
        receive_count = sum(
            1 for s in seq.steps
            if "credit" in s.function.lower() or ("receive" in s.function.lower())
        )

        # Each relay should have exactly one credit
        if relay_count > 0 and relay_count != receive_count:
            return PropertyViolation(
                property_type=PropertyType.BRIDGE_INTEGRITY,
                title="Bridge relay/receive count mismatch",
                description=(
                    f"Relay count ({relay_count}) != receive count ({receive_count})"
                ),
                severity="high",
                sequence=seq,
                state_before=before,
                state_after=after,
            )

        return None

    def _check_swap_completeness(
        self,
        seq: InteractionSequence,
        before: SystemState,
        after: SystemState,
        results: list[dict[str, Any]],
    ) -> PropertyViolation | None:
        """Atomic swaps must complete or fully refund."""
        if after.pending_swaps > before.pending_swaps + len(
            [s for s in seq.steps if "initiate" in s.function.lower()]
        ):
            return PropertyViolation(
                property_type=PropertyType.SWAP_COMPLETENESS,
                title="Pending swap count anomaly",
                description="More pending swaps than expected",
                severity="medium",
                sequence=seq,
                state_before=before,
                state_after=after,
            )
        return None

    def _check_privacy_guarantee(
        self,
        seq: InteractionSequence,
        before: SystemState,
        after: SystemState,
        results: list[dict[str, Any]],
    ) -> PropertyViolation | None:
        """No information leakage across contract boundaries."""
        # Check for events that could leak privacy info
        for result in results:
            events = result.get("events", [])
            for event in events:
                event_str = str(event).lower()
                # Check for potential privacy leaks in events
                if any(word in event_str for word in ["sender", "recipient", "amount"]):
                    if "encrypted" not in event_str and "hash" not in event_str:
                        return PropertyViolation(
                            property_type=PropertyType.PRIVACY_GUARANTEE,
                            title="Potential privacy information leak",
                            description="Event emits unencrypted sender/recipient/amount data",
                            severity="high",
                            sequence=seq,
                            state_before=before,
                            state_after=after,
                            details={"event": event},
                        )
        return None

    def _check_access_transitivity(
        self,
        seq: InteractionSequence,
        before: SystemState,
        after: SystemState,
        results: list[dict[str, Any]],
    ) -> PropertyViolation | None:
        """Access control must be consistent across proxy/module boundaries."""
        # Check if non-admin operations succeeded on admin-only steps
        for i, step in enumerate(seq.steps):
            if step.sender and step.sender != "admin":
                privileged = any(
                    kw in step.function.lower()
                    for kw in ["register", "upgrade", "pause", "set", "admin"]
                )
                if privileged and i < len(results):
                    if results[i].get("success"):
                        return PropertyViolation(
                            property_type=PropertyType.ACCESS_TRANSITIVITY,
                            title="Unauthorized privileged operation",
                            description=(
                                f"Non-admin '{step.sender}' executed privileged function "
                                f"'{step.function}' on {step.contract}"
                            ),
                            severity="critical",
                            sequence=seq,
                            state_before=before,
                            state_after=after,
                            step_index=i,
                        )
        return None

    def _check_composability_safety(
        self,
        seq: InteractionSequence,
        before: SystemState,
        after: SystemState,
        results: list[dict[str, Any]],
    ) -> PropertyViolation | None:
        """Cross-contract calls must not create unsafe state."""
        # Check for reentrancy-like patterns
        call_stack: list[str] = []
        for step in seq.steps:
            call_sig = f"{step.contract}.{step.function}"
            if call_sig in call_stack:
                return PropertyViolation(
                    property_type=PropertyType.COMPOSABILITY_SAFETY,
                    title="Circular call pattern detected",
                    description=f"Reentrant call to {call_sig} in sequence",
                    severity="high",
                    sequence=seq,
                    state_before=before,
                    state_after=after,
                )
            call_stack.append(call_sig)
        return None

    def _check_upgrade_safety(
        self,
        seq: InteractionSequence,
        before: SystemState,
        after: SystemState,
        results: list[dict[str, Any]],
    ) -> PropertyViolation | None:
        """Storage layout must be preserved across upgrades."""
        # Compare storage layouts
        for name in before.contracts:
            if name in after.contracts:
                # Check key preservation
                old_keys = set(before.contracts[name].storage.keys())
                new_keys = set(after.contracts[name].storage.keys())
                lost = old_keys - new_keys
                if lost:
                    return PropertyViolation(
                        property_type=PropertyType.UPGRADE_SAFETY,
                        title="Storage slots lost during upgrade",
                        description=f"Lost storage slots in {name}: {lost}",
                        severity="critical",
                        sequence=seq,
                        state_before=before,
                        state_after=after,
                    )
        return None

    def _check_rate_limit_consistency(
        self,
        seq: InteractionSequence,
        before: SystemState,
        after: SystemState,
        results: list[dict[str, Any]],
    ) -> PropertyViolation | None:
        """Rate limits must be enforced consistently across entry points."""
        return None  # Requires specific rate limit tracking


# ── Cross-Contract Property Tester ───────────────────────────────────────────


class CrossContractPropertyTester:
    """End-to-end property tester for Soul Protocol's multi-contract system.

    Orchestrates:
    1. Sequence generation (realistic cross-contract flows)
    2. System state management (mock or real)
    3. Sequence execution
    4. Property verification
    5. Violation collection and reporting
    """

    def __init__(
        self,
        executor: Any | None = None,
        max_sequences: int = 500,
        timeout_sec: float = 600.0,
    ) -> None:
        self.executor = executor
        self.max_sequences = max_sequences
        self.timeout_sec = timeout_sec
        self.seq_gen = SequenceGenerator()
        self.prop_checker = PropertyChecker()

    async def run_property_tests(
        self,
        target_patterns: list[InteractionPattern] | None = None,
        per_pattern: int = 20,
    ) -> PropertyTestResult:
        """Run cross-contract property tests."""
        start = time.time()
        result = PropertyTestResult()

        sequences = self.seq_gen.generate_sequences(
            target_patterns=target_patterns,
            per_pattern=per_pattern,
        )

        logger.info(
            "Starting cross-contract property testing: %d sequences, %d patterns",
            len(sequences),
            len(target_patterns or InteractionPattern),
        )

        for seq in sequences[:self.max_sequences]:
            elapsed = time.time() - start
            if elapsed >= self.timeout_sec:
                break

            violations = await self._test_sequence(seq)
            result.sequences_tested += 1
            result.properties_checked += len(seq.properties_to_check)

            for v in violations:
                result.violations.append(v)
                result.violations_by_property[v.property_type.value] = (
                    result.violations_by_property.get(v.property_type.value, 0) + 1
                )
                result.violations_by_severity[v.severity] = (
                    result.violations_by_severity.get(v.severity, 0) + 1
                )

        result.duration_sec = time.time() - start

        logger.info(
            "Property testing complete: %d sequences, %d violations (%d critical) in %.1fs",
            result.sequences_tested,
            len(result.violations),
            len(result.critical_violations),
            result.duration_sec,
        )

        return result

    async def _test_sequence(
        self,
        seq: InteractionSequence,
    ) -> list[PropertyViolation]:
        """Test a single interaction sequence."""
        # Create initial system state
        state_before = self._create_initial_state()

        # Execute each step
        execution_results: list[dict[str, Any]] = []
        current_state = state_before.clone()

        for i, step in enumerate(seq.steps):
            result = await self._execute_step(step, current_state)
            execution_results.append(result)

            # Update state based on execution
            self._update_state(current_state, step, result)

        # Check properties
        violations = self.prop_checker.check_properties(
            seq, state_before, current_state, execution_results,
        )

        return violations

    async def _execute_step(
        self,
        step: TransactionStep,
        state: SystemState,
    ) -> dict[str, Any]:
        """Execute a single transaction step."""
        if self.executor:
            try:
                result = await self.executor.execute(
                    contract_name=step.contract,
                    function_name=step.function,
                    inputs=step.inputs,
                    sender=step.sender,
                    value=step.value,
                )
                return {
                    "success": result.success,
                    "reverted": result.reverted,
                    "revert_reason": result.revert_reason,
                    "gas_used": result.gas_used,
                    "events": result.logs,
                    "state_changes": result.state_changes,
                }
            except Exception as e:
                return {"success": False, "error": str(e)}

        # Simulation mode
        return self._simulate_step(step, state)

    def _simulate_step(
        self,
        step: TransactionStep,
        state: SystemState,
    ) -> dict[str, Any]:
        """Simulate step execution for analysis mode."""
        import random

        # Check if contract is paused
        contract_state = state.contracts.get(step.contract)
        if contract_state and contract_state.paused:
            return {"success": False, "reverted": True, "revert_reason": "Contract paused"}

        # Check expected success
        if not step.expected_success:
            return {"success": False, "reverted": True, "revert_reason": "Expected failure"}

        # Simulate based on function type
        func = step.function.lower()

        if "deposit" in func:
            return {"success": True, "events": [{"Deposit": step.value}]}
        if "withdraw" in func:
            return {"success": True, "events": [{"Withdraw": step.inputs.get("amount", 0)}]}
        if "register" in func and step.sender != "admin":
            if "module" in func or "upgrade" in func:
                return {"success": False, "reverted": True, "revert_reason": "Unauthorized"}
        if "relay" in func:
            return {"success": True, "events": [{"MessageRelayed": True}]}

        return {"success": True, "gas_used": 50000 + random.randint(0, 100000)}

    def _update_state(
        self,
        state: SystemState,
        step: TransactionStep,
        result: dict[str, Any],
    ) -> None:
        """Update system state based on execution result."""
        if not result.get("success"):
            return

        # Ensure contract state exists
        if step.contract not in state.contracts:
            state.contracts[step.contract] = ContractState(step.contract)

        cs = state.contracts[step.contract]
        func = step.function.lower()

        if "deposit" in func:
            cs.balances["pool"] = cs.balances.get("pool", 0) + step.value
            commitment = step.inputs.get("commitment")
            if commitment:
                cs.commitments.add(str(commitment))

        elif "withdraw" in func:
            amount = step.inputs.get("amount", 0)
            cs.balances["pool"] = max(0, cs.balances.get("pool", 0) - amount)
            nullifier = step.inputs.get("nullifier")
            if nullifier:
                cs.nullifiers.add(str(nullifier))
                state.global_nullifiers.add(str(nullifier))

        elif "register" in func and "nullifier" in func:
            nullifier = step.inputs.get("nullifier")
            if nullifier:
                cs.nullifiers.add(str(nullifier))
                state.global_nullifiers.add(str(nullifier))

        elif "lock" in func or "createstate" in func:
            cs.lock_count += 1

        elif "bridge" in func or "relay" in func:
            amount = step.inputs.get("amount", 0)
            state.total_bridged_value += amount

        elif "swap" in func and "initiate" in func:
            state.pending_swaps += 1

        elif "swap" in func and ("complete" in func or "refund" in func):
            state.pending_swaps = max(0, state.pending_swaps - 1)

    def _create_initial_state(self) -> SystemState:
        """Create initial system state for testing."""
        return SystemState(
            contracts={
                "PrivacyPool": ContractState(
                    "PrivacyPool",
                    balances={"pool": 100 * 10**18},
                ),
                "NullifierAggregator": ContractState("NullifierAggregator"),
                "ZKSLock": ContractState("ZKSLock"),
                "AtomicSwap": ContractState("AtomicSwap"),
                "PrivacyBridge": ContractState(
                    "PrivacyBridge",
                    balances={"liquidity": 50 * 10**18},
                ),
                "BridgeRelay": ContractState("BridgeRelay"),
                "ModuleRegistry": ContractState("ModuleRegistry"),
                "UpgradeProxy": ContractState("UpgradeProxy"),
            },
            block_number=18_000_000,
            timestamp=int(time.time()),
        )
