"""Taint-Guided Mutator — dataflow-aware mutation targeting.

Tracks dataflow taint from inputs through storage/memory to outputs,
then focuses mutations on taint-sensitive paths for maximum coverage.

Architecture:
  ┌──────────────────────────────────────────────────────────────────┐
  │              TAINT-GUIDED  MUTATOR                              │
  │                                                                  │
  │  ┌──────────┐  ┌────────────┐  ┌──────────────┐  ┌──────────┐ │
  │  │Taint     │─►│Propagation │─►│Sink          │─►│Targeted  │ │
  │  │Source    │  │Engine      │  │Detector      │  │Mutator   │ │
  │  │Marker    │  │            │  │              │  │          │ │
  │  └──────────┘  └────────────┘  └──────────────┘  └──────────┘ │
  │       │              │               │                   │      │
  │       ▼              ▼               ▼                   ▼      │
  │  ┌──────────┐  ┌────────────┐  ┌──────────────┐  ┌──────────┐ │
  │  │Input     │  │Storage     │  │Security-     │  │Taint-    │ │
  │  │Classifier│  │Flow        │  │critical      │  │weighted  │ │
  │  │          │  │Tracker     │  │Operations    │  │Scheduling│ │
  │  └──────────┘  └────────────┘  └──────────────┘  └──────────┘ │
  │                                                                  │
  │  ┌──────────────────────────────────────────────────────────┐   │
  │  │ Soul Protocol Taint Rules:                               │   │
  │  │   proof_data → verifyProof() → state_update              │   │
  │  │   nullifier  → checkNullifier() → nullifier_set          │   │
  │  │   commitment → deposit() → merkle_tree                   │   │
  │  │   msg.value  → pool_balance → withdraw()                 │   │
  │  └──────────────────────────────────────────────────────────┘   │
  └──────────────────────────────────────────────────────────────────┘
"""

from __future__ import annotations

import hashlib
import logging
import random
import time
from collections import defaultdict
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

logger = logging.getLogger(__name__)


# ── Enums ────────────────────────────────────────────────────────────────────

class TaintSource(Enum):
    """Origins of tainted data."""
    CALLDATA = "calldata"            # Function arguments
    MSG_VALUE = "msg.value"          # Ether sent
    MSG_SENDER = "msg.sender"        # Caller address
    BLOCK_TIMESTAMP = "block.timestamp"
    BLOCK_NUMBER = "block.number"
    TX_ORIGIN = "tx.origin"
    RETURN_DATA = "return_data"      # Return from external call
    DELEGATECALL_DATA = "delegatecall_data"
    STORAGE_READ = "storage_read"    # Loaded from storage
    MEMORY_READ = "memory_read"      # From memory
    PROOF_DATA = "proof_data"        # ZK proof bytes (Soul-specific)
    NULLIFIER_INPUT = "nullifier_input"  # Nullifier (Soul-specific)
    COMMITMENT_INPUT = "commitment_input"  # Commitment (Soul-specific)
    MERKLE_PROOF = "merkle_proof"    # Merkle proof nodes (Soul-specific)
    PUBLIC_INPUTS = "public_inputs"  # ZK public inputs (Soul-specific)
    BRIDGE_MESSAGE = "bridge_message"  # Cross-chain message (Soul-specific)
    ORACLE_PRICE = "oracle_price"    # External oracle data


class TaintSink(Enum):
    """Security-critical destinations for tainted data."""
    EXTERNAL_CALL = "external_call"
    DELEGATECALL = "delegatecall"
    SELFDESTRUCT = "selfdestruct"
    STORAGE_WRITE = "storage_write"
    ETH_TRANSFER = "eth_transfer"
    EVENT_EMIT = "event_emit"
    REVERT_CONDITION = "revert_condition"
    REQUIRE_CONDITION = "require_condition"
    # Soul-specific sinks
    ZK_VERIFY = "zk_verify"
    NULLIFIER_REGISTER = "nullifier_register"
    MERKLE_UPDATE = "merkle_update"
    BRIDGE_RELAY = "bridge_relay"
    POOL_BALANCE_UPDATE = "pool_balance_update"
    COMMITMENT_INSERT = "commitment_insert"
    ACCESS_CHECK = "access_check"


class TaintPropagation(Enum):
    """How taint propagates through operations."""
    DIRECT = "direct"          # y = x
    ARITHMETIC = "arithmetic"  # y = x + z
    BITWISE = "bitwise"        # y = x & mask
    HASH = "hash"              # y = keccak256(x)
    COMPARISON = "comparison"  # y = (x == z)
    CONDITIONAL = "conditional"  # if(x) { y = ... }
    STORAGE = "storage"        # slot[x] = y
    MEMORY = "memory"          # mstore(x, y)
    CONCAT = "concat"          # y = abi.encodePacked(x, z)


class TaintSensitivity(Enum):
    """Mutation sensitivity based on taint analysis."""
    CRITICAL = "critical"   # Direct path to security sink
    HIGH = "high"           # Indirect path to security sink
    MEDIUM = "medium"       # Reaches storage/state change
    LOW = "low"             # Reaches benign operation
    NONE = "none"           # No taint reaches significant sink


# ── Data Classes ─────────────────────────────────────────────────────────────

@dataclass
class TaintLabel:
    """A taint label tracking data origin."""
    id: str = ""
    source: TaintSource = TaintSource.CALLDATA
    parameter_name: str = ""
    parameter_index: int = -1
    byte_offset: int = 0
    byte_length: int = 32
    propagation_chain: list[TaintPropagation] = field(default_factory=list)
    generation: int = 0  # propagation distance from source

    def derive(self, prop: TaintPropagation) -> TaintLabel:
        """Create a derived taint label after propagation."""
        return TaintLabel(
            id=f"{self.id}→{prop.value}",
            source=self.source,
            parameter_name=self.parameter_name,
            parameter_index=self.parameter_index,
            byte_offset=self.byte_offset,
            byte_length=self.byte_length,
            propagation_chain=[*self.propagation_chain, prop],
            generation=self.generation + 1,
        )


@dataclass
class TaintedValue:
    """A value carrying taint labels."""
    value: Any = None
    labels: list[TaintLabel] = field(default_factory=list)
    location: str = ""  # calldata, memory, storage, stack
    offset: int = 0

    @property
    def is_tainted(self) -> bool:
        return len(self.labels) > 0

    @property
    def sources(self) -> set[TaintSource]:
        return {l.source for l in self.labels}


@dataclass
class TaintFlow:
    """A complete taint flow from source to sink."""
    flow_id: str = ""
    source: TaintSource = TaintSource.CALLDATA
    sink: TaintSink = TaintSink.STORAGE_WRITE
    source_param: str = ""
    sink_operation: str = ""
    propagation_path: list[TaintPropagation] = field(default_factory=list)
    path_length: int = 0
    sensitivity: TaintSensitivity = TaintSensitivity.MEDIUM
    soul_specific: bool = False
    contract: str = ""
    function: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "flow_id": self.flow_id,
            "source": self.source.value,
            "sink": self.sink.value,
            "source_param": self.source_param,
            "sink_operation": self.sink_operation,
            "path_length": self.path_length,
            "sensitivity": self.sensitivity.value,
            "soul_specific": self.soul_specific,
            "function": self.function,
        }


@dataclass
class MutationTarget:
    """A specific mutation target derived from taint analysis."""
    parameter_name: str = ""
    parameter_index: int = -1
    byte_offset: int = 0
    byte_length: int = 32
    sensitivity: TaintSensitivity = TaintSensitivity.MEDIUM
    recommended_mutations: list[str] = field(default_factory=list)
    reaching_sinks: list[TaintSink] = field(default_factory=list)
    weight: float = 1.0
    soul_specific: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "parameter": self.parameter_name,
            "index": self.parameter_index,
            "offset": self.byte_offset,
            "length": self.byte_length,
            "sensitivity": self.sensitivity.value,
            "mutations": self.recommended_mutations[:5],
            "sinks": [s.value for s in self.reaching_sinks],
            "weight": round(self.weight, 3),
            "soul_specific": self.soul_specific,
        }


@dataclass
class TaintAnalysisResult:
    """Result of taint analysis for a function."""
    contract: str = ""
    function: str = ""
    flows: list[TaintFlow] = field(default_factory=list)
    mutation_targets: list[MutationTarget] = field(default_factory=list)
    critical_paths: int = 0
    high_paths: int = 0
    total_flows: int = 0
    analysis_time_sec: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "contract": self.contract,
            "function": self.function,
            "flows": [f.to_dict() for f in self.flows[:20]],
            "mutation_targets": [m.to_dict() for m in self.mutation_targets],
            "critical_paths": self.critical_paths,
            "high_paths": self.high_paths,
            "total_flows": self.total_flows,
            "analysis_time_sec": round(self.analysis_time_sec, 3),
        }


# ── Taint Source Marker ──────────────────────────────────────────────────────

class TaintSourceMarker:
    """Marks taint sources in function inputs."""

    # Soul Protocol parameter classification
    SOUL_PARAM_SOURCES: dict[str, TaintSource] = {
        "proof": TaintSource.PROOF_DATA,
        "zkProof": TaintSource.PROOF_DATA,
        "_proof": TaintSource.PROOF_DATA,
        "proofData": TaintSource.PROOF_DATA,
        "nullifier": TaintSource.NULLIFIER_INPUT,
        "_nullifier": TaintSource.NULLIFIER_INPUT,
        "nullifierHash": TaintSource.NULLIFIER_INPUT,
        "commitment": TaintSource.COMMITMENT_INPUT,
        "_commitment": TaintSource.COMMITMENT_INPUT,
        "merkleProof": TaintSource.MERKLE_PROOF,
        "_merkleProof": TaintSource.MERKLE_PROOF,
        "pathElements": TaintSource.MERKLE_PROOF,
        "pathIndices": TaintSource.MERKLE_PROOF,
        "publicInputs": TaintSource.PUBLIC_INPUTS,
        "_publicInputs": TaintSource.PUBLIC_INPUTS,
        "root": TaintSource.MERKLE_PROOF,
        "_root": TaintSource.MERKLE_PROOF,
        "bridgeMsg": TaintSource.BRIDGE_MESSAGE,
        "relayData": TaintSource.BRIDGE_MESSAGE,
        "sourceChainId": TaintSource.BRIDGE_MESSAGE,
    }

    def mark_function_inputs(
        self,
        function_name: str,
        parameters: list[dict[str, Any]],
        has_payable: bool = False,
    ) -> list[TaintedValue]:
        """Mark all function inputs as taint sources."""
        tainted: list[TaintedValue] = []

        for idx, param in enumerate(parameters):
            name = param.get("name", f"param_{idx}")
            ptype = param.get("type", "uint256")

            source = self._classify_source(name, ptype)
            label = TaintLabel(
                id=f"src-{function_name}-{name}",
                source=source,
                parameter_name=name,
                parameter_index=idx,
                byte_offset=idx * 32,
                byte_length=self._type_size(ptype),
                generation=0,
            )

            tainted.append(TaintedValue(
                labels=[label],
                location="calldata",
                offset=4 + idx * 32,  # skip selector
            ))

        # msg.value
        if has_payable:
            label = TaintLabel(
                id=f"src-{function_name}-msg.value",
                source=TaintSource.MSG_VALUE,
                parameter_name="msg.value",
                generation=0,
            )
            tainted.append(TaintedValue(
                labels=[label],
                location="special",
            ))

        # msg.sender (always tainted)
        sender_label = TaintLabel(
            id=f"src-{function_name}-msg.sender",
            source=TaintSource.MSG_SENDER,
            parameter_name="msg.sender",
            generation=0,
        )
        tainted.append(TaintedValue(
            labels=[sender_label],
            location="special",
        ))

        return tainted

    def _classify_source(self, name: str, ptype: str) -> TaintSource:
        """Classify parameter as taint source."""
        # Check Soul-specific mappings
        if name in self.SOUL_PARAM_SOURCES:
            return self.SOUL_PARAM_SOURCES[name]

        # Heuristic classification
        lower_name = name.lower()
        if "proof" in lower_name:
            return TaintSource.PROOF_DATA
        if "nullif" in lower_name:
            return TaintSource.NULLIFIER_INPUT
        if "commit" in lower_name:
            return TaintSource.COMMITMENT_INPUT
        if "merkle" in lower_name or "root" in lower_name:
            return TaintSource.MERKLE_PROOF
        if "bridge" in lower_name or "relay" in lower_name:
            return TaintSource.BRIDGE_MESSAGE
        if "price" in lower_name or "oracle" in lower_name:
            return TaintSource.ORACLE_PRICE

        return TaintSource.CALLDATA

    def _type_size(self, ptype: str) -> int:
        """Estimate byte size of a Solidity type."""
        if ptype.startswith("bytes") and ptype != "bytes":
            try:
                return int(ptype[5:])
            except ValueError:
                return 32
        if ptype in ("address", "uint160"):
            return 20
        if ptype in ("bool", "uint8", "int8"):
            return 1
        if "[]" in ptype or ptype == "bytes" or ptype == "string":
            return 64  # dynamic — offset + length minimum
        return 32


# ── Taint Propagation Engine ────────────────────────────────────────────────

class TaintPropagationEngine:
    """Tracks how taint propagates through operations."""

    def __init__(self, max_generation: int = 20) -> None:
        self._max_generation = max_generation
        self._tainted_storage: dict[int, list[TaintLabel]] = {}
        self._tainted_memory: dict[int, list[TaintLabel]] = {}

    def propagate_arithmetic(
        self,
        operands: list[TaintedValue],
    ) -> list[TaintLabel]:
        """Taint propagates through arithmetic (ADD, SUB, MUL, DIV, MOD)."""
        labels: list[TaintLabel] = []
        for op in operands:
            for label in op.labels:
                if label.generation < self._max_generation:
                    labels.append(label.derive(TaintPropagation.ARITHMETIC))
        return labels

    def propagate_hash(
        self,
        operands: list[TaintedValue],
    ) -> list[TaintLabel]:
        """Taint propagates through hashing (SHA3/KECCAK256)."""
        labels: list[TaintLabel] = []
        for op in operands:
            for label in op.labels:
                if label.generation < self._max_generation:
                    labels.append(label.derive(TaintPropagation.HASH))
        return labels

    def propagate_comparison(
        self,
        operands: list[TaintedValue],
    ) -> list[TaintLabel]:
        """Taint propagates through comparisons (EQ, LT, GT, SLT, SGT)."""
        labels: list[TaintLabel] = []
        for op in operands:
            for label in op.labels:
                if label.generation < self._max_generation:
                    labels.append(label.derive(TaintPropagation.COMPARISON))
        return labels

    def propagate_storage_write(
        self,
        slot: int,
        value_labels: list[TaintLabel],
    ) -> None:
        """Record taint flowing into storage."""
        self._tainted_storage[slot] = value_labels

    def propagate_storage_read(self, slot: int) -> list[TaintLabel]:
        """Retrieve taint from storage slot."""
        stored = self._tainted_storage.get(slot, [])
        return [
            label.derive(TaintPropagation.STORAGE)
            for label in stored
            if label.generation < self._max_generation
        ]

    def propagate_memory_write(
        self, offset: int, value_labels: list[TaintLabel],
    ) -> None:
        self._tainted_memory[offset] = value_labels

    def propagate_memory_read(self, offset: int) -> list[TaintLabel]:
        stored = self._tainted_memory.get(offset, [])
        return [
            label.derive(TaintPropagation.MEMORY)
            for label in stored
            if label.generation < self._max_generation
        ]

    def combine_labels(
        self, labels_list: list[list[TaintLabel]],
    ) -> list[TaintLabel]:
        """Combine taint labels from multiple operands (union semantics)."""
        seen: set[str] = set()
        result: list[TaintLabel] = []
        for labels in labels_list:
            for label in labels:
                if label.id not in seen:
                    seen.add(label.id)
                    result.append(label)
        return result

    def reset(self) -> None:
        """Reset propagation state."""
        self._tainted_storage.clear()
        self._tainted_memory.clear()


# ── Sink Detector ────────────────────────────────────────────────────────────

class TaintSinkDetector:
    """Detects when tainted data reaches security-critical sinks."""

    # Soul Protocol function → sink type mapping
    SOUL_FUNCTION_SINKS: dict[str, TaintSink] = {
        "verifyProof": TaintSink.ZK_VERIFY,
        "verify": TaintSink.ZK_VERIFY,
        "registerNullifier": TaintSink.NULLIFIER_REGISTER,
        "checkNullifier": TaintSink.NULLIFIER_REGISTER,
        "updateMerkleRoot": TaintSink.MERKLE_UPDATE,
        "insertLeaf": TaintSink.MERKLE_UPDATE,
        "relayProof": TaintSink.BRIDGE_RELAY,
        "processRelay": TaintSink.BRIDGE_RELAY,
        "deposit": TaintSink.POOL_BALANCE_UPDATE,
        "withdraw": TaintSink.POOL_BALANCE_UPDATE,
        "insertCommitment": TaintSink.COMMITMENT_INSERT,
    }

    def detect_sink(
        self,
        opcode: str,
        tainted_operands: list[TaintedValue],
        function_name: str = "",
    ) -> TaintSink | None:
        """Detect if an operation is a taint sink."""
        if not any(op.is_tainted for op in tainted_operands):
            return None

        # EVM opcode sinks
        opcode_sinks: dict[str, TaintSink] = {
            "CALL": TaintSink.EXTERNAL_CALL,
            "DELEGATECALL": TaintSink.DELEGATECALL,
            "STATICCALL": TaintSink.EXTERNAL_CALL,
            "SELFDESTRUCT": TaintSink.SELFDESTRUCT,
            "SSTORE": TaintSink.STORAGE_WRITE,
            "LOG0": TaintSink.EVENT_EMIT,
            "LOG1": TaintSink.EVENT_EMIT,
            "LOG2": TaintSink.EVENT_EMIT,
            "LOG3": TaintSink.EVENT_EMIT,
            "LOG4": TaintSink.EVENT_EMIT,
            "REVERT": TaintSink.REVERT_CONDITION,
        }

        sink = opcode_sinks.get(opcode)
        if sink:
            return sink

        # Function-level sinks
        if function_name in self.SOUL_FUNCTION_SINKS:
            return self.SOUL_FUNCTION_SINKS[function_name]

        return None

    def classify_sensitivity(
        self,
        source: TaintSource,
        sink: TaintSink,
        path_length: int,
    ) -> TaintSensitivity:
        """Classify the sensitivity of a taint flow."""
        # Critical: direct attacker-controlled input → critical sink
        critical_combos = {
            (TaintSource.CALLDATA, TaintSink.DELEGATECALL),
            (TaintSource.CALLDATA, TaintSink.SELFDESTRUCT),
            (TaintSource.CALLDATA, TaintSink.EXTERNAL_CALL),
            (TaintSource.PROOF_DATA, TaintSink.ZK_VERIFY),
            (TaintSource.NULLIFIER_INPUT, TaintSink.NULLIFIER_REGISTER),
            (TaintSource.COMMITMENT_INPUT, TaintSink.COMMITMENT_INSERT),
            (TaintSource.MERKLE_PROOF, TaintSink.MERKLE_UPDATE),
            (TaintSource.BRIDGE_MESSAGE, TaintSink.BRIDGE_RELAY),
            (TaintSource.PUBLIC_INPUTS, TaintSink.ZK_VERIFY),
            (TaintSource.MSG_VALUE, TaintSink.POOL_BALANCE_UPDATE),
            (TaintSource.RETURN_DATA, TaintSink.DELEGATECALL),
            (TaintSource.DELEGATECALL_DATA, TaintSink.STORAGE_WRITE),
        }

        if (source, sink) in critical_combos:
            return TaintSensitivity.CRITICAL

        # High: controlled input → state modification
        high_sinks = {
            TaintSink.STORAGE_WRITE,
            TaintSink.EXTERNAL_CALL,
            TaintSink.ETH_TRANSFER,
            TaintSink.POOL_BALANCE_UPDATE,
        }
        if sink in high_sinks and path_length <= 5:
            return TaintSensitivity.HIGH

        # Medium: longer path to significant sink
        if sink in high_sinks:
            return TaintSensitivity.MEDIUM

        # Low: reaches only benign operations
        return TaintSensitivity.LOW


# ── Taint-Guided Mutation Recommender ────────────────────────────────────────

class TaintMutationRecommender:
    """Recommends mutations based on taint analysis."""

    # Source → recommended mutation strategies
    SOURCE_MUTATIONS: dict[TaintSource, list[str]] = {
        TaintSource.CALLDATA: [
            "bit_flip", "byte_flip", "interesting_value",
            "arithmetic_boundary", "type_confusion",
        ],
        TaintSource.MSG_VALUE: [
            "zero_value", "max_value", "overflow_value",
            "dust_amount", "exact_balance",
        ],
        TaintSource.MSG_SENDER: [
            "zero_address", "contract_address", "owner_address",
            "self_address", "precompile_address",
        ],
        TaintSource.PROOF_DATA: [
            "corrupt_proof", "zero_proof", "replay_proof",
            "truncated_proof", "malformed_proof", "flipped_proof_bits",
        ],
        TaintSource.NULLIFIER_INPUT: [
            "replay_nullifier", "zero_nullifier", "max_nullifier",
            "collision_nullifier", "sequential_nullifier",
        ],
        TaintSource.COMMITMENT_INPUT: [
            "zero_commitment", "duplicate_commitment",
            "malformed_commitment", "non_member_commitment",
        ],
        TaintSource.MERKLE_PROOF: [
            "stale_merkle_root", "empty_proof", "truncated_proof",
            "wrong_path", "sibling_swap", "root_manipulation",
        ],
        TaintSource.PUBLIC_INPUTS: [
            "zero_inputs", "overflow_inputs", "mismatched_inputs",
            "reordered_inputs", "extra_inputs",
        ],
        TaintSource.BRIDGE_MESSAGE: [
            "wrong_chain_id", "duplicate_relay", "forged_message",
            "empty_payload", "oversized_payload",
        ],
        TaintSource.ORACLE_PRICE: [
            "zero_price", "max_price", "negative_price",
            "stale_price", "manipulated_price",
        ],
        TaintSource.BLOCK_TIMESTAMP: [
            "future_timestamp", "past_timestamp", "exact_deadline",
        ],
    }

    # Sink → extra mutation hints
    SINK_MUTATIONS: dict[TaintSink, list[str]] = {
        TaintSink.EXTERNAL_CALL: [
            "reentrant_callback", "gas_limited_call", "failing_call",
        ],
        TaintSink.DELEGATECALL: [
            "malicious_implementation", "storage_collision",
        ],
        TaintSink.ZK_VERIFY: [
            "invalid_proof_format", "wrong_verifier_key",
        ],
        TaintSink.NULLIFIER_REGISTER: [
            "race_condition_nullifier",
        ],
        TaintSink.BRIDGE_RELAY: [
            "replay_relay", "cross_chain_race",
        ],
    }

    def recommend_mutations(
        self,
        flows: list[TaintFlow],
    ) -> list[MutationTarget]:
        """Generate mutation targets from taint flows."""
        # Group flows by source parameter
        param_flows: dict[str, list[TaintFlow]] = defaultdict(list)
        for flow in flows:
            key = flow.source_param or f"param_{flow.source.value}"
            param_flows[key].append(flow)

        targets: list[MutationTarget] = []

        for param, pflows in param_flows.items():
            # Find most sensitive flow
            best = max(pflows, key=lambda f: self._sensitivity_score(f.sensitivity))

            # Collect mutations from source + sink
            mutations: list[str] = []
            for m in self.SOURCE_MUTATIONS.get(best.source, []):
                if m not in mutations:
                    mutations.append(m)
            for m in self.SINK_MUTATIONS.get(best.sink, []):
                if m not in mutations:
                    mutations.append(m)

            # Collect all reaching sinks
            sinks = list({f.sink for f in pflows})

            # Compute weight
            weight = self._compute_weight(pflows)

            targets.append(MutationTarget(
                parameter_name=param,
                sensitivity=best.sensitivity,
                recommended_mutations=mutations,
                reaching_sinks=sinks,
                weight=weight,
                soul_specific=any(f.soul_specific for f in pflows),
            ))

        # Sort by weight
        targets.sort(key=lambda t: t.weight, reverse=True)

        return targets

    def _sensitivity_score(self, s: TaintSensitivity) -> int:
        return {
            TaintSensitivity.CRITICAL: 4,
            TaintSensitivity.HIGH: 3,
            TaintSensitivity.MEDIUM: 2,
            TaintSensitivity.LOW: 1,
            TaintSensitivity.NONE: 0,
        }.get(s, 0)

    def _compute_weight(self, flows: list[TaintFlow]) -> float:
        """Compute mutation weight from taint flows."""
        weight = 0.0
        for f in flows:
            # Sensitivity contributes
            weight += self._sensitivity_score(f.sensitivity) * 2.0

            # Shorter paths are more actionable
            if f.path_length <= 3:
                weight += 1.5
            elif f.path_length <= 6:
                weight += 0.8

            # Soul-specific bonus
            if f.soul_specific:
                weight += 2.0

            # Critical sinks bonus
            if f.sink in (TaintSink.DELEGATECALL, TaintSink.SELFDESTRUCT):
                weight += 3.0
            elif f.sink in (TaintSink.ZK_VERIFY, TaintSink.BRIDGE_RELAY):
                weight += 2.5

        return round(weight, 3)


# ── Taint-Based Fuzzing Scheduler ────────────────────────────────────────────

class TaintFuzzScheduler:
    """Schedules fuzzing based on taint sensitivity weights."""

    def __init__(self, seed: int | None = None) -> None:
        self._rng = random.Random(seed)
        self._target_history: dict[str, int] = defaultdict(int)
        self._target_hits: dict[str, int] = defaultdict(int)

    def select_target(
        self,
        targets: list[MutationTarget],
    ) -> MutationTarget | None:
        """Select mutation target weighted by taint sensitivity."""
        if not targets:
            return None

        # Weight-based selection with exploration bonus
        weights: list[float] = []
        for t in targets:
            w = t.weight
            # Exploration: boost undersampled targets
            hits = self._target_history.get(t.parameter_name, 0)
            exploration_bonus = 1.0 / (1.0 + hits * 0.1)
            w *= exploration_bonus
            weights.append(max(w, 0.01))

        total = sum(weights)
        if total <= 0:
            return self._rng.choice(targets)

        normalized = [w / total for w in weights]
        target = self._rng.choices(targets, weights=normalized, k=1)[0]
        self._target_history[target.parameter_name] += 1

        return target

    def select_mutation(
        self,
        target: MutationTarget,
    ) -> str:
        """Select a specific mutation for the target."""
        if not target.recommended_mutations:
            return "random_byte_flip"

        return self._rng.choice(target.recommended_mutations)

    def record_hit(self, target_param: str, new_coverage: bool) -> None:
        """Record whether the target produced new coverage."""
        if new_coverage:
            self._target_hits[target_param] += 1

    def get_stats(self) -> dict[str, Any]:
        return {
            "target_selection_counts": dict(self._target_history),
            "target_coverage_hits": dict(self._target_hits),
            "total_selections": sum(self._target_history.values()),
            "coverage_hit_rate": (
                sum(self._target_hits.values()) /
                max(sum(self._target_history.values()), 1)
            ),
        }


# ── Main Taint-Guided Mutator ───────────────────────────────────────────────

class TaintGuidedMutator:
    """Complete taint-guided mutation engine.

    Analyzes dataflow from inputs to security-critical sinks, then
    focuses mutations on the most sensitive input parameters with
    appropriate mutation strategies.

    Usage:
        mutator = TaintGuidedMutator()
        result = mutator.analyze_function(
            function_name="withdraw",
            parameters=[
                {"name": "proof", "type": "bytes"},
                {"name": "nullifier", "type": "bytes32"},
                {"name": "recipient", "type": "address"},
                {"name": "amount", "type": "uint256"},
            ],
            has_payable=False,
            opcodes=[...],  # optional EVM opcode trace
        )
        # Get mutation targets
        targets = result.mutation_targets
        # Select target and mutation
        target = mutator.select_target(targets)
        mutation = mutator.select_mutation(target)
    """

    def __init__(self, seed: int | None = None) -> None:
        self._source_marker = TaintSourceMarker()
        self._propagation = TaintPropagationEngine()
        self._sink_detector = TaintSinkDetector()
        self._recommender = TaintMutationRecommender()
        self._scheduler = TaintFuzzScheduler(seed=seed)

    def analyze_function(
        self,
        function_name: str,
        parameters: list[dict[str, Any]],
        has_payable: bool = False,
        opcodes: list[dict[str, Any]] | None = None,
        storage_accesses: list[dict[str, Any]] | None = None,
        external_calls: list[dict[str, Any]] | None = None,
        contract_name: str = "",
    ) -> TaintAnalysisResult:
        """Analyze taint flows for a function."""
        start = time.time()
        result = TaintAnalysisResult(
            contract=contract_name,
            function=function_name,
        )

        # Step 1: Mark sources
        tainted_inputs = self._source_marker.mark_function_inputs(
            function_name, parameters, has_payable,
        )

        # Step 2: Compute flows (static approximation)
        flows = self._compute_flows(
            function_name=function_name,
            tainted_inputs=tainted_inputs,
            opcodes=opcodes or [],
            storage_accesses=storage_accesses or [],
            external_calls=external_calls or [],
            contract_name=contract_name,
        )

        # Step 3: Classify sensitivity
        for flow in flows:
            flow.sensitivity = self._sink_detector.classify_sensitivity(
                flow.source, flow.sink, flow.path_length,
            )

        result.flows = flows
        result.total_flows = len(flows)
        result.critical_paths = sum(
            1 for f in flows if f.sensitivity == TaintSensitivity.CRITICAL
        )
        result.high_paths = sum(
            1 for f in flows if f.sensitivity == TaintSensitivity.HIGH
        )

        # Step 4: Generate mutation targets
        result.mutation_targets = self._recommender.recommend_mutations(flows)

        result.analysis_time_sec = time.time() - start

        logger.info(
            "Taint analysis for %s.%s: %d flows (%d critical, %d high), "
            "%d mutation targets",
            contract_name, function_name, len(flows),
            result.critical_paths, result.high_paths,
            len(result.mutation_targets),
        )

        return result

    def _compute_flows(
        self,
        function_name: str,
        tainted_inputs: list[TaintedValue],
        opcodes: list[dict[str, Any]],
        storage_accesses: list[dict[str, Any]],
        external_calls: list[dict[str, Any]],
        contract_name: str,
    ) -> list[TaintFlow]:
        """Compute taint flows from inputs to sinks."""
        flows: list[TaintFlow] = []

        self._propagation.reset()

        # If we have opcodes, do fine-grained analysis
        if opcodes:
            flows.extend(self._opcode_level_flows(
                function_name, tainted_inputs, opcodes, contract_name,
            ))
        else:
            # Heuristic: infer flows from parameter types and function name
            flows.extend(self._heuristic_flows(
                function_name, tainted_inputs, storage_accesses,
                external_calls, contract_name,
            ))

        return flows

    def _opcode_level_flows(
        self,
        function_name: str,
        tainted_inputs: list[TaintedValue],
        opcodes: list[dict[str, Any]],
        contract_name: str,
    ) -> list[TaintFlow]:
        """Compute flows from opcode-level trace."""
        flows: list[TaintFlow] = []
        flow_counter = 0

        # Track tainted stack positions (simplified)
        taint_stack: list[list[TaintLabel]] = []

        for _idx, op in enumerate(opcodes):
            opname = op.get("op", "")

            # Check sink
            if any(taint_stack):
                flat_labels = [l for labels in taint_stack for l in labels]
                if flat_labels:
                    tainted_vals = [TaintedValue(labels=flat_labels)]
                    sink = self._sink_detector.detect_sink(
                        opname, tainted_vals, function_name,
                    )
                    if sink:
                        for label in flat_labels:
                            flow_counter += 1
                            flows.append(TaintFlow(
                                flow_id=f"flow-{flow_counter:04d}",
                                source=label.source,
                                sink=sink,
                                source_param=label.parameter_name,
                                sink_operation=opname,
                                propagation_path=label.propagation_chain,
                                path_length=label.generation,
                                soul_specific=self._is_soul_source(label.source),
                                contract=contract_name,
                                function=function_name,
                            ))

            # Propagate taint through stack operations
            if opname in ("ADD", "SUB", "MUL", "DIV", "MOD", "EXP"):
                if len(taint_stack) >= 2:
                    a = taint_stack.pop()
                    b = taint_stack.pop()
                    merged = self._propagation.propagate_arithmetic(
                        [TaintedValue(labels=a), TaintedValue(labels=b)]
                    )
                    taint_stack.append(merged)
            elif opname == "SHA3":
                if taint_stack:
                    top = taint_stack.pop()
                    derived = self._propagation.propagate_hash(
                        [TaintedValue(labels=top)]
                    )
                    taint_stack.append(derived)
            elif opname in ("EQ", "LT", "GT", "SLT", "SGT", "ISZERO"):
                if taint_stack:
                    top = taint_stack.pop()
                    derived = self._propagation.propagate_comparison(
                        [TaintedValue(labels=top)]
                    )
                    taint_stack.append(derived)
            elif opname == "CALLDATALOAD":
                # Load taint from input
                offset = op.get("value", 0)
                matching = [
                    tv for tv in tainted_inputs
                    if tv.location == "calldata" and
                    abs(tv.offset - offset) < 32
                ]
                if matching:
                    taint_stack.append(matching[0].labels[:])
                else:
                    taint_stack.append([])
            elif opname == "SSTORE":
                if len(taint_stack) >= 2:
                    slot_labels = taint_stack.pop()
                    value_labels = taint_stack.pop()
                    slot = op.get("slot", 0)
                    self._propagation.propagate_storage_write(
                        slot, value_labels,
                    )
            elif opname == "SLOAD":
                slot = op.get("slot", 0)
                labels = self._propagation.propagate_storage_read(slot)
                taint_stack.append(labels)
            else:
                # Default: push empty for unknown opcodes
                taint_stack.append([])

        return flows

    def _heuristic_flows(
        self,
        function_name: str,
        tainted_inputs: list[TaintedValue],
        storage_accesses: list[dict[str, Any]],
        external_calls: list[dict[str, Any]],
        contract_name: str,
    ) -> list[TaintFlow]:
        """Infer taint flows heuristically without opcodes."""
        flows: list[TaintFlow] = []
        flow_counter = 0

        # Soul Protocol function → expected sink patterns
        func_patterns: dict[str, list[tuple[TaintSource, TaintSink]]] = {
            "withdraw": [
                (TaintSource.PROOF_DATA, TaintSink.ZK_VERIFY),
                (TaintSource.NULLIFIER_INPUT, TaintSink.NULLIFIER_REGISTER),
                (TaintSource.MERKLE_PROOF, TaintSink.MERKLE_UPDATE),
                (TaintSource.MSG_VALUE, TaintSink.POOL_BALANCE_UPDATE),
                (TaintSource.CALLDATA, TaintSink.ETH_TRANSFER),
            ],
            "deposit": [
                (TaintSource.MSG_VALUE, TaintSink.POOL_BALANCE_UPDATE),
                (TaintSource.COMMITMENT_INPUT, TaintSink.COMMITMENT_INSERT),
                (TaintSource.CALLDATA, TaintSink.STORAGE_WRITE),
            ],
            "verify": [
                (TaintSource.PROOF_DATA, TaintSink.ZK_VERIFY),
                (TaintSource.PUBLIC_INPUTS, TaintSink.ZK_VERIFY),
            ],
            "verifyProof": [
                (TaintSource.PROOF_DATA, TaintSink.ZK_VERIFY),
                (TaintSource.PUBLIC_INPUTS, TaintSink.ZK_VERIFY),
            ],
            "relayProof": [
                (TaintSource.BRIDGE_MESSAGE, TaintSink.BRIDGE_RELAY),
                (TaintSource.CALLDATA, TaintSink.EXTERNAL_CALL),
            ],
            "registerNullifier": [
                (TaintSource.NULLIFIER_INPUT, TaintSink.NULLIFIER_REGISTER),
            ],
            "updateMerkleRoot": [
                (TaintSource.MERKLE_PROOF, TaintSink.MERKLE_UPDATE),
            ],
            "transfer": [
                (TaintSource.CALLDATA, TaintSink.STORAGE_WRITE),
                (TaintSource.MSG_SENDER, TaintSink.ACCESS_CHECK),
            ],
        }

        # Apply known patterns
        patterns = func_patterns.get(function_name, [])
        for source_type, sink_type in patterns:
            # Find matching input
            matching_inputs = [
                tv for tv in tainted_inputs
                if any(l.source == source_type for l in tv.labels)
            ]

            for tv in matching_inputs:
                for label in tv.labels:
                    if label.source == source_type:
                        flow_counter += 1
                        flows.append(TaintFlow(
                            flow_id=f"hflow-{flow_counter:04d}",
                            source=source_type,
                            sink=sink_type,
                            source_param=label.parameter_name,
                            sink_operation=function_name,
                            path_length=2,  # heuristic estimate
                            soul_specific=self._is_soul_source(source_type),
                            contract=contract_name,
                            function=function_name,
                        ))

        # Generic: every calldata input → storage write
        for tv in tainted_inputs:
            for label in tv.labels:
                if label.source == TaintSource.CALLDATA:
                    flow_counter += 1
                    flows.append(TaintFlow(
                        flow_id=f"hflow-{flow_counter:04d}",
                        source=TaintSource.CALLDATA,
                        sink=TaintSink.STORAGE_WRITE,
                        source_param=label.parameter_name,
                        sink_operation="sstore",
                        path_length=3,
                        soul_specific=False,
                        contract=contract_name,
                        function=function_name,
                    ))

        # External calls
        if external_calls:
            for tv in tainted_inputs:
                for label in tv.labels:
                    flow_counter += 1
                    flows.append(TaintFlow(
                        flow_id=f"hflow-{flow_counter:04d}",
                        source=label.source,
                        sink=TaintSink.EXTERNAL_CALL,
                        source_param=label.parameter_name,
                        sink_operation="call",
                        path_length=4,
                        soul_specific=self._is_soul_source(label.source),
                        contract=contract_name,
                        function=function_name,
                    ))

        return flows

    def _is_soul_source(self, source: TaintSource) -> bool:
        return source in (
            TaintSource.PROOF_DATA,
            TaintSource.NULLIFIER_INPUT,
            TaintSource.COMMITMENT_INPUT,
            TaintSource.MERKLE_PROOF,
            TaintSource.PUBLIC_INPUTS,
            TaintSource.BRIDGE_MESSAGE,
        )

    def select_target(
        self,
        targets: list[MutationTarget],
    ) -> MutationTarget | None:
        """Select a mutation target using taint-weighted scheduling."""
        return self._scheduler.select_target(targets)

    def select_mutation(self, target: MutationTarget) -> str:
        """Select a mutation for the given target."""
        return self._scheduler.select_mutation(target)

    def record_result(
        self, target_param: str, new_coverage: bool,
    ) -> None:
        """Record fuzzing result for adaptive scheduling."""
        self._scheduler.record_hit(target_param, new_coverage)

    def get_stats(self) -> dict[str, Any]:
        return self._scheduler.get_stats()
