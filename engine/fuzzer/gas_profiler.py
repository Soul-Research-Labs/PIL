"""Gas Profiler Engine — per-opcode gas accounting and DoS detection.

Profiles gas consumption at opcode, function, and contract level to
detect gas griefing vectors, unbounded loops, and worst-case gas
estimation for Soul Protocol operations.

Architecture:
  ┌──────────────────────────────────────────────────────────────────┐
  │                   GAS  PROFILER  ENGINE                         │
  │                                                                  │
  │  ┌──────────┐  ┌────────────┐  ┌──────────────┐  ┌──────────┐ │
  │  │Opcode    │─►│Function    │─►│Anomaly       │─►│DoS       │ │
  │  │Gas       │  │Gas         │  │Detector      │  │Vector    │ │
  │  │Counter   │  │Profiler    │  │              │  │Finder    │ │
  │  └──────────┘  └────────────┘  └──────────────┘  └──────────┘ │
  │       │              │               │                   │      │
  │       ▼              ▼               ▼                   ▼      │
  │  ┌──────────┐  ┌────────────┐  ┌──────────────┐  ┌──────────┐ │
  │  │Worst-Case│  │Gas         │  │Soul Protocol │  │Fuzz      │ │
  │  │Estimator │  │Heatmap     │  │Gas Patterns  │  │Targets   │ │
  │  │          │  │Generator   │  │              │  │          │ │
  │  └──────────┘  └────────────┘  └──────────────┘  └──────────┘ │
  │                                                                  │
  │  ┌──────────────────────────────────────────────────────────┐   │
  │  │ Soul Protocol Gas Patterns:                              │   │
  │  │   ZK verify: ~200K-500K gas (circuit dependent)          │   │
  │  │   Merkle insert: ~50K-200K gas (tree depth dependent)    │   │
  │  │   Nullifier check: ~20K-50K gas (set size dependent)     │   │
  │  │   Bridge relay: ~100K-300K gas (payload dependent)       │   │
  │  │   Privacy pool deposit: ~300K-800K gas                   │   │
  │  └──────────────────────────────────────────────────────────┘   │
  └──────────────────────────────────────────────────────────────────┘
"""

from __future__ import annotations

import logging
import math
import time
from collections import defaultdict
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

logger = logging.getLogger(__name__)


# ── Constants ────────────────────────────────────────────────────────────────

# Base gas costs per EVM opcode (Berlin/Shanghai)
OPCODE_GAS: dict[str, int] = {
    # Arithmetic
    "STOP": 0, "ADD": 3, "MUL": 5, "SUB": 3, "DIV": 5,
    "SDIV": 5, "MOD": 5, "SMOD": 5, "ADDMOD": 8, "MULMOD": 8,
    "EXP": 10, "SIGNEXTEND": 5,
    # Comparison
    "LT": 3, "GT": 3, "SLT": 3, "SGT": 3, "EQ": 3, "ISZERO": 3,
    # Bitwise
    "AND": 3, "OR": 3, "XOR": 3, "NOT": 3, "BYTE": 3,
    "SHL": 3, "SHR": 3, "SAR": 3,
    # Hash
    "SHA3": 30,  # + 6 per word
    # Environment
    "ADDRESS": 2, "BALANCE": 100, "ORIGIN": 2, "CALLER": 2,
    "CALLVALUE": 2, "CALLDATALOAD": 3, "CALLDATASIZE": 2,
    "CALLDATACOPY": 3, "CODESIZE": 2, "CODECOPY": 3,
    "GASPRICE": 2, "EXTCODESIZE": 100, "EXTCODECOPY": 100,
    "RETURNDATASIZE": 2, "RETURNDATACOPY": 3, "EXTCODEHASH": 100,
    # Block
    "BLOCKHASH": 20, "COINBASE": 2, "TIMESTAMP": 2,
    "NUMBER": 2, "DIFFICULTY": 2, "GASLIMIT": 2, "CHAINID": 2,
    "SELFBALANCE": 5, "BASEFEE": 2,
    # Stack
    "POP": 2, "MLOAD": 3, "MSTORE": 3, "MSTORE8": 3,
    # Storage
    "SLOAD": 100,      # warm: 100, cold: 2100
    "SSTORE": 100,     # varies: 100-20000
    # Jump
    "JUMP": 8, "JUMPI": 10, "PC": 2, "MSIZE": 2, "GAS": 2,
    "JUMPDEST": 1,
    # Push/Dup/Swap
    **{f"PUSH{i}": 3 for i in range(1, 33)},
    **{f"DUP{i}": 3 for i in range(1, 17)},
    **{f"SWAP{i}": 3 for i in range(1, 17)},
    # Log
    "LOG0": 375, "LOG1": 750, "LOG2": 1125, "LOG3": 1500, "LOG4": 1875,
    # System
    "CREATE": 32000, "CALL": 100, "CALLCODE": 100,
    "RETURN": 0, "DELEGATECALL": 100, "CREATE2": 32000,
    "STATICCALL": 100, "REVERT": 0, "INVALID": 0, "SELFDESTRUCT": 5000,
}

# Additional costs for specific operations
COLD_SLOAD_COST = 2100
WARM_SLOAD_COST = 100
SSTORE_SET_COST = 20000      # 0 → non-zero
SSTORE_RESET_COST = 2900     # non-zero → non-zero
SSTORE_CLEAR_REFUND = 4800   # non-zero → 0 refund
CALL_VALUE_COST = 9000       # extra for non-zero value
CALL_NEW_ACCOUNT_COST = 25000
MEMORY_COST_PER_WORD = 3
LOG_DATA_COST_PER_BYTE = 8
LOG_TOPIC_COST = 375
SHA3_WORD_COST = 6


# ── Enums ────────────────────────────────────────────────────────────────────

class GasAnomaly(Enum):
    """Types of gas anomalies detected."""
    UNBOUNDED_LOOP = "unbounded_loop"
    QUADRATIC_GROWTH = "quadratic_growth"
    EXCESSIVE_STORAGE = "excessive_storage"
    COLD_STORAGE_FLOOD = "cold_storage_flood"
    MEMORY_EXPANSION = "memory_expansion"
    LOG_SPAM = "log_spam"
    EXTERNAL_CALL_CHAIN = "external_call_chain"
    CREATE_IN_LOOP = "create_in_loop"
    HASH_FLOOD = "hash_flood"
    DEEP_RECURSION = "deep_recursion"
    # Soul-specific
    ZK_VERIFY_REPEATED = "zk_verify_repeated"
    MERKLE_DEPTH_EXPLOIT = "merkle_depth_exploit"
    NULLIFIER_SET_GROWTH = "nullifier_set_growth"
    BRIDGE_PAYLOAD_BLOAT = "bridge_payload_bloat"


class GasSeverity(Enum):
    """Severity of gas issues."""
    CRITICAL = "critical"  # DoS: reverts at block gas limit
    HIGH = "high"          # Near block gas limit
    MEDIUM = "medium"      # Significantly above average
    LOW = "low"            # Slightly elevated
    INFO = "info"          # Informational


# ── Data Classes ─────────────────────────────────────────────────────────────

@dataclass
class OpcodeGasProfile:
    """Gas profile for a single opcode execution."""
    opcode: str = ""
    base_cost: int = 0
    dynamic_cost: int = 0  # memory expansion, storage cold/warm, etc.
    total_cost: int = 0
    pc: int = 0            # program counter
    depth: int = 0         # call depth


@dataclass
class FunctionGasProfile:
    """Aggregated gas profile for a function."""
    function_name: str = ""
    selector: str = ""
    total_gas: int = 0
    min_gas: int = 0
    max_gas: int = 0
    avg_gas: float = 0.0
    stddev_gas: float = 0.0
    sample_count: int = 0

    # Breakdown
    computation_gas: int = 0     # arithmetic, logic, stack ops
    storage_gas: int = 0         # SLOAD, SSTORE
    memory_gas: int = 0          # MEM expansion
    external_call_gas: int = 0   # CALL, DELEGATECALL, STATICCALL
    log_gas: int = 0             # LOG0-LOG4
    hash_gas: int = 0            # SHA3
    create_gas: int = 0          # CREATE, CREATE2

    # Anomalies
    anomalies: list[GasAnomaly] = field(default_factory=list)

    # Soul-specific
    zk_verify_gas: int = 0
    merkle_ops_gas: int = 0
    nullifier_ops_gas: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "function": self.function_name,
            "selector": self.selector,
            "gas_stats": {
                "total": self.total_gas,
                "min": self.min_gas,
                "max": self.max_gas,
                "avg": round(self.avg_gas, 1),
                "stddev": round(self.stddev_gas, 1),
                "samples": self.sample_count,
            },
            "breakdown": {
                "computation": self.computation_gas,
                "storage": self.storage_gas,
                "memory": self.memory_gas,
                "external_calls": self.external_call_gas,
                "logs": self.log_gas,
                "hashing": self.hash_gas,
                "create": self.create_gas,
            },
            "soul_specific": {
                "zk_verify": self.zk_verify_gas,
                "merkle_ops": self.merkle_ops_gas,
                "nullifier_ops": self.nullifier_ops_gas,
            },
            "anomalies": [a.value for a in self.anomalies],
        }


@dataclass
class GasHotspot:
    """A gas-intensive code region."""
    pc_start: int = 0
    pc_end: int = 0
    gas_consumed: int = 0
    gas_percentage: float = 0.0
    opcode_sequence: list[str] = field(default_factory=list)
    description: str = ""
    anomaly: GasAnomaly | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "pc_range": f"0x{self.pc_start:04x}-0x{self.pc_end:04x}",
            "gas": self.gas_consumed,
            "percentage": round(self.gas_percentage, 1),
            "opcodes": self.opcode_sequence[:10],
            "description": self.description,
            "anomaly": self.anomaly.value if self.anomaly else None,
        }


@dataclass
class DoSVector:
    """A potential denial-of-service vector."""
    id: str = ""
    anomaly: GasAnomaly = GasAnomaly.UNBOUNDED_LOOP
    severity: GasSeverity = GasSeverity.MEDIUM
    description: str = ""
    function: str = ""
    worst_case_gas: int = 0
    block_gas_limit: int = 30_000_000
    block_utilization: float = 0.0
    trigger_input: str = ""
    mitigation: str = ""
    soul_specific: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "anomaly": self.anomaly.value,
            "severity": self.severity.value,
            "description": self.description,
            "function": self.function,
            "worst_case_gas": self.worst_case_gas,
            "block_utilization": round(self.block_utilization * 100, 1),
            "trigger": self.trigger_input[:100],
            "mitigation": self.mitigation,
            "soul_specific": self.soul_specific,
        }


@dataclass
class GasProfileResult:
    """Complete gas profiling result."""
    contract: str = ""
    function_profiles: list[FunctionGasProfile] = field(default_factory=list)
    hotspots: list[GasHotspot] = field(default_factory=list)
    dos_vectors: list[DoSVector] = field(default_factory=list)
    total_gas_sampled: int = 0
    profiling_time_sec: float = 0.0

    # Summary stats
    max_function_gas: int = 0
    avg_function_gas: float = 0.0
    most_expensive_function: str = ""
    gas_by_category: dict[str, int] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "contract": self.contract,
            "functions": [fp.to_dict() for fp in self.function_profiles],
            "hotspots": [h.to_dict() for h in self.hotspots[:20]],
            "dos_vectors": [d.to_dict() for d in self.dos_vectors],
            "summary": {
                "total_gas_sampled": self.total_gas_sampled,
                "max_function_gas": self.max_function_gas,
                "avg_function_gas": round(self.avg_function_gas, 1),
                "most_expensive": self.most_expensive_function,
                "gas_by_category": self.gas_by_category,
                "dos_vector_count": len(self.dos_vectors),
                "critical_dos": sum(
                    1 for d in self.dos_vectors
                    if d.severity == GasSeverity.CRITICAL
                ),
            },
            "profiling_time_sec": round(self.profiling_time_sec, 3),
        }


# ── Opcode Gas Counter ──────────────────────────────────────────────────────

class OpcodeGasCounter:
    """Count gas consumption per opcode with dynamic cost modeling."""

    def __init__(self) -> None:
        self._warm_slots: set[int] = set()
        self._memory_size: int = 0

    def compute_gas(
        self,
        opcode: str,
        context: dict[str, Any] | None = None,
    ) -> OpcodeGasProfile:
        """Compute gas cost for a single opcode execution."""
        ctx = context or {}

        base = OPCODE_GAS.get(opcode, 3)
        dynamic = 0

        # Dynamic costs
        if opcode == "SLOAD":
            slot = ctx.get("slot", 0)
            if slot in self._warm_slots:
                base = WARM_SLOAD_COST
            else:
                base = COLD_SLOAD_COST
                self._warm_slots.add(slot)

        elif opcode == "SSTORE":
            slot = ctx.get("slot", 0)
            old_val = ctx.get("old_value", 0)
            new_val = ctx.get("new_value", 1)

            if slot not in self._warm_slots:
                dynamic += COLD_SLOAD_COST
                self._warm_slots.add(slot)

            if old_val == 0 and new_val != 0:
                base = SSTORE_SET_COST
            elif old_val != 0 and new_val != 0:
                base = SSTORE_RESET_COST
            elif old_val != 0 and new_val == 0:
                base = SSTORE_RESET_COST  # refund handled separately

        elif opcode == "SHA3":
            data_size = ctx.get("size", 32)
            words = (data_size + 31) // 32
            dynamic += words * SHA3_WORD_COST

        elif opcode in ("CALL", "DELEGATECALL", "STATICCALL"):
            if slot := ctx.get("target_address"):
                if slot not in self._warm_slots:
                    dynamic += 2500  # cold account access
                    self._warm_slots.add(slot)
            value = ctx.get("value", 0)
            if value > 0:
                dynamic += CALL_VALUE_COST

        elif opcode in ("LOG0", "LOG1", "LOG2", "LOG3", "LOG4"):
            data_size = ctx.get("data_size", 0)
            dynamic += data_size * LOG_DATA_COST_PER_BYTE

        elif opcode in ("MLOAD", "MSTORE"):
            offset = ctx.get("offset", 0)
            new_size = offset + 32
            if new_size > self._memory_size:
                old_cost = self._memory_cost(self._memory_size)
                new_cost = self._memory_cost(new_size)
                dynamic += new_cost - old_cost
                self._memory_size = new_size

        elif opcode == "EXP":
            exponent = ctx.get("exponent", 1)
            if exponent > 0:
                exp_bytes = (exponent.bit_length() + 7) // 8
                dynamic += 50 * exp_bytes

        return OpcodeGasProfile(
            opcode=opcode,
            base_cost=base,
            dynamic_cost=dynamic,
            total_cost=base + dynamic,
            pc=ctx.get("pc", 0),
            depth=ctx.get("depth", 0),
        )

    def _memory_cost(self, size: int) -> int:
        """Calculate memory expansion cost."""
        if size == 0:
            return 0
        words = (size + 31) // 32
        return (words * MEMORY_COST_PER_WORD) + (words * words // 512)

    def reset(self) -> None:
        self._warm_slots.clear()
        self._memory_size = 0


# ── Function Gas Profiler ────────────────────────────────────────────────────

class FunctionGasProfiler:
    """Profile gas at the function level from execution traces."""

    def __init__(self) -> None:
        self._counter = OpcodeGasCounter()
        self._samples: dict[str, list[int]] = defaultdict(list)
        self._breakdowns: dict[str, dict[str, int]] = defaultdict(
            lambda: defaultdict(int)
        )

    def profile_trace(
        self,
        function_name: str,
        opcodes: list[dict[str, Any]],
        selector: str = "",
    ) -> FunctionGasProfile:
        """Profile a single function execution trace."""
        self._counter.reset()

        total_gas = 0
        breakdown: dict[str, int] = defaultdict(int)
        hotspot_regions: list[tuple[int, int, int]] = []  # (start, end, gas)
        region_start = 0
        region_gas = 0

        soul_gas = {"zk_verify": 0, "merkle": 0, "nullifier": 0}

        for idx, op in enumerate(opcodes):
            opname = op.get("op", "INVALID")
            profile = self._counter.compute_gas(opname, op)
            total_gas += profile.total_cost

            # Categorize
            cat = self._categorize_opcode(opname)
            breakdown[cat] += profile.total_cost

            # Detect Soul-specific gas patterns
            if opname in ("CALL", "STATICCALL"):
                func = op.get("callee_function", "")
                if "verify" in func.lower() or "proof" in func.lower():
                    soul_gas["zk_verify"] += profile.total_cost
                elif "merkle" in func.lower() or "tree" in func.lower():
                    soul_gas["merkle"] += profile.total_cost
                elif "nullifier" in func.lower():
                    soul_gas["nullifier"] += profile.total_cost

            # Track hotspot regions
            region_gas += profile.total_cost
            if idx > 0 and idx % 50 == 0:
                hotspot_regions.append((region_start, idx, region_gas))
                region_start = idx
                region_gas = 0

        # Record sample
        self._samples[function_name].append(total_gas)
        for cat, gas in breakdown.items():
            self._breakdowns[function_name][cat] += gas

        # Build profile
        samples = self._samples[function_name]
        avg = sum(samples) / len(samples)
        variance = sum((s - avg) ** 2 for s in samples) / max(len(samples), 1)
        stddev = math.sqrt(variance)

        fp = FunctionGasProfile(
            function_name=function_name,
            selector=selector,
            total_gas=total_gas,
            min_gas=min(samples),
            max_gas=max(samples),
            avg_gas=avg,
            stddev_gas=stddev,
            sample_count=len(samples),
            computation_gas=breakdown.get("computation", 0),
            storage_gas=breakdown.get("storage", 0),
            memory_gas=breakdown.get("memory", 0),
            external_call_gas=breakdown.get("external_call", 0),
            log_gas=breakdown.get("log", 0),
            hash_gas=breakdown.get("hash", 0),
            create_gas=breakdown.get("create", 0),
            zk_verify_gas=soul_gas["zk_verify"],
            merkle_ops_gas=soul_gas["merkle"],
            nullifier_ops_gas=soul_gas["nullifier"],
        )

        return fp

    def _categorize_opcode(self, opcode: str) -> str:
        if opcode in ("SLOAD", "SSTORE"):
            return "storage"
        if opcode in ("MLOAD", "MSTORE", "MSTORE8", "MSIZE"):
            return "memory"
        if opcode in ("CALL", "DELEGATECALL", "STATICCALL", "CALLCODE"):
            return "external_call"
        if opcode in ("LOG0", "LOG1", "LOG2", "LOG3", "LOG4"):
            return "log"
        if opcode == "SHA3":
            return "hash"
        if opcode in ("CREATE", "CREATE2"):
            return "create"
        return "computation"


# ── Gas Anomaly Detector ─────────────────────────────────────────────────────

class GasAnomalyDetector:
    """Detect gas anomalies in execution traces."""

    def __init__(
        self,
        block_gas_limit: int = 30_000_000,
    ) -> None:
        self._block_gas_limit = block_gas_limit

    def detect_anomalies(
        self,
        function_name: str,
        opcodes: list[dict[str, Any]],
        gas_profile: FunctionGasProfile,
    ) -> list[DoSVector]:
        """Detect gas anomalies and DoS vectors."""
        vectors: list[DoSVector] = []
        counter = 0

        # 1. Unbounded loop detection
        loop_vectors = self._detect_unbounded_loops(
            function_name, opcodes, gas_profile,
        )
        for v in loop_vectors:
            counter += 1
            v.id = f"DOS-{counter:03d}"
        vectors.extend(loop_vectors)

        # 2. Excessive storage access
        storage_vectors = self._detect_storage_issues(
            function_name, opcodes, gas_profile,
        )
        for v in storage_vectors:
            counter += 1
            v.id = f"DOS-{counter:03d}"
        vectors.extend(storage_vectors)

        # 3. Memory expansion issues
        mem_vectors = self._detect_memory_issues(
            function_name, opcodes, gas_profile,
        )
        for v in mem_vectors:
            counter += 1
            v.id = f"DOS-{counter:03d}"
        vectors.extend(mem_vectors)

        # 4. External call chains
        call_vectors = self._detect_call_chain_issues(
            function_name, opcodes, gas_profile,
        )
        for v in call_vectors:
            counter += 1
            v.id = f"DOS-{counter:03d}"
        vectors.extend(call_vectors)

        # 5. Soul-specific gas patterns
        soul_vectors = self._detect_soul_gas_patterns(
            function_name, opcodes, gas_profile,
        )
        for v in soul_vectors:
            counter += 1
            v.id = f"DOS-{counter:03d}"
        vectors.extend(soul_vectors)

        return vectors

    def _detect_unbounded_loops(
        self,
        function_name: str,
        opcodes: list[dict[str, Any]],
        profile: FunctionGasProfile,
    ) -> list[DoSVector]:
        vectors: list[DoSVector] = []

        # Count backwards jumps (loop indicators)
        back_jumps = 0
        sstore_in_loop = 0
        last_jumpdest = 0

        for op in opcodes:
            opname = op.get("op", "")
            pc = op.get("pc", 0)

            if opname == "JUMPDEST":
                last_jumpdest = pc
            elif opname == "JUMP" or opname == "JUMPI":
                target = op.get("target", 0)
                if target <= pc:  # backward jump = loop
                    back_jumps += 1
            elif opname == "SSTORE" and back_jumps > 0:
                sstore_in_loop += 1

        if back_jumps > 10:
            severity = GasSeverity.CRITICAL if back_jumps > 50 else GasSeverity.HIGH
            worst_case = profile.total_gas * (back_jumps // 10)

            vectors.append(DoSVector(
                anomaly=GasAnomaly.UNBOUNDED_LOOP,
                severity=severity,
                description=(
                    f"Function {function_name} contains {back_jumps} backward jumps "
                    f"indicating loops. {sstore_in_loop} SSTORE ops in loop body."
                ),
                function=function_name,
                worst_case_gas=worst_case,
                block_gas_limit=self._block_gas_limit,
                block_utilization=worst_case / self._block_gas_limit,
                mitigation="Add loop bounds or use pagination patterns",
            ))

        if sstore_in_loop > 5:
            vectors.append(DoSVector(
                anomaly=GasAnomaly.EXCESSIVE_STORAGE,
                severity=GasSeverity.HIGH,
                description=(
                    f"{sstore_in_loop} storage writes inside loops in {function_name}. "
                    f"Each SSTORE costs up to 20,000 gas."
                ),
                function=function_name,
                worst_case_gas=sstore_in_loop * SSTORE_SET_COST,
                block_gas_limit=self._block_gas_limit,
                block_utilization=(sstore_in_loop * SSTORE_SET_COST) / self._block_gas_limit,
                mitigation="Batch storage writes or use mapping patterns",
            ))

        return vectors

    def _detect_storage_issues(
        self,
        function_name: str,
        opcodes: list[dict[str, Any]],
        profile: FunctionGasProfile,
    ) -> list[DoSVector]:
        vectors: list[DoSVector] = []

        sload_count = sum(1 for op in opcodes if op.get("op") == "SLOAD")
        sstore_count = sum(1 for op in opcodes if op.get("op") == "SSTORE")
        unique_slots: set[int] = set()

        for op in opcodes:
            if op.get("op") in ("SLOAD", "SSTORE"):
                slot = op.get("slot", 0)
                unique_slots.add(slot)

        cold_accesses = len(unique_slots)

        if cold_accesses > 50:
            worst_case = cold_accesses * COLD_SLOAD_COST
            vectors.append(DoSVector(
                anomaly=GasAnomaly.COLD_STORAGE_FLOOD,
                severity=GasSeverity.HIGH if cold_accesses > 100 else GasSeverity.MEDIUM,
                description=(
                    f"{function_name} accesses {cold_accesses} unique storage slots. "
                    f"Cold access costs {COLD_SLOAD_COST} gas each. "
                    f"Total: {sload_count} SLOADs + {sstore_count} SSTOREs."
                ),
                function=function_name,
                worst_case_gas=worst_case,
                block_gas_limit=self._block_gas_limit,
                block_utilization=worst_case / self._block_gas_limit,
                mitigation="Pack related storage variables, use memory caching",
            ))

        return vectors

    def _detect_memory_issues(
        self,
        function_name: str,
        opcodes: list[dict[str, Any]],
        profile: FunctionGasProfile,
    ) -> list[DoSVector]:
        vectors: list[DoSVector] = []

        max_offset = 0
        for op in opcodes:
            if op.get("op") in ("MSTORE", "MLOAD"):
                offset = op.get("offset", 0)
                if offset > max_offset:
                    max_offset = offset

        if max_offset > 10000:
            words = (max_offset + 31) // 32
            expansion_cost = (words * MEMORY_COST_PER_WORD) + (words * words // 512)

            severity = GasSeverity.HIGH if expansion_cost > 100000 else GasSeverity.MEDIUM
            vectors.append(DoSVector(
                anomaly=GasAnomaly.MEMORY_EXPANSION,
                severity=severity,
                description=(
                    f"{function_name} expands memory to {max_offset} bytes "
                    f"({words} words). Quadratic memory cost: {expansion_cost} gas."
                ),
                function=function_name,
                worst_case_gas=expansion_cost,
                block_gas_limit=self._block_gas_limit,
                block_utilization=expansion_cost / self._block_gas_limit,
                mitigation="Limit memory allocation, use bounded arrays",
            ))

        return vectors

    def _detect_call_chain_issues(
        self,
        function_name: str,
        opcodes: list[dict[str, Any]],
        profile: FunctionGasProfile,
    ) -> list[DoSVector]:
        vectors: list[DoSVector] = []

        call_count = sum(
            1 for op in opcodes
            if op.get("op") in ("CALL", "DELEGATECALL", "STATICCALL")
        )

        if call_count > 10:
            worst_case = call_count * 2600  # cold account access per call
            vectors.append(DoSVector(
                anomaly=GasAnomaly.EXTERNAL_CALL_CHAIN,
                severity=GasSeverity.MEDIUM,
                description=(
                    f"{function_name} makes {call_count} external calls. "
                    f"Each cold call costs at least 2,600 gas."
                ),
                function=function_name,
                worst_case_gas=worst_case,
                block_gas_limit=self._block_gas_limit,
                block_utilization=worst_case / self._block_gas_limit,
                mitigation="Minimize external calls, use batch patterns",
            ))

        return vectors

    def _detect_soul_gas_patterns(
        self,
        function_name: str,
        opcodes: list[dict[str, Any]],
        profile: FunctionGasProfile,
    ) -> list[DoSVector]:
        """Detect Soul Protocol specific gas patterns."""
        vectors: list[DoSVector] = []

        # ZK verify repeated calls
        if profile.zk_verify_gas > 500000:
            vectors.append(DoSVector(
                anomaly=GasAnomaly.ZK_VERIFY_REPEATED,
                severity=GasSeverity.HIGH,
                description=(
                    f"ZK verification in {function_name} costs {profile.zk_verify_gas} gas. "
                    f"Multiple verifications could exceed block limit."
                ),
                function=function_name,
                worst_case_gas=profile.zk_verify_gas * 3,  # assume 3x worst case
                block_gas_limit=self._block_gas_limit,
                block_utilization=(profile.zk_verify_gas * 3) / self._block_gas_limit,
                mitigation="Batch verify proofs, use proof aggregation",
                soul_specific=True,
            ))

        # Merkle tree depth
        if profile.merkle_ops_gas > 200000:
            vectors.append(DoSVector(
                anomaly=GasAnomaly.MERKLE_DEPTH_EXPLOIT,
                severity=GasSeverity.MEDIUM,
                description=(
                    f"Merkle operations in {function_name} cost {profile.merkle_ops_gas} gas. "
                    f"Deep trees or many operations increase cost."
                ),
                function=function_name,
                worst_case_gas=profile.merkle_ops_gas * 2,
                block_gas_limit=self._block_gas_limit,
                block_utilization=(profile.merkle_ops_gas * 2) / self._block_gas_limit,
                mitigation="Limit tree depth, use sparse Merkle trees",
                soul_specific=True,
            ))

        # Nullifier set growth
        if profile.nullifier_ops_gas > 100000:
            vectors.append(DoSVector(
                anomaly=GasAnomaly.NULLIFIER_SET_GROWTH,
                severity=GasSeverity.MEDIUM,
                description=(
                    f"Nullifier operations in {function_name} cost {profile.nullifier_ops_gas} gas. "
                    f"Unbounded set growth increases lookup cost."
                ),
                function=function_name,
                worst_case_gas=profile.nullifier_ops_gas * 5,
                block_gas_limit=self._block_gas_limit,
                block_utilization=(profile.nullifier_ops_gas * 5) / self._block_gas_limit,
                mitigation="Use mapping-based nullifier storage O(1) lookup",
                soul_specific=True,
            ))

        return vectors


# ── Gas Heatmap Generator ────────────────────────────────────────────────────

class GasHeatmapGenerator:
    """Generates a gas heatmap across bytecode regions."""

    def generate(
        self,
        opcodes: list[dict[str, Any]],
        bucket_size: int = 32,
    ) -> list[GasHotspot]:
        """Generate gas hotspots from an opcode trace."""
        counter = OpcodeGasCounter()
        buckets: dict[int, int] = defaultdict(int)
        bucket_opcodes: dict[int, list[str]] = defaultdict(list)
        total_gas = 0

        for op in opcodes:
            opname = op.get("op", "INVALID")
            pc = op.get("pc", 0)
            profile = counter.compute_gas(opname, op)

            bucket_idx = pc // bucket_size
            buckets[bucket_idx] += profile.total_cost
            bucket_opcodes[bucket_idx].append(opname)
            total_gas += profile.total_cost

        hotspots: list[GasHotspot] = []
        for bucket_idx, gas in sorted(buckets.items(), key=lambda x: -x[1]):
            if gas == 0:
                continue

            pc_start = bucket_idx * bucket_size
            pc_end = pc_start + bucket_size - 1
            percentage = (gas / max(total_gas, 1)) * 100

            # Detect anomaly type
            opcodes_in_bucket = bucket_opcodes[bucket_idx]
            anomaly = self._detect_bucket_anomaly(opcodes_in_bucket, gas)

            hotspots.append(GasHotspot(
                pc_start=pc_start,
                pc_end=pc_end,
                gas_consumed=gas,
                gas_percentage=percentage,
                opcode_sequence=opcodes_in_bucket[:10],
                description=self._describe_bucket(opcodes_in_bucket, gas),
                anomaly=anomaly,
            ))

        return hotspots[:50]  # Top 50 hotspots

    def _detect_bucket_anomaly(
        self, opcodes: list[str], gas: int,
    ) -> GasAnomaly | None:
        sstore_count = opcodes.count("SSTORE")
        if sstore_count > 3:
            return GasAnomaly.EXCESSIVE_STORAGE

        sha3_count = opcodes.count("SHA3")
        if sha3_count > 5:
            return GasAnomaly.HASH_FLOOD

        call_count = sum(1 for o in opcodes if o in ("CALL", "DELEGATECALL"))
        if call_count > 3:
            return GasAnomaly.EXTERNAL_CALL_CHAIN

        return None

    def _describe_bucket(self, opcodes: list[str], gas: int) -> str:
        top_ops = defaultdict(int)
        for op in opcodes:
            top_ops[op] += 1
        sorted_ops = sorted(top_ops.items(), key=lambda x: -x[1])[:3]
        op_str = ", ".join(f"{op}×{c}" for op, c in sorted_ops)
        return f"{gas} gas — dominant: {op_str}"


# ── Main Gas Profiler Engine ─────────────────────────────────────────────────

class GasProfilerEngine:
    """Complete gas profiling engine.

    Profiles gas consumption at opcode, function, and contract level.
    Detects gas griefing vectors, unbounded loops, and worst-case
    gas estimation for Soul Protocol operations.

    Usage:
        profiler = GasProfilerEngine()
        result = profiler.profile(
            contract_name="PrivacyPool",
            traces=[
                {
                    "function": "withdraw",
                    "selector": "0x2e1a7d4d",
                    "opcodes": [...],
                },
            ],
        )
    """

    def __init__(
        self,
        block_gas_limit: int = 30_000_000,
    ) -> None:
        self._func_profiler = FunctionGasProfiler()
        self._anomaly_detector = GasAnomalyDetector(block_gas_limit)
        self._heatmap_gen = GasHeatmapGenerator()
        self._block_gas_limit = block_gas_limit

    def profile(
        self,
        contract_name: str = "",
        traces: list[dict[str, Any]] | None = None,
    ) -> GasProfileResult:
        """Profile gas for a contract from execution traces."""
        start = time.time()
        result = GasProfileResult(contract=contract_name)

        if not traces:
            return result

        all_hotspots: list[GasHotspot] = []

        for trace in traces:
            func = trace.get("function", "unknown")
            selector = trace.get("selector", "")
            opcodes = trace.get("opcodes", [])

            if not opcodes:
                continue

            # Profile function
            fp = self._func_profiler.profile_trace(func, opcodes, selector)

            # Detect anomalies
            dos_vectors = self._anomaly_detector.detect_anomalies(
                func, opcodes, fp,
            )
            fp.anomalies = [v.anomaly for v in dos_vectors]

            result.function_profiles.append(fp)
            result.dos_vectors.extend(dos_vectors)
            result.total_gas_sampled += fp.total_gas

            # Generate hotspots
            hotspots = self._heatmap_gen.generate(opcodes)
            all_hotspots.extend(hotspots)

        # Summarize
        if result.function_profiles:
            max_fp = max(result.function_profiles, key=lambda f: f.total_gas)
            result.max_function_gas = max_fp.total_gas
            result.most_expensive_function = max_fp.function_name
            result.avg_function_gas = (
                sum(fp.total_gas for fp in result.function_profiles) /
                len(result.function_profiles)
            )

            # Category breakdown
            cats: dict[str, int] = defaultdict(int)
            for fp in result.function_profiles:
                cats["computation"] += fp.computation_gas
                cats["storage"] += fp.storage_gas
                cats["memory"] += fp.memory_gas
                cats["external_calls"] += fp.external_call_gas
                cats["logs"] += fp.log_gas
                cats["hashing"] += fp.hash_gas
                cats["zk_verify"] += fp.zk_verify_gas
                cats["merkle_ops"] += fp.merkle_ops_gas
            result.gas_by_category = dict(cats)

        # Sort hotspots by gas
        all_hotspots.sort(key=lambda h: -h.gas_consumed)
        result.hotspots = all_hotspots[:50]

        # Sort DoS vectors by severity
        severity_order = {
            GasSeverity.CRITICAL: 0,
            GasSeverity.HIGH: 1,
            GasSeverity.MEDIUM: 2,
            GasSeverity.LOW: 3,
            GasSeverity.INFO: 4,
        }
        result.dos_vectors.sort(
            key=lambda v: severity_order.get(v.severity, 5)
        )

        result.profiling_time_sec = time.time() - start

        logger.info(
            "Gas profiling complete for %s: %d functions, %d DoS vectors, %.1fs",
            contract_name,
            len(result.function_profiles),
            len(result.dos_vectors),
            result.profiling_time_sec,
        )

        return result

    def estimate_worst_case(
        self,
        function_name: str,
        base_gas: int,
        loop_bound: int = 100,
        storage_writes: int = 10,
    ) -> dict[str, Any]:
        """Estimate worst-case gas for a function given parameters."""
        loop_gas = base_gas * loop_bound
        storage_gas = storage_writes * SSTORE_SET_COST
        total = loop_gas + storage_gas
        utilization = total / self._block_gas_limit

        return {
            "function": function_name,
            "base_gas": base_gas,
            "loop_bound": loop_bound,
            "storage_writes": storage_writes,
            "worst_case_gas": total,
            "block_utilization": round(utilization * 100, 1),
            "fits_in_block": total < self._block_gas_limit,
            "severity": (
                "critical" if utilization > 1.0 else
                "high" if utilization > 0.5 else
                "medium" if utilization > 0.1 else
                "low"
            ),
        }

    def get_fuzz_targets(
        self,
        result: GasProfileResult,
    ) -> list[dict[str, Any]]:
        """Extract fuzz targets from gas profiling to drive the fuzzer."""
        targets: list[dict[str, Any]] = []

        # Functions with anomalies
        for fp in result.function_profiles:
            if fp.anomalies:
                targets.append({
                    "function": fp.function_name,
                    "selector": fp.selector,
                    "reason": f"Gas anomalies: {', '.join(a.value for a in fp.anomalies)}",
                    "priority": "high" if any(
                        a in (GasAnomaly.UNBOUNDED_LOOP, GasAnomaly.QUADRATIC_GROWTH)
                        for a in fp.anomalies
                    ) else "medium",
                    "strategy": "maximize_gas",
                    "current_max_gas": fp.max_gas,
                })

        # DoS vectors
        for dos in result.dos_vectors:
            targets.append({
                "function": dos.function,
                "reason": f"DoS vector: {dos.description[:100]}",
                "priority": dos.severity.value,
                "strategy": "trigger_dos",
                "worst_case_gas": dos.worst_case_gas,
                "soul_specific": dos.soul_specific,
            })

        return targets
