"""EVM Bytecode Analyzer — deep opcode-level analysis for Soul Protocol.

Disassembles EVM bytecode, extracts opcode patterns, identifies storage
layout from runtime code, detects delegate-call targets, maps jump
destinations, and feeds coverage-guided fuzzing at the bytecode level.

Architecture:
  ┌──────────────────────────────────────────────────────────────────┐
  │                    BYTECODE  ANALYZER                           │
  │                                                                  │
  │  ┌──────────┐  ┌────────────┐  ┌──────────────┐  ┌──────────┐ │
  │  │Disasm    │─►│Opcode CFG  │─►│Storage       │─►│Coverage  │ │
  │  │Engine    │  │Builder     │  │Layout        │  │Bitmap    │ │
  │  │          │  │            │  │Extractor     │  │Generator │ │
  │  └──────────┘  └────────────┘  └──────────────┘  └──────────┘ │
  │       │              │               │                   │      │
  │       ▼              ▼               ▼                   ▼      │
  │  ┌──────────┐  ┌────────────┐  ┌──────────────┐  ┌──────────┐ │
  │  │Selector  │  │DelegateCall│  │Immutables    │  │Opcode    │ │
  │  │Extractor │  │Detector    │  │Scanner       │  │Frequency │ │
  │  │          │  │            │  │              │  │Profiler  │ │
  │  └──────────┘  └────────────┘  └──────────────┘  └──────────┘ │
  │                                                                  │
  │  ┌──────────────────────────────────────────────────────────┐   │
  │  │ Soul Protocol Pattern Library (ZK-verify, nullifier,     │   │
  │  │ privacy-router, state-container, bridge relay patterns)  │   │
  │  └──────────────────────────────────────────────────────────┘   │
  └──────────────────────────────────────────────────────────────────┘
"""

from __future__ import annotations

import hashlib
import logging
import re
import struct
from collections import defaultdict
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

logger = logging.getLogger(__name__)


# ── EVM Opcode Table ─────────────────────────────────────────────────────────

class Opcode(Enum):
    """EVM opcodes relevant to security analysis."""
    STOP = 0x00
    ADD = 0x01
    MUL = 0x02
    SUB = 0x03
    DIV = 0x04
    SDIV = 0x05
    MOD = 0x06
    SMOD = 0x07
    ADDMOD = 0x08
    MULMOD = 0x09
    EXP = 0x0A
    SIGNEXTEND = 0x0B
    LT = 0x10
    GT = 0x11
    SLT = 0x12
    SGT = 0x13
    EQ = 0x14
    ISZERO = 0x15
    AND = 0x16
    OR = 0x17
    XOR = 0x18
    NOT = 0x19
    BYTE = 0x1A
    SHL = 0x1B
    SHR = 0x1C
    SAR = 0x1D
    SHA3 = 0x20
    ADDRESS = 0x30
    BALANCE = 0x31
    ORIGIN = 0x32
    CALLER = 0x33
    CALLVALUE = 0x34
    CALLDATALOAD = 0x35
    CALLDATASIZE = 0x36
    CALLDATACOPY = 0x37
    CODESIZE = 0x38
    CODECOPY = 0x39
    GASPRICE = 0x3A
    EXTCODESIZE = 0x3B
    EXTCODECOPY = 0x3C
    RETURNDATASIZE = 0x3D
    RETURNDATACOPY = 0x3E
    EXTCODEHASH = 0x3F
    BLOCKHASH = 0x40
    COINBASE = 0x41
    TIMESTAMP = 0x42
    NUMBER = 0x43
    DIFFICULTY = 0x44
    GASLIMIT = 0x45
    CHAINID = 0x46
    SELFBALANCE = 0x47
    BASEFEE = 0x48
    POP = 0x50
    MLOAD = 0x51
    MSTORE = 0x52
    MSTORE8 = 0x53
    SLOAD = 0x54
    SSTORE = 0x55
    JUMP = 0x56
    JUMPI = 0x57
    PC = 0x58
    MSIZE = 0x59
    GAS = 0x5A
    JUMPDEST = 0x5B
    PUSH0 = 0x5F
    # PUSH1..PUSH32
    PUSH1 = 0x60
    PUSH2 = 0x61
    PUSH3 = 0x62
    PUSH4 = 0x63
    PUSH32 = 0x7F
    # DUP1..DUP16
    DUP1 = 0x80
    DUP16 = 0x8F
    # SWAP1..SWAP16
    SWAP1 = 0x90
    SWAP16 = 0x9F
    # LOG0..LOG4
    LOG0 = 0xA0
    LOG4 = 0xA4
    CREATE = 0xF0
    CALL = 0xF1
    CALLCODE = 0xF2
    RETURN = 0xF3
    DELEGATECALL = 0xF4
    CREATE2 = 0xF5
    STATICCALL = 0xFA
    REVERT = 0xFD
    INVALID = 0xFE
    SELFDESTRUCT = 0xFF


# Opcode name mapping for all 256 possible byte values
OPCODE_NAMES: dict[int, str] = {}
for _op in Opcode:
    OPCODE_NAMES[_op.value] = _op.name
# Fill PUSH range
for _i in range(0x60, 0x80):
    OPCODE_NAMES[_i] = f"PUSH{_i - 0x5F}"
# Fill DUP range
for _i in range(0x80, 0x90):
    OPCODE_NAMES[_i] = f"DUP{_i - 0x7F}"
# Fill SWAP range
for _i in range(0x90, 0xA0):
    OPCODE_NAMES[_i] = f"SWAP{_i - 0x8F}"
# Fill LOG range
for _i in range(0xA0, 0xA5):
    OPCODE_NAMES[_i] = f"LOG{_i - 0xA0}"


# ── Data Classes ─────────────────────────────────────────────────────────────

class BasicBlockType(Enum):
    """Classification of basic blocks in CFG."""
    NORMAL = "normal"
    JUMPDEST = "jumpdest"
    DISPATCHER = "dispatcher"
    FUNCTION_ENTRY = "function_entry"
    MODIFIER_CHECK = "modifier_check"
    REVERT_HANDLER = "revert_handler"
    FALLBACK = "fallback"
    RECEIVE = "receive"
    SELECTOR_SWITCH = "selector_switch"
    ZK_VERIFY_BLOCK = "zk_verify_block"
    STORAGE_GUARD = "storage_guard"
    REENTRANCY_LOCK = "reentrancy_lock"


@dataclass
class DisassembledInstruction:
    """A single disassembled EVM instruction."""
    offset: int
    opcode: int
    opcode_name: str
    operand: bytes = b""
    operand_value: int = 0
    size: int = 1  # instruction size in bytes

    @property
    def is_push(self) -> bool:
        return 0x60 <= self.opcode <= 0x7F or self.opcode == 0x5F

    @property
    def is_jump(self) -> bool:
        return self.opcode in (0x56, 0x57)

    @property
    def is_call(self) -> bool:
        return self.opcode in (0xF1, 0xF2, 0xF4, 0xFA)

    @property
    def is_storage(self) -> bool:
        return self.opcode in (0x54, 0x55)

    @property
    def is_terminator(self) -> bool:
        return self.opcode in (0x00, 0x56, 0x57, 0xF3, 0xFD, 0xFE, 0xFF)

    def __repr__(self) -> str:
        if self.operand:
            return f"{self.offset:#06x}: {self.opcode_name} 0x{self.operand.hex()}"
        return f"{self.offset:#06x}: {self.opcode_name}"


@dataclass
class BasicBlock:
    """A basic block in the control-flow graph."""
    start_offset: int
    end_offset: int
    instructions: list[DisassembledInstruction] = field(default_factory=list)
    successors: list[int] = field(default_factory=list)  # offsets
    predecessors: list[int] = field(default_factory=list)  # offsets
    block_type: BasicBlockType = BasicBlockType.NORMAL
    function_selector: str = ""
    is_reachable: bool = True

    @property
    def id(self) -> str:
        return f"bb_{self.start_offset:#06x}"

    @property
    def instruction_count(self) -> int:
        return len(self.instructions)

    @property
    def has_external_call(self) -> bool:
        return any(i.is_call for i in self.instructions)

    @property
    def has_storage_access(self) -> bool:
        return any(i.is_storage for i in self.instructions)

    @property
    def has_delegatecall(self) -> bool:
        return any(i.opcode == Opcode.DELEGATECALL.value for i in self.instructions)


@dataclass
class StorageSlot:
    """Extracted storage slot information."""
    slot: int
    slot_hex: str
    access_type: str  # "read", "write", "both"
    accessed_by: list[str] = field(default_factory=list)  # function selectors
    possible_type: str = "unknown"
    is_mapping: bool = False
    mapping_key_type: str = ""
    is_packed: bool = False
    byte_offset: int = 0
    byte_size: int = 32


@dataclass
class FunctionSignature:
    """Extracted function signature from bytecode."""
    selector: str  # 4-byte hex
    offset: int  # JUMPDEST offset
    name: str = ""  # resolved name if available
    is_payable: bool = False
    has_delegatecall: bool = False
    storage_reads: list[int] = field(default_factory=list)
    storage_writes: list[int] = field(default_factory=list)
    external_calls: int = 0
    static_calls: int = 0
    estimated_gas: int = 0
    revert_conditions: int = 0
    soul_pattern: str = ""  # Soul-specific pattern identified


@dataclass
class DelegateCallTarget:
    """Detected delegate call target."""
    caller_offset: int
    target_type: str  # "constant", "storage", "calldata", "computed"
    target_value: str = ""  # resolved target if constant
    storage_slot: int = -1  # storage slot if target is from storage
    risk_level: str = "high"


@dataclass
class BytecodeAnalysisResult:
    """Complete result of bytecode analysis."""
    # Basics
    bytecode_hash: str = ""
    bytecode_size: int = 0
    instruction_count: int = 0

    # Disassembly
    instructions: list[DisassembledInstruction] = field(default_factory=list)

    # CFG
    basic_blocks: list[BasicBlock] = field(default_factory=list)
    block_count: int = 0
    edge_count: int = 0
    cyclomatic_complexity: int = 0

    # Functions
    function_signatures: list[FunctionSignature] = field(default_factory=list)
    has_fallback: bool = False
    has_receive: bool = False

    # Storage
    storage_slots: list[StorageSlot] = field(default_factory=list)
    storage_slot_count: int = 0

    # Security
    delegate_call_targets: list[DelegateCallTarget] = field(default_factory=list)
    selfdestruct_reachable: bool = False
    has_create2: bool = False
    unchecked_calls: int = 0
    reentrancy_guards: int = 0

    # Opcode statistics
    opcode_frequency: dict[str, int] = field(default_factory=dict)
    opcode_categories: dict[str, int] = field(default_factory=dict)

    # Soul-specific
    soul_patterns: dict[str, list[str]] = field(default_factory=dict)
    zk_verify_blocks: list[int] = field(default_factory=list)
    nullifier_check_blocks: list[int] = field(default_factory=list)
    privacy_router_patterns: list[dict[str, Any]] = field(default_factory=list)

    # Coverage guidance
    coverage_bitmap_size: int = 0
    jump_targets: set[int] = field(default_factory=set)
    conditional_jumps: list[tuple[int, int, int]] = field(default_factory=list)  # (offset, true_target, false_target)

    # Fuzz targets
    fuzz_recommendations: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """Serialize analysis result."""
        return {
            "bytecode_hash": self.bytecode_hash,
            "bytecode_size": self.bytecode_size,
            "instruction_count": self.instruction_count,
            "block_count": self.block_count,
            "edge_count": self.edge_count,
            "cyclomatic_complexity": self.cyclomatic_complexity,
            "function_count": len(self.function_signatures),
            "functions": [
                {
                    "selector": f.selector,
                    "name": f.name,
                    "offset": f.offset,
                    "is_payable": f.is_payable,
                    "has_delegatecall": f.has_delegatecall,
                    "storage_reads": f.storage_reads,
                    "storage_writes": f.storage_writes,
                    "external_calls": f.external_calls,
                    "revert_conditions": f.revert_conditions,
                    "estimated_gas": f.estimated_gas,
                    "soul_pattern": f.soul_pattern,
                }
                for f in self.function_signatures
            ],
            "storage_slots": [
                {
                    "slot": s.slot,
                    "slot_hex": s.slot_hex,
                    "access_type": s.access_type,
                    "possible_type": s.possible_type,
                    "is_mapping": s.is_mapping,
                    "accessed_by": s.accessed_by,
                }
                for s in self.storage_slots
            ],
            "delegate_calls": [
                {
                    "offset": d.caller_offset,
                    "target_type": d.target_type,
                    "target_value": d.target_value,
                    "risk_level": d.risk_level,
                }
                for d in self.delegate_call_targets
            ],
            "security": {
                "selfdestruct_reachable": self.selfdestruct_reachable,
                "has_create2": self.has_create2,
                "unchecked_calls": self.unchecked_calls,
                "reentrancy_guards": self.reentrancy_guards,
                "delegate_call_count": len(self.delegate_call_targets),
            },
            "opcode_categories": self.opcode_categories,
            "soul_patterns": self.soul_patterns,
            "zk_verify_blocks": self.zk_verify_blocks,
            "nullifier_check_blocks": self.nullifier_check_blocks,
            "coverage_bitmap_size": self.coverage_bitmap_size,
            "conditional_jumps": len(self.conditional_jumps),
            "fuzz_recommendations": self.fuzz_recommendations,
        }


# ── Soul Protocol Bytecode Patterns ─────────────────────────────────────────

# Known function selectors for Soul Protocol contracts
SOUL_SELECTORS: dict[str, str] = {
    # ConfidentialStateContainer
    "0xa6f9dae1": "createLock(bytes32,bytes32,address,uint256)",
    "0x6198e339": "unlock(bytes32,bytes,bytes32[])",
    "0xe8a3d485": "cancelLock(bytes32)",
    "0x4a4e9d86": "batchExecute(bytes32[],bytes[],bytes32[][])",
    # NullifierRegistry
    "0x98d5fdca": "registerNullifier(bytes32,bytes32)",
    "0x7c025200": "isNullifierUsed(bytes32)",
    "0xd0e30db0": "batchRegister(bytes32[],bytes32[])",
    "0x3ccfd60b": "verifyNullifierDomain(bytes32,bytes32)",
    # PrivacyRouter
    "0xd0e30db0": "deposit(bytes,bytes32,bytes32[])",
    "0x3ccfd60b": "withdraw(bytes,bytes32,address,uint256)",
    "0xa9059cbb": "crossChainTransfer(uint256,bytes,bytes32)",
    "0x23b872dd": "stealthSend(address,bytes,bytes32)",
    # SoulProtocolHub
    "0x4420e486": "registerModule(string,address,bytes)",
    "0x23b872dd": "executeTransaction(bytes32,bytes)",
    "0xf2fde38b": "upgradeModule(string,address)",
    # ZK Verifiers
    "0xaf640d0f": "verify(uint256[2],uint256[2][2],uint256[2],uint256[])",
    "0x695ef6f9": "verifyProof(bytes,uint256[])",
    "0x8e760afe": "verifyBatch(bytes[],uint256[][])",
    # Bridge
    "0x40c10f19": "relayProof(uint256,bytes32,bytes)",
    "0xa9059cbb": "initiateTransfer(uint256,address,uint256,bytes)",
    "0x150b7a02": "finalizeTransfer(uint256,bytes32,bytes)",
    "0xd09de08a": "claimTimeout(uint256,bytes32)",
}

# Known event signatures for Soul Protocol
SOUL_EVENT_SIGS: dict[str, str] = {
    "0x7b0820cb": "LockCreated(bytes32,address,bytes32)",
    "0xf6391f5c": "LockUnlocked(bytes32,bytes)",
    "0x8c5be1e5": "NullifierRegistered(bytes32,bytes32)",
    "0xd78ad95f": "Deposit(address,uint256,bytes32)",
    "0x7c025200": "Withdrawal(address,uint256,bytes32)",
    "0xddf252ad": "Transfer(address,address,uint256)",
    "0xe8d23d0c": "ProofVerified(bytes32,address)",
    "0x3b0820cb": "ModuleRegistered(string,address)",
    "0x6b0820cb": "CrossChainTransfer(uint256,bytes32,uint256)",
    "0x8b0820cb": "CircuitBreakerTriggered(address,uint256)",
}

# Opcode patterns that indicate Soul-specific constructs
SOUL_BYTECODE_PATTERNS = {
    # ZK proof verification: typically involves ecPairing precompile (0x08)
    "zk_verify": [
        [0x60, 0x08, 0xFA],  # PUSH1 0x08 STATICCALL (bn128 pairing)
        [0x61, None, None, 0xFA],  # PUSH2 addr STATICCALL
        [0x60, 0x06, 0xFA],  # PUSH1 0x06 STATICCALL (bn128 add)
        [0x60, 0x07, 0xFA],  # PUSH1 0x07 STATICCALL (bn128 mul)
    ],
    # Nullifier registry pattern: SLOAD check + SSTORE
    "nullifier_check": [
        [0x54, 0x15, 0x57],  # SLOAD ISZERO JUMPI (check not used)
        [0x54, 0x14, 0x57],  # SLOAD EQ JUMPI
    ],
    # Reentrancy guard: SLOAD check 1, SSTORE 2
    "reentrancy_guard": [
        [0x54, 0x60, 0x01, 0x14, 0x57],  # SLOAD PUSH1 1 EQ JUMPI
        [0x60, 0x02, 0x55],  # PUSH1 2 SSTORE (lock)
        [0x60, 0x01, 0x55],  # PUSH1 1 SSTORE (unlock)
    ],
    # Ownable pattern: CALLER SLOAD EQ
    "access_control": [
        [0x33, 0x54, 0x14, 0x57],  # CALLER SLOAD EQ JUMPI
        [0x33, 0x73, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, 0x14, 0x57],
    ],
    # Merkle tree pattern: SHA3 in loop with JUMPI back
    "merkle_tree": [
        [0x20, 0x90, 0x57],  # SHA3 SWAP1 JUMPI  (hash-and-branch)
    ],
    # Bridge message encoding: ABI encode with chain ID
    "bridge_message": [
        [0x46, 0x52],  # CHAINID MSTORE
    ],
}


# ── Disassembly Engine ───────────────────────────────────────────────────────

class EVMDisassembler:
    """Disassembles EVM bytecode into structured instructions."""

    def disassemble(self, bytecode: bytes) -> list[DisassembledInstruction]:
        """Disassemble raw bytecode into instructions."""
        instructions: list[DisassembledInstruction] = []
        i = 0

        while i < len(bytecode):
            opcode = bytecode[i]
            name = OPCODE_NAMES.get(opcode, f"UNKNOWN_0x{opcode:02x}")

            if 0x60 <= opcode <= 0x7F:
                # PUSH1 .. PUSH32
                n_bytes = opcode - 0x5F
                operand = bytecode[i + 1: i + 1 + n_bytes]
                operand_value = int.from_bytes(operand, "big") if operand else 0
                inst = DisassembledInstruction(
                    offset=i,
                    opcode=opcode,
                    opcode_name=name,
                    operand=operand,
                    operand_value=operand_value,
                    size=1 + n_bytes,
                )
                instructions.append(inst)
                i += 1 + n_bytes
            elif opcode == 0x5F:
                # PUSH0
                inst = DisassembledInstruction(
                    offset=i,
                    opcode=opcode,
                    opcode_name="PUSH0",
                    operand_value=0,
                )
                instructions.append(inst)
                i += 1
            else:
                inst = DisassembledInstruction(
                    offset=i,
                    opcode=opcode,
                    opcode_name=name,
                )
                instructions.append(inst)
                i += 1

        return instructions


# ── Control Flow Graph Builder ───────────────────────────────────────────────

class CFGBuilder:
    """Builds control-flow graph from disassembled instructions."""

    def build(
        self, instructions: list[DisassembledInstruction],
    ) -> list[BasicBlock]:
        """Build basic blocks and connect CFG edges."""
        if not instructions:
            return []

        # 1. Identify basic block boundaries
        leaders: set[int] = {0}  # First instruction is always a leader
        jumpdests: set[int] = set()

        for i, inst in enumerate(instructions):
            if inst.opcode == Opcode.JUMPDEST.value:
                leaders.add(inst.offset)
                jumpdests.add(inst.offset)
            if inst.is_terminator:
                # Next instruction (if exists) is a leader
                next_offset = inst.offset + inst.size
                if next_offset < instructions[-1].offset + instructions[-1].size:
                    leaders.add(next_offset)
                # For JUMPI, the target is a leader
                if inst.opcode == Opcode.JUMPI.value:
                    # Look for preceding PUSH
                    if i > 0 and instructions[i - 1].is_push:
                        target = instructions[i - 1].operand_value
                        leaders.add(target)
                elif inst.opcode == Opcode.JUMP.value:
                    if i > 0 and instructions[i - 1].is_push:
                        target = instructions[i - 1].operand_value
                        leaders.add(target)

        # 2. Build basic blocks
        sorted_leaders = sorted(leaders)
        blocks: dict[int, BasicBlock] = {}
        inst_map: dict[int, DisassembledInstruction] = {
            inst.offset: inst for inst in instructions
        }

        for idx, leader in enumerate(sorted_leaders):
            end = sorted_leaders[idx + 1] if idx + 1 < len(sorted_leaders) else (
                instructions[-1].offset + instructions[-1].size
            )
            block_insts = [
                inst for inst in instructions
                if leader <= inst.offset < end
            ]
            if block_insts:
                block = BasicBlock(
                    start_offset=leader,
                    end_offset=end,
                    instructions=block_insts,
                    block_type=(
                        BasicBlockType.JUMPDEST if leader in jumpdests
                        else BasicBlockType.NORMAL
                    ),
                )
                blocks[leader] = block

        # 3. Connect edges
        for offset, block in blocks.items():
            if not block.instructions:
                continue

            last = block.instructions[-1]

            if last.opcode == Opcode.JUMP.value:
                # Unconditional jump — look at preceding PUSH
                for inst in reversed(block.instructions[:-1]):
                    if inst.is_push:
                        target = inst.operand_value
                        if target in blocks:
                            block.successors.append(target)
                            blocks[target].predecessors.append(offset)
                        break

            elif last.opcode == Opcode.JUMPI.value:
                # Conditional jump
                fall_through = last.offset + last.size
                if fall_through in blocks:
                    block.successors.append(fall_through)
                    blocks[fall_through].predecessors.append(offset)

                for inst in reversed(block.instructions[:-1]):
                    if inst.is_push:
                        target = inst.operand_value
                        if target in blocks:
                            block.successors.append(target)
                            blocks[target].predecessors.append(offset)
                        break

            elif last.opcode in (
                Opcode.STOP.value, Opcode.RETURN.value,
                Opcode.REVERT.value, Opcode.INVALID.value,
                Opcode.SELFDESTRUCT.value,
            ):
                pass  # Terminal — no successors

            else:
                # Fall through
                fall_through = last.offset + last.size
                if fall_through in blocks:
                    block.successors.append(fall_through)
                    blocks[fall_through].predecessors.append(offset)

        return list(blocks.values())


# ── Storage Layout Extractor ─────────────────────────────────────────────────

class StorageLayoutExtractor:
    """Extracts storage layout from bytecode patterns."""

    def extract(
        self,
        instructions: list[DisassembledInstruction],
        function_sigs: list[FunctionSignature],
    ) -> list[StorageSlot]:
        """Extract storage slots accessed by the contract."""
        slots: dict[int, StorageSlot] = {}

        for i, inst in enumerate(instructions):
            if inst.opcode == Opcode.SLOAD.value:
                slot = self._resolve_slot(instructions, i)
                if slot is not None:
                    if slot not in slots:
                        slots[slot] = StorageSlot(
                            slot=slot,
                            slot_hex=f"0x{slot:064x}",
                            access_type="read",
                        )
                    elif slots[slot].access_type == "write":
                        slots[slot].access_type = "both"
                    self._determine_type(instructions, i, slots[slot])

            elif inst.opcode == Opcode.SSTORE.value:
                slot = self._resolve_slot(instructions, i)
                if slot is not None:
                    if slot not in slots:
                        slots[slot] = StorageSlot(
                            slot=slot,
                            slot_hex=f"0x{slot:064x}",
                            access_type="write",
                        )
                    elif slots[slot].access_type == "read":
                        slots[slot].access_type = "both"

        # Map slots to functions
        for sig in function_sigs:
            for slot_id in sig.storage_reads:
                if slot_id in slots:
                    slots[slot_id].accessed_by.append(sig.selector)
            for slot_id in sig.storage_writes:
                if slot_id in slots:
                    slots[slot_id].accessed_by.append(sig.selector)

        return list(slots.values())

    def _resolve_slot(
        self,
        instructions: list[DisassembledInstruction],
        sload_index: int,
    ) -> int | None:
        """Try to resolve the storage slot for SLOAD/SSTORE."""
        # Look backwards for a PUSH that feeds the slot
        for j in range(sload_index - 1, max(sload_index - 5, -1), -1):
            if j < 0:
                break
            inst = instructions[j]
            if inst.is_push and inst.operand_value < 2**16:
                return inst.operand_value
            if inst.opcode == Opcode.SHA3.value:
                # Mapping access — slot is computed from keccak256
                return None  # Dynamic slot
            if inst.opcode == Opcode.ADD.value:
                # Possible packed storage or array access
                for k in range(j - 1, max(j - 3, -1), -1):
                    if k < 0:
                        break
                    if instructions[k].is_push and instructions[k].operand_value < 2**16:
                        return instructions[k].operand_value
                return None
        return None

    def _determine_type(
        self,
        instructions: list[DisassembledInstruction],
        sload_index: int,
        slot: StorageSlot,
    ) -> None:
        """Try to determine the type stored in a slot."""
        # Look at operations after SLOAD
        for j in range(sload_index + 1, min(sload_index + 6, len(instructions))):
            inst = instructions[j]

            # address type: AND with 0xFF..FF (20 bytes)
            if inst.opcode == Opcode.AND.value:
                for k in range(j - 1, max(j - 3, -1), -1):
                    if instructions[k].is_push:
                        val = instructions[k].operand_value
                        if val == (2**160 - 1):
                            slot.possible_type = "address"
                            return
                        if val == 0xFF:
                            slot.possible_type = "uint8"
                            slot.is_packed = True
                            return
                        if val == 0xFFFF:
                            slot.possible_type = "uint16"
                            slot.is_packed = True
                            return

            # bool: ISZERO
            if inst.opcode == Opcode.ISZERO.value:
                slot.possible_type = "bool"
                return

            # SHA3 after SLOAD suggests mapping
            if inst.opcode == Opcode.SHA3.value:
                slot.is_mapping = True
                slot.possible_type = "mapping"
                return


# ── Function Selector Extractor ──────────────────────────────────────────────

class SelectorExtractor:
    """Extracts function selectors from the dispatcher."""

    def extract(
        self,
        instructions: list[DisassembledInstruction],
        blocks: list[BasicBlock],
    ) -> list[FunctionSignature]:
        """Extract function selectors from bytecode dispatcher."""
        signatures: list[FunctionSignature] = []
        seen_selectors: set[str] = set()

        # Pattern: PUSH4 <selector> EQ PUSH2 <offset> JUMPI
        for i in range(len(instructions) - 4):
            inst = instructions[i]

            if inst.opcode == Opcode.PUSH4.value:
                selector_hex = f"0x{inst.operand.hex()}"

                if selector_hex in seen_selectors:
                    continue

                # Check next instructions for EQ + JUMPI pattern
                remaining = instructions[i + 1: i + 5]
                eq_found = False
                target_offset = 0

                for r_inst in remaining:
                    if r_inst.opcode == Opcode.EQ.value:
                        eq_found = True
                    if eq_found and r_inst.is_push:
                        target_offset = r_inst.operand_value
                        break

                if eq_found and target_offset > 0:
                    seen_selectors.add(selector_hex)
                    name = SOUL_SELECTORS.get(selector_hex, "")

                    sig = FunctionSignature(
                        selector=selector_hex,
                        offset=target_offset,
                        name=name,
                    )

                    # Analyze the function body
                    self._analyze_function_body(
                        sig, instructions, blocks, target_offset,
                    )

                    signatures.append(sig)

        return signatures

    def _analyze_function_body(
        self,
        sig: FunctionSignature,
        instructions: list[DisassembledInstruction],
        blocks: list[BasicBlock],
        entry_offset: int,
    ) -> None:
        """Analyze function body for security-relevant patterns."""
        # Find all instructions reachable from entry
        body_insts: list[DisassembledInstruction] = []
        in_body = False

        for inst in instructions:
            if inst.offset == entry_offset:
                in_body = True
            if in_body:
                body_insts.append(inst)
                if len(body_insts) > 500:
                    break
                if inst.opcode in (
                    Opcode.STOP.value, Opcode.RETURN.value,
                    Opcode.REVERT.value,
                ):
                    break

        # Payable check: CALLVALUE early
        for inst in body_insts[:20]:
            if inst.opcode == Opcode.CALLVALUE.value:
                # Check if there's an ISZERO + JUMPI after (non-payable)
                following = body_insts[body_insts.index(inst): body_insts.index(inst) + 5]
                has_revert = any(
                    f.opcode == Opcode.ISZERO.value for f in following
                )
                sig.is_payable = not has_revert
                break

        # Count storage accesses
        for inst in body_insts:
            if inst.opcode == Opcode.SLOAD.value:
                sig.storage_reads.append(inst.offset)
            elif inst.opcode == Opcode.SSTORE.value:
                sig.storage_writes.append(inst.offset)
            elif inst.opcode == Opcode.CALL.value:
                sig.external_calls += 1
            elif inst.opcode == Opcode.STATICCALL.value:
                sig.static_calls += 1
            elif inst.opcode == Opcode.DELEGATECALL.value:
                sig.has_delegatecall = True
            elif inst.opcode == Opcode.REVERT.value:
                sig.revert_conditions += 1

        # Gas estimate (rough: sum of basic gas costs)
        gas = 0
        for inst in body_insts:
            if inst.opcode == Opcode.SLOAD.value:
                gas += 2100
            elif inst.opcode == Opcode.SSTORE.value:
                gas += 5000
            elif inst.is_call:
                gas += 2600
            elif inst.opcode == Opcode.SHA3.value:
                gas += 30
            else:
                gas += 3
        sig.estimated_gas = gas

        # Soul pattern identification
        sig.soul_pattern = self._identify_soul_pattern(body_insts)

    def _identify_soul_pattern(
        self, body_insts: list[DisassembledInstruction],
    ) -> str:
        """Identify Soul Protocol-specific patterns in function body."""
        opcodes = [inst.opcode for inst in body_insts]

        # ZK verify pattern: STATICCALL to precompile 0x06/0x07/0x08
        for i, inst in enumerate(body_insts):
            if inst.opcode == Opcode.STATICCALL.value:
                # Check if target is precompile
                for j in range(max(0, i - 5), i):
                    if body_insts[j].is_push and body_insts[j].operand_value in (6, 7, 8):
                        return "zk_verify"

        # Nullifier pattern: SLOAD + check + SSTORE
        has_sload = Opcode.SLOAD.value in opcodes
        has_sstore = Opcode.SSTORE.value in opcodes
        has_sha3 = Opcode.SHA3.value in opcodes

        if has_sload and has_sstore and has_sha3:
            # Could be nullifier registration
            sload_count = opcodes.count(Opcode.SLOAD.value)
            sstore_count = opcodes.count(Opcode.SSTORE.value)
            if sload_count >= 1 and sstore_count == 1 and has_sha3:
                return "nullifier_registry"

        # Bridge relay: CHAINID usage
        if Opcode.CHAINID.value in opcodes:
            if Opcode.CALL.value in opcodes or Opcode.STATICCALL.value in opcodes:
                return "bridge_relay"

        # Delegatecall pattern: upgradeable proxy
        if Opcode.DELEGATECALL.value in opcodes:
            return "proxy_delegate"

        # Privacy router: multiple external calls + SHA3
        call_count = opcodes.count(Opcode.CALL.value) + opcodes.count(Opcode.STATICCALL.value)
        if call_count >= 3 and has_sha3:
            return "privacy_router"

        # State container: heavy storage usage
        if opcodes.count(Opcode.SSTORE.value) >= 3:
            return "state_container"

        return ""


# ── Delegate Call Detector ───────────────────────────────────────────────────

class DelegateCallDetector:
    """Detects and analyzes delegate call usage."""

    def detect(
        self, instructions: list[DisassembledInstruction],
    ) -> list[DelegateCallTarget]:
        """Find all delegate call instances and analyze targets."""
        targets: list[DelegateCallTarget] = []

        for i, inst in enumerate(instructions):
            if inst.opcode != Opcode.DELEGATECALL.value:
                continue

            target = self._resolve_target(instructions, i)
            targets.append(target)

        return targets

    def _resolve_target(
        self,
        instructions: list[DisassembledInstruction],
        delegatecall_index: int,
    ) -> DelegateCallTarget:
        """Resolve the target of a delegatecall."""
        # The target address is the 2nd stack item for DELEGATECALL
        # Look backwards for the address source
        for j in range(delegatecall_index - 1, max(delegatecall_index - 20, -1), -1):
            inst = instructions[j]

            if inst.is_push and inst.opcode >= Opcode.PUSH4.value:
                # Constant address
                return DelegateCallTarget(
                    caller_offset=instructions[delegatecall_index].offset,
                    target_type="constant",
                    target_value=f"0x{inst.operand.hex()}",
                    risk_level="medium",
                )

            if inst.opcode == Opcode.SLOAD.value:
                # Target from storage (upgradeable proxy pattern)
                slot = None
                for k in range(j - 1, max(j - 5, -1), -1):
                    if instructions[k].is_push:
                        slot = instructions[k].operand_value
                        break

                return DelegateCallTarget(
                    caller_offset=instructions[delegatecall_index].offset,
                    target_type="storage",
                    storage_slot=slot if slot is not None else -1,
                    risk_level="high",
                )

            if inst.opcode == Opcode.CALLDATALOAD.value:
                # Target from calldata — very dangerous
                return DelegateCallTarget(
                    caller_offset=instructions[delegatecall_index].offset,
                    target_type="calldata",
                    risk_level="critical",
                )

        return DelegateCallTarget(
            caller_offset=instructions[delegatecall_index].offset,
            target_type="computed",
            risk_level="high",
        )


# ── Pattern Matcher ──────────────────────────────────────────────────────────

class SoulPatternMatcher:
    """Matches Soul Protocol-specific bytecode patterns."""

    def match_all(
        self,
        instructions: list[DisassembledInstruction],
        blocks: list[BasicBlock],
    ) -> dict[str, list[dict[str, Any]]]:
        """Find all Soul-specific patterns in bytecode."""
        results: dict[str, list[dict[str, Any]]] = defaultdict(list)

        opcodes = [inst.opcode for inst in instructions]
        offsets = [inst.offset for inst in instructions]

        for pattern_name, pattern_variants in SOUL_BYTECODE_PATTERNS.items():
            for variant in pattern_variants:
                matches = self._find_pattern(opcodes, offsets, variant)
                for match_offset in matches:
                    results[pattern_name].append({
                        "offset": match_offset,
                        "pattern": pattern_name,
                        "variant_length": len(variant),
                    })

        # Classify blocks based on patterns
        for block in blocks:
            block_opcodes = [inst.opcode for inst in block.instructions]

            if any(inst.opcode == Opcode.STATICCALL.value for inst in block.instructions):
                # Check if calling precompile
                for inst in block.instructions:
                    if inst.is_push and inst.operand_value in (6, 7, 8):
                        block.block_type = BasicBlockType.ZK_VERIFY_BLOCK
                        results["zk_verify_blocks"].append({
                            "block": block.start_offset,
                        })
                        break

            if Opcode.SLOAD.value in block_opcodes and Opcode.SSTORE.value in block_opcodes:
                # Storage guard pattern
                sload_idx = block_opcodes.index(Opcode.SLOAD.value)
                if sload_idx < len(block_opcodes) - 2:
                    following = block_opcodes[sload_idx + 1: sload_idx + 4]
                    if Opcode.ISZERO.value in following or Opcode.EQ.value in following:
                        if Opcode.JUMPI.value in block_opcodes[sload_idx:]:
                            block.block_type = BasicBlockType.STORAGE_GUARD

        return dict(results)

    def _find_pattern(
        self,
        opcodes: list[int],
        offsets: list[int],
        pattern: list[int | None],
    ) -> list[int]:
        """Find pattern matches in opcode sequence. None = wildcard."""
        matches: list[int] = []
        pattern_len = len(pattern)

        for i in range(len(opcodes) - pattern_len + 1):
            match = True
            for j, p in enumerate(pattern):
                if p is not None and opcodes[i + j] != p:
                    match = False
                    break
            if match:
                matches.append(offsets[i])

        return matches


# ── Coverage Bitmap Generator ────────────────────────────────────────────────

class CoverageBitmapGenerator:
    """Generates coverage bitmaps for bytecode-level fuzzing."""

    def __init__(self, bitmap_size: int = 65536) -> None:
        self.bitmap_size = bitmap_size
        self.bitmap = bytearray(bitmap_size)
        self._edge_map: dict[tuple[int, int], int] = {}

    def record_edge(self, from_offset: int, to_offset: int) -> bool:
        """Record a CFG edge hit. Returns True if new edge."""
        edge = (from_offset, to_offset)
        idx = self._hash_edge(from_offset, to_offset)

        if self.bitmap[idx] == 0:
            self.bitmap[idx] = 1
            self._edge_map[edge] = idx
            return True

        if self.bitmap[idx] < 255:
            self.bitmap[idx] += 1

        return False

    def record_path(self, offsets: list[int]) -> int:
        """Record a path (sequence of offsets). Returns new edge count."""
        new_edges = 0
        for i in range(len(offsets) - 1):
            if self.record_edge(offsets[i], offsets[i + 1]):
                new_edges += 1
        return new_edges

    def get_coverage_pct(self, total_edges: int) -> float:
        """Get coverage percentage."""
        if total_edges == 0:
            return 0.0
        covered = sum(1 for b in self.bitmap if b > 0)
        return covered / total_edges * 100

    def get_hot_edges(self, threshold: int = 10) -> list[tuple[int, int]]:
        """Get frequently-hit edges (hot paths)."""
        return [
            edge for edge, idx in self._edge_map.items()
            if self.bitmap[idx] >= threshold
        ]

    def get_cold_edges(self) -> list[tuple[int, int]]:
        """Get edges hit exactly once (rare paths)."""
        return [
            edge for edge, idx in self._edge_map.items()
            if self.bitmap[idx] == 1
        ]

    def _hash_edge(self, from_offset: int, to_offset: int) -> int:
        """Hash edge to bitmap index."""
        return ((from_offset >> 1) ^ to_offset) % self.bitmap_size

    def merge(self, other: "CoverageBitmapGenerator") -> int:
        """Merge another bitmap. Returns number of new edges found."""
        new_edges = 0
        for i in range(self.bitmap_size):
            if self.bitmap[i] == 0 and other.bitmap[i] > 0:
                new_edges += 1
            self.bitmap[i] = max(self.bitmap[i], other.bitmap[i])
        return new_edges

    def to_bytes(self) -> bytes:
        return bytes(self.bitmap)

    def get_stats(self) -> dict[str, Any]:
        return {
            "bitmap_size": self.bitmap_size,
            "edges_covered": sum(1 for b in self.bitmap if b > 0),
            "total_hits": sum(self.bitmap),
            "max_hits": max(self.bitmap) if self.bitmap else 0,
            "hot_edges": len(self.get_hot_edges()),
            "cold_edges": len(self.get_cold_edges()),
        }


# ── Main Bytecode Analyzer ──────────────────────────────────────────────────

class EVMBytecodeAnalyzer:
    """Complete EVM bytecode analyzer for Soul Protocol.

    Combines disassembly, CFG construction, storage extraction,
    function identification, delegate call detection, and
    Soul-specific pattern matching.

    Usage:
        analyzer = EVMBytecodeAnalyzer()
        result = analyzer.analyze(bytecode_hex)
    """

    def __init__(self) -> None:
        self._disassembler = EVMDisassembler()
        self._cfg_builder = CFGBuilder()
        self._storage_extractor = StorageLayoutExtractor()
        self._selector_extractor = SelectorExtractor()
        self._delegatecall_detector = DelegateCallDetector()
        self._pattern_matcher = SoulPatternMatcher()
        self._coverage_bitmap = CoverageBitmapGenerator()

    def analyze(
        self,
        bytecode: str | bytes,
        known_selectors: dict[str, str] | None = None,
    ) -> BytecodeAnalysisResult:
        """Perform complete bytecode analysis.

        Args:
            bytecode: Hex string (0x-prefixed or not) or raw bytes
            known_selectors: Optional mapping of selectors to names

        Returns:
            BytecodeAnalysisResult with all analysis data
        """
        raw = self._normalize_bytecode(bytecode)
        if not raw:
            return BytecodeAnalysisResult()

        result = BytecodeAnalysisResult(
            bytecode_hash=hashlib.sha256(raw).hexdigest(),
            bytecode_size=len(raw),
        )

        # 1. Disassemble
        instructions = self._disassembler.disassemble(raw)
        result.instructions = instructions
        result.instruction_count = len(instructions)
        logger.info("Disassembled %d instructions from %d bytes", len(instructions), len(raw))

        # 2. Build CFG
        blocks = self._cfg_builder.build(instructions)
        result.basic_blocks = blocks
        result.block_count = len(blocks)
        result.edge_count = sum(len(b.successors) for b in blocks)
        result.cyclomatic_complexity = result.edge_count - result.block_count + 2

        # 3. Extract function selectors
        merge_selectors = dict(SOUL_SELECTORS)
        if known_selectors:
            merge_selectors.update(known_selectors)

        function_sigs = self._selector_extractor.extract(instructions, blocks)
        for sig in function_sigs:
            if not sig.name and sig.selector in merge_selectors:
                sig.name = merge_selectors[sig.selector]
        result.function_signatures = function_sigs

        # Check fallback/receive
        result.has_fallback = any(
            b.block_type == BasicBlockType.FALLBACK for b in blocks
        )
        result.has_receive = any(
            b.block_type == BasicBlockType.RECEIVE for b in blocks
        )

        # 4. Extract storage layout
        storage_slots = self._storage_extractor.extract(instructions, function_sigs)
        result.storage_slots = storage_slots
        result.storage_slot_count = len(storage_slots)

        # 5. Detect delegate calls
        delegate_targets = self._delegatecall_detector.detect(instructions)
        result.delegate_call_targets = delegate_targets

        # 6. Security checks
        result.selfdestruct_reachable = any(
            inst.opcode == Opcode.SELFDESTRUCT.value for inst in instructions
        )
        result.has_create2 = any(
            inst.opcode == Opcode.CREATE2.value for inst in instructions
        )

        # Count unchecked calls
        result.unchecked_calls = self._count_unchecked_calls(instructions)

        # Count reentrancy guards
        result.reentrancy_guards = self._count_reentrancy_guards(instructions)

        # 7. Opcode frequency analysis
        freq: dict[str, int] = defaultdict(int)
        categories: dict[str, int] = defaultdict(int)

        for inst in instructions:
            freq[inst.opcode_name] += 1
            cat = self._categorize_opcode(inst.opcode)
            categories[cat] += 1

        result.opcode_frequency = dict(freq)
        result.opcode_categories = dict(categories)

        # 8. Soul-specific pattern matching
        patterns = self._pattern_matcher.match_all(instructions, blocks)
        result.soul_patterns = patterns

        result.zk_verify_blocks = [
            p["block"] for p in patterns.get("zk_verify_blocks", [])
        ]
        result.nullifier_check_blocks = [
            p["offset"] for p in patterns.get("nullifier_check", [])
        ]

        # 9. Coverage bitmap prep
        result.coverage_bitmap_size = self._coverage_bitmap.bitmap_size
        result.jump_targets = {
            inst.operand_value
            for inst in instructions
            if inst.is_push and inst.opcode >= 0x60
        } & {b.start_offset for b in blocks}

        result.conditional_jumps = []
        for block in blocks:
            if block.instructions and block.instructions[-1].opcode == Opcode.JUMPI.value:
                true_target = block.successors[1] if len(block.successors) > 1 else 0
                false_target = block.successors[0] if block.successors else 0
                result.conditional_jumps.append(
                    (block.instructions[-1].offset, true_target, false_target)
                )

        # 10. Generate fuzz recommendations
        result.fuzz_recommendations = self._generate_fuzz_recommendations(result)

        logger.info(
            "Bytecode analysis complete: %d blocks, %d functions, %d storage slots, %d patterns",
            result.block_count,
            len(result.function_signatures),
            result.storage_slot_count,
            sum(len(v) for v in result.soul_patterns.values()),
        )

        return result

    def get_coverage_bitmap(self) -> CoverageBitmapGenerator:
        """Get the coverage bitmap generator for runtime tracking."""
        return self._coverage_bitmap

    def _normalize_bytecode(self, bytecode: str | bytes) -> bytes:
        """Normalize bytecode input to raw bytes."""
        if isinstance(bytecode, bytes):
            return bytecode
        if isinstance(bytecode, str):
            bc = bytecode.strip()
            if bc.startswith("0x") or bc.startswith("0X"):
                bc = bc[2:]
            try:
                return bytes.fromhex(bc)
            except ValueError:
                logger.error("Invalid hex bytecode")
                return b""
        return b""

    def _count_unchecked_calls(
        self, instructions: list[DisassembledInstruction],
    ) -> int:
        """Count CALL/DELEGATECALL without subsequent ISZERO + JUMPI check."""
        unchecked = 0
        for i, inst in enumerate(instructions):
            if inst.opcode in (
                Opcode.CALL.value,
                Opcode.DELEGATECALL.value,
                Opcode.CALLCODE.value,
            ):
                # Check next few instructions for ISZERO (return value check)
                following = instructions[i + 1: i + 5]
                has_check = any(
                    f.opcode == Opcode.ISZERO.value for f in following
                )
                if not has_check:
                    unchecked += 1
        return unchecked

    def _count_reentrancy_guards(
        self, instructions: list[DisassembledInstruction],
    ) -> int:
        """Count reentrancy guard patterns (SLOAD 1 → SSTORE 2 → ... → SSTORE 1)."""
        guards = 0
        opcodes = [inst.opcode for inst in instructions]

        for i in range(len(opcodes) - 6):
            if (
                opcodes[i] == Opcode.SLOAD.value
                and Opcode.EQ.value in opcodes[i + 1: i + 4]
                and Opcode.JUMPI.value in opcodes[i + 1: i + 5]
            ):
                # Look for SSTORE pattern after
                for j in range(i + 4, min(i + 20, len(opcodes))):
                    if opcodes[j] == Opcode.SSTORE.value:
                        guards += 1
                        break

        return guards

    def _categorize_opcode(self, opcode: int) -> str:
        """Categorize opcode for frequency analysis."""
        if opcode in range(0x01, 0x0C):
            return "arithmetic"
        if opcode in range(0x10, 0x1E):
            return "comparison"
        if opcode == 0x20:
            return "crypto"
        if opcode in range(0x30, 0x49):
            return "environment"
        if opcode in range(0x50, 0x5C):
            return "stack_memory"
        if opcode in (0x54, 0x55):
            return "storage"
        if opcode in range(0x60, 0x80) or opcode == 0x5F:
            return "push"
        if opcode in range(0x80, 0x90):
            return "dup"
        if opcode in range(0x90, 0xA0):
            return "swap"
        if opcode in range(0xA0, 0xA5):
            return "log"
        if opcode in (0xF0, 0xF5):
            return "create"
        if opcode in (0xF1, 0xF2, 0xF4, 0xFA):
            return "call"
        if opcode in (0xF3, 0xFD):
            return "return_revert"
        if opcode in (0xFE, 0xFF):
            return "halt"
        return "other"

    def _generate_fuzz_recommendations(
        self, result: BytecodeAnalysisResult,
    ) -> list[dict[str, Any]]:
        """Generate fuzz targeting recommendations from analysis."""
        recommendations: list[dict[str, Any]] = []

        # 1. Functions with delegatecall — highest priority
        for sig in result.function_signatures:
            if sig.has_delegatecall:
                recommendations.append({
                    "priority": 1,
                    "target": sig.selector,
                    "name": sig.name or sig.selector,
                    "reason": "Contains DELEGATECALL — proxy vulnerability risk",
                    "mutations": [
                        "storage_collision",
                        "type_confusion",
                        "interesting_address",
                    ],
                })

        # 2. Payable functions with external calls
        for sig in result.function_signatures:
            if sig.is_payable and sig.external_calls > 0:
                recommendations.append({
                    "priority": 2,
                    "target": sig.selector,
                    "name": sig.name or sig.selector,
                    "reason": "Payable + external calls — reentrancy risk",
                    "mutations": [
                        "max_uint_amount",
                        "flash_loan_sequence",
                        "reentrancy_sequence",
                    ],
                })

        # 3. Functions with ZK verify pattern
        for sig in result.function_signatures:
            if sig.soul_pattern == "zk_verify":
                recommendations.append({
                    "priority": 2,
                    "target": sig.selector,
                    "name": sig.name or sig.selector,
                    "reason": "ZK verification — proof manipulation risk",
                    "mutations": [
                        "corrupt_proof",
                        "truncate_proof",
                        "invalid_public_inputs",
                        "wrong_verifier",
                    ],
                })

        # 4. Functions with nullifier registry pattern
        for sig in result.function_signatures:
            if sig.soul_pattern == "nullifier_registry":
                recommendations.append({
                    "priority": 2,
                    "target": sig.selector,
                    "name": sig.name or sig.selector,
                    "reason": "Nullifier registry — replay attack risk",
                    "mutations": [
                        "replay_nullifier",
                        "zero_nullifier",
                        "double_execute",
                        "cross_domain_collision",
                    ],
                })

        # 5. Bridge relay patterns
        for sig in result.function_signatures:
            if sig.soul_pattern == "bridge_relay":
                recommendations.append({
                    "priority": 3,
                    "target": sig.selector,
                    "name": sig.name or sig.selector,
                    "reason": "Bridge relay — cross-chain exploit risk",
                    "mutations": [
                        "wrong_chain_id",
                        "invalid_bridge_message",
                        "duplicate_relay",
                        "stale_merkle_root",
                    ],
                })

        # 6. Unchecked calls
        if result.unchecked_calls > 0:
            recommendations.append({
                "priority": 2,
                "target": "contract",
                "name": "Unchecked external calls",
                "reason": f"{result.unchecked_calls} external calls without return value check",
                "mutations": [
                    "interesting_address",
                    "max_uint_amount",
                ],
            })

        # 7. SELFDESTRUCT reachable
        if result.selfdestruct_reachable:
            recommendations.append({
                "priority": 1,
                "target": "contract",
                "name": "SELFDESTRUCT reachable",
                "reason": "Contract can be destroyed — critical risk",
                "mutations": [
                    "interesting_address",
                    "type_confusion",
                ],
            })

        # 8. Complex conditional logic (many JUMPI)
        if len(result.conditional_jumps) > 20:
            recommendations.append({
                "priority": 3,
                "target": "contract",
                "name": "Complex conditionals",
                "reason": f"{len(result.conditional_jumps)} conditional branches — high path complexity",
                "mutations": [
                    "boundary_value",
                    "bit_flip",
                    "arithmetic_overflow",
                ],
            })

        recommendations.sort(key=lambda r: r["priority"])
        return recommendations
