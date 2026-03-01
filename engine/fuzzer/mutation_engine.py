"""Mutation-feedback fuzzing engine for Soul Protocol.

Implements coverage-guided, mutation-based fuzzing specifically designed
for Soul Protocol's ZK privacy interoperability contracts.

Mutation strategies:
  1. Input mutations   — bit flips, byte swaps, boundary values for Solidity types
  2. ZK proof mutations — corrupt proof bytes, change VKs, replay proofs cross-chain
  3. Nullifier mutations — reuse, cross-domain collision, batch partial replay
  4. State mutations    — corrupt encrypted state, modify commitment values
  5. Bridge mutations   — wrong chain IDs, invalid relay data, timing attacks
  6. Economic mutations — flash loan sequences, large value transfers, dust
  7. Sequence mutations — reorder txns, skip steps, double-execute
  8. Cross-contract mutations — delegate call payloads, reentrancy sequences
"""

from __future__ import annotations

import hashlib
import logging
import os
import random
import struct
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

logger = logging.getLogger(__name__)


# ── Mutation Types ───────────────────────────────────────────────────────────


class MutationType(str, Enum):
    """Categories of mutations for fuzzing."""

    # Input-level mutations
    BIT_FLIP = "bit_flip"
    BYTE_SWAP = "byte_swap"
    BOUNDARY_VALUE = "boundary_value"
    ARITHMETIC_BOUNDARY = "arithmetic_boundary"
    INTERESTING_ADDRESS = "interesting_address"
    ZERO_SUBSTITUTE = "zero_substitute"
    MAX_SUBSTITUTE = "max_substitute"

    # ZK-specific mutations
    CORRUPT_PROOF = "corrupt_proof"
    TRUNCATE_PROOF = "truncate_proof"
    REPLAY_PROOF = "replay_proof"
    WRONG_VERIFIER = "wrong_verifier"
    INVALID_PUBLIC_INPUTS = "invalid_public_inputs"

    # Nullifier mutations
    REPLAY_NULLIFIER = "replay_nullifier"
    CROSS_DOMAIN_COLLISION = "cross_domain_collision"
    PARTIAL_BATCH_REPLAY = "partial_batch_replay"
    ZERO_NULLIFIER = "zero_nullifier"

    # State mutations
    CORRUPT_ENCRYPTED_STATE = "corrupt_encrypted_state"
    MODIFY_COMMITMENT = "modify_commitment"
    STALE_MERKLE_ROOT = "stale_merkle_root"
    WRONG_STATE_HASH = "wrong_state_hash"

    # Bridge mutations
    WRONG_CHAIN_ID = "wrong_chain_id"
    DUPLICATE_RELAY = "duplicate_relay"
    EXPIRED_TIMELOCK = "expired_timelock"
    INVALID_BRIDGE_MESSAGE = "invalid_bridge_message"

    # Economic mutations
    FLASH_LOAN_SEQUENCE = "flash_loan_sequence"
    DUST_AMOUNT = "dust_amount"
    MAX_UINT_AMOUNT = "max_uint_amount"
    FEE_MANIPULATION = "fee_manipulation"

    # Sequence mutations
    REORDER_TRANSACTIONS = "reorder_transactions"
    SKIP_STEP = "skip_step"
    DOUBLE_EXECUTE = "double_execute"
    FRONT_RUN = "front_run"
    SANDWICH_ATTACK = "sandwich_attack"

    # Cross-contract mutations
    REENTRANCY_PAYLOAD = "reentrancy_payload"
    DELEGATECALL_INJECTION = "delegatecall_injection"
    CALLBACK_MANIPULATION = "callback_manipulation"

    # Advanced mutations (v2)
    GRAMMAR_AWARE = "grammar_aware"
    DICTIONARY = "dictionary"
    SYMBOLIC_GUIDED = "symbolic_guided"
    CONCOLIC_GUIDED = "concolic_guided"
    LLM_GUIDED = "llm_guided"
    HAVOC = "havoc"
    SPLICE = "splice"
    TYPE_CONFUSION = "type_confusion"
    ABI_EDGE_CASE = "abi_edge_case"
    STORAGE_COLLISION = "storage_collision"


class FuzzInputType(str, Enum):
    """Solidity input types for fuzzing."""

    UINT256 = "uint256"
    INT256 = "int256"
    BYTES32 = "bytes32"
    BYTES = "bytes"
    ADDRESS = "address"
    BOOL = "bool"
    STRING = "string"
    UINT8 = "uint8"
    UINT256_ARRAY = "uint256[]"
    BYTES32_ARRAY = "bytes32[]"
    ADDRESS_ARRAY = "address[]"


# ── Interesting Values ───────────────────────────────────────────────────────

# Well-known boundary values for Solidity types
INTERESTING_UINT256 = [
    0,
    1,
    2,
    0xFF,
    0xFFFF,
    0xFFFFFFFF,
    2**128 - 1,
    2**255 - 1,
    2**256 - 1,
    2**256 - 2,
    10**18,  # 1 ETH in wei
    10**27,  # 1 billion ETH in wei
    2**64 - 1,
    2**128,
    2**192,
]

INTERESTING_INT256 = [
    0, 1, -1,
    2**255 - 1,  # max int256
    -(2**255),  # min int256
    2**127, -(2**127),
]

INTERESTING_BYTES32 = [
    b"\x00" * 32,  # zero
    b"\xff" * 32,  # max
    b"\x00" * 31 + b"\x01",  # one
    b"\xde\xad" * 16,  # deadbeef pattern
    hashlib.sha256(b"soul_protocol_test").digest(),
]

INTERESTING_ADDRESSES = [
    "0x0000000000000000000000000000000000000000",  # zero address
    "0x0000000000000000000000000000000000000001",  # ecrecover precompile
    "0x0000000000000000000000000000000000000002",  # sha256 precompile
    "0x0000000000000000000000000000000000000006",  # ecAdd precompile (BN254)
    "0x0000000000000000000000000000000000000007",  # ecMul precompile (BN254)
    "0x0000000000000000000000000000000000000008",  # ecPairing precompile
    "0xdead000000000000000000000000000000000000",  # burn address
    "0xFFfFfFffFFfffFFfFFfFFFFFffFFFffffFfFFFfF",  # max address
]

# Chain IDs used by Soul Protocol
SOUL_CHAIN_IDS = [
    1,          # Ethereum Mainnet
    11155111,   # Sepolia
    42161,      # Arbitrum One
    421614,     # Arbitrum Sepolia
    10,         # Optimism
    84532,      # Base Sepolia
    8453,       # Base Mainnet
    324,        # zkSync Era
    534352,     # Scroll
    59144,      # Linea
    1101,       # Polygon zkEVM
    0,          # Invalid
    2**256 - 1, # Max
]


# ── Mutation Data Structures ─────────────────────────────────────────────────


@dataclass
class MutationSeed:
    """A seed input for fuzzing."""

    id: str
    function_name: str
    contract_name: str
    inputs: dict[str, Any]
    sequence: list[dict[str, Any]] = field(default_factory=list)
    mutation_history: list[MutationType] = field(default_factory=list)
    coverage_hash: str = ""
    interesting_score: float = 0.0
    generation: int = 0
    parent_id: str = ""


@dataclass
class MutationResult:
    """Result of applying a mutation and executing it."""

    seed: MutationSeed
    mutation_type: MutationType
    reverted: bool = False
    revert_reason: str = ""
    new_coverage: bool = False
    invariant_violated: str = ""
    gas_used: int = 0
    execution_time_ms: float = 0
    raw_output: bytes = b""
    state_changes: dict[str, Any] = field(default_factory=dict)


@dataclass
class FuzzCampaignStats:
    """Statistics for a fuzzing campaign."""

    total_executions: int = 0
    unique_crashes: int = 0
    invariant_violations: int = 0
    coverage_percentage: float = 0.0
    corpus_size: int = 0
    mutations_applied: dict[str, int] = field(default_factory=dict)
    execution_time_seconds: float = 0.0
    interesting_finds: list[dict[str, Any]] = field(default_factory=list)
    violations_by_invariant: dict[str, int] = field(default_factory=dict)
    coverage_over_time: list[tuple[int, float]] = field(default_factory=list)


# ── Mutation Engine ──────────────────────────────────────────────────────────


class SoulMutationEngine:
    """Mutation engine specialized for Soul Protocol contracts.

    Generates mutated inputs targeting Soul-specific vulnerabilities:
    - ZK proof corruption/replay
    - Nullifier double-spend
    - Cross-domain nullifier collisions
    - Bridge relay attacks
    - Shielded pool economic invariants
    - Access control bypass
    """

    def __init__(self, seed: int | None = None, protocol_model: Any = None) -> None:
        self.rng = random.Random(seed or int.from_bytes(os.urandom(4), "big"))
        self.protocol_model = protocol_model
        self._mutation_weights: dict[MutationType, float] = self._default_weights()
        self._dictionary: list[Any] = []  # Learned interesting values
        self._grammar_templates: dict[str, list[dict[str, Any]]] = {}
        self._symbolic_seeds: list[dict[str, Any]] = []  # From symbolic executor

    def _default_weights(self) -> dict[MutationType, float]:
        """Default weights for each mutation type — higher = more likely."""
        return {
            # High-priority Soul-specific mutations
            MutationType.REPLAY_NULLIFIER: 10.0,
            MutationType.CORRUPT_PROOF: 10.0,
            MutationType.CROSS_DOMAIN_COLLISION: 9.0,
            MutationType.DOUBLE_EXECUTE: 9.0,
            MutationType.FLASH_LOAN_SEQUENCE: 8.0,
            MutationType.REPLAY_PROOF: 8.0,
            MutationType.STALE_MERKLE_ROOT: 8.0,
            MutationType.WRONG_CHAIN_ID: 7.0,
            MutationType.DUPLICATE_RELAY: 7.0,

            # Standard mutations
            MutationType.BIT_FLIP: 5.0,
            MutationType.BYTE_SWAP: 4.0,
            MutationType.BOUNDARY_VALUE: 6.0,
            MutationType.ZERO_SUBSTITUTE: 5.0,
            MutationType.MAX_SUBSTITUTE: 5.0,
            MutationType.INTERESTING_ADDRESS: 4.0,
            MutationType.ARITHMETIC_BOUNDARY: 4.0,

            # ZK mutations
            MutationType.TRUNCATE_PROOF: 6.0,
            MutationType.WRONG_VERIFIER: 6.0,
            MutationType.INVALID_PUBLIC_INPUTS: 7.0,

            # Nullifier mutations
            MutationType.PARTIAL_BATCH_REPLAY: 7.0,
            MutationType.ZERO_NULLIFIER: 5.0,

            # State mutations
            MutationType.CORRUPT_ENCRYPTED_STATE: 6.0,
            MutationType.MODIFY_COMMITMENT: 7.0,
            MutationType.WRONG_STATE_HASH: 6.0,

            # Bridge mutations
            MutationType.EXPIRED_TIMELOCK: 5.0,
            MutationType.INVALID_BRIDGE_MESSAGE: 5.0,

            # Economic mutations
            MutationType.DUST_AMOUNT: 4.0,
            MutationType.MAX_UINT_AMOUNT: 5.0,
            MutationType.FEE_MANIPULATION: 5.0,

            # Sequence mutations
            MutationType.REORDER_TRANSACTIONS: 6.0,
            MutationType.SKIP_STEP: 5.0,
            MutationType.FRONT_RUN: 5.0,
            MutationType.SANDWICH_ATTACK: 6.0,

            # Cross-contract mutations
            MutationType.REENTRANCY_PAYLOAD: 7.0,
            MutationType.DELEGATECALL_INJECTION: 6.0,
            MutationType.CALLBACK_MANIPULATION: 5.0,

            # Advanced mutations (v2)
            MutationType.GRAMMAR_AWARE: 8.0,
            MutationType.DICTIONARY: 7.0,
            MutationType.SYMBOLIC_GUIDED: 9.0,
            MutationType.CONCOLIC_GUIDED: 9.0,
            MutationType.LLM_GUIDED: 8.0,
            MutationType.HAVOC: 6.0,
            MutationType.SPLICE: 5.0,
            MutationType.TYPE_CONFUSION: 7.0,
            MutationType.ABI_EDGE_CASE: 6.0,
            MutationType.STORAGE_COLLISION: 7.0,
        }

    def update_weights(self, mutation_type: MutationType, factor: float) -> None:
        """Update mutation weight based on feedback — increase for productive mutations."""
        if mutation_type in self._mutation_weights:
            self._mutation_weights[mutation_type] *= factor
            # Clamp between 0.1 and 50.0
            self._mutation_weights[mutation_type] = max(
                0.1, min(50.0, self._mutation_weights[mutation_type])
            )

    def select_mutation(
        self,
        target_function: str = "",
        target_invariant: str = "",
    ) -> MutationType:
        """Select a mutation type using weighted random selection.

        Biases towards mutations relevant to the target function/invariant.
        """
        weights = dict(self._mutation_weights)

        # Boost relevant mutations based on target
        if target_invariant:
            invariant_mutations = self._get_invariant_mutations(target_invariant)
            for mt in invariant_mutations:
                if mt in weights:
                    weights[mt] *= 3.0

        if target_function:
            function_mutations = self._get_function_mutations(target_function)
            for mt in function_mutations:
                if mt in weights:
                    weights[mt] *= 2.0

        types = list(weights.keys())
        mutation_weights = [weights[t] for t in types]
        total = sum(mutation_weights)
        normalized = [w / total for w in mutation_weights]

        return self.rng.choices(types, weights=normalized, k=1)[0]

    def mutate_seed(self, seed: MutationSeed, mutation_type: MutationType) -> MutationSeed:
        """Apply a mutation to a seed, producing a new seed.

        Returns a new MutationSeed with mutated inputs.
        """
        new_seed = MutationSeed(
            id=hashlib.md5(
                f"{seed.id}:{mutation_type.value}:{time.time()}".encode()
            ).hexdigest()[:16],
            function_name=seed.function_name,
            contract_name=seed.contract_name,
            inputs=dict(seed.inputs),  # shallow copy
            sequence=list(seed.sequence),
            mutation_history=list(seed.mutation_history) + [mutation_type],
            generation=seed.generation + 1,
            parent_id=seed.id,
        )

        # Apply the mutation
        mutator = self._get_mutator(mutation_type)
        mutator(new_seed)

        return new_seed

    # ── Input Mutators ───────────────────────────────────────────────

    def _get_mutator(self, mutation_type: MutationType):
        """Get the mutator function for a given mutation type."""
        mutators = {
            MutationType.BIT_FLIP: self._mutate_bit_flip,
            MutationType.BYTE_SWAP: self._mutate_byte_swap,
            MutationType.BOUNDARY_VALUE: self._mutate_boundary_value,
            MutationType.ARITHMETIC_BOUNDARY: self._mutate_arithmetic_boundary,
            MutationType.INTERESTING_ADDRESS: self._mutate_interesting_address,
            MutationType.ZERO_SUBSTITUTE: self._mutate_zero_substitute,
            MutationType.MAX_SUBSTITUTE: self._mutate_max_substitute,
            MutationType.CORRUPT_PROOF: self._mutate_corrupt_proof,
            MutationType.TRUNCATE_PROOF: self._mutate_truncate_proof,
            MutationType.REPLAY_PROOF: self._mutate_replay_proof,
            MutationType.WRONG_VERIFIER: self._mutate_wrong_verifier,
            MutationType.INVALID_PUBLIC_INPUTS: self._mutate_invalid_public_inputs,
            MutationType.REPLAY_NULLIFIER: self._mutate_replay_nullifier,
            MutationType.CROSS_DOMAIN_COLLISION: self._mutate_cross_domain_collision,
            MutationType.PARTIAL_BATCH_REPLAY: self._mutate_partial_batch_replay,
            MutationType.ZERO_NULLIFIER: self._mutate_zero_nullifier,
            MutationType.CORRUPT_ENCRYPTED_STATE: self._mutate_corrupt_state,
            MutationType.MODIFY_COMMITMENT: self._mutate_modify_commitment,
            MutationType.STALE_MERKLE_ROOT: self._mutate_stale_root,
            MutationType.WRONG_STATE_HASH: self._mutate_wrong_state_hash,
            MutationType.WRONG_CHAIN_ID: self._mutate_wrong_chain_id,
            MutationType.DUPLICATE_RELAY: self._mutate_duplicate_relay,
            MutationType.EXPIRED_TIMELOCK: self._mutate_expired_timelock,
            MutationType.INVALID_BRIDGE_MESSAGE: self._mutate_invalid_bridge_message,
            MutationType.FLASH_LOAN_SEQUENCE: self._mutate_flash_loan_sequence,
            MutationType.DUST_AMOUNT: self._mutate_dust_amount,
            MutationType.MAX_UINT_AMOUNT: self._mutate_max_uint_amount,
            MutationType.FEE_MANIPULATION: self._mutate_fee_manipulation,
            MutationType.REORDER_TRANSACTIONS: self._mutate_reorder,
            MutationType.SKIP_STEP: self._mutate_skip_step,
            MutationType.DOUBLE_EXECUTE: self._mutate_double_execute,
            MutationType.FRONT_RUN: self._mutate_front_run,
            MutationType.SANDWICH_ATTACK: self._mutate_sandwich,
            MutationType.REENTRANCY_PAYLOAD: self._mutate_reentrancy,
            MutationType.DELEGATECALL_INJECTION: self._mutate_delegatecall,
            MutationType.CALLBACK_MANIPULATION: self._mutate_callback,
            MutationType.GRAMMAR_AWARE: self._mutate_grammar_aware,
            MutationType.DICTIONARY: self._mutate_dictionary,
            MutationType.SYMBOLIC_GUIDED: self._mutate_symbolic_guided,
            MutationType.CONCOLIC_GUIDED: self._mutate_concolic_guided,
            MutationType.LLM_GUIDED: self._mutate_llm_guided,
            MutationType.HAVOC: self._mutate_havoc,
            MutationType.SPLICE: self._mutate_splice,
            MutationType.TYPE_CONFUSION: self._mutate_type_confusion,
            MutationType.ABI_EDGE_CASE: self._mutate_abi_edge_case,
            MutationType.STORAGE_COLLISION: self._mutate_storage_collision,
        }
        return mutators.get(mutation_type, self._mutate_bit_flip)

    # ── Primitive Mutators ───────────────────────────────────────────

    def _mutate_bit_flip(self, seed: MutationSeed) -> None:
        """Flip random bits in a random input field."""
        if not seed.inputs:
            return
        key = self.rng.choice(list(seed.inputs.keys()))
        val = seed.inputs[key]

        if isinstance(val, int):
            bit_pos = self.rng.randint(0, 255)
            seed.inputs[key] = val ^ (1 << bit_pos)
        elif isinstance(val, (bytes, bytearray)):
            if val:
                data = bytearray(val)
                idx = self.rng.randint(0, len(data) - 1)
                data[idx] ^= 1 << self.rng.randint(0, 7)
                seed.inputs[key] = bytes(data)
        elif isinstance(val, str) and val.startswith("0x"):
            # Hex string — flip bit
            try:
                num = int(val, 16)
                bit_pos = self.rng.randint(0, 255)
                seed.inputs[key] = hex(num ^ (1 << bit_pos))
            except ValueError:
                pass

    def _mutate_byte_swap(self, seed: MutationSeed) -> None:
        """Swap random bytes in a bytes field."""
        for key, val in seed.inputs.items():
            if isinstance(val, (bytes, bytearray)) and len(val) >= 2:
                data = bytearray(val)
                i, j = self.rng.sample(range(len(data)), 2)
                data[i], data[j] = data[j], data[i]
                seed.inputs[key] = bytes(data)
                return
        # Fallback to bit flip
        self._mutate_bit_flip(seed)

    def _mutate_boundary_value(self, seed: MutationSeed) -> None:
        """Replace a numeric input with an interesting boundary value."""
        for key, val in seed.inputs.items():
            if isinstance(val, int):
                seed.inputs[key] = self.rng.choice(INTERESTING_UINT256)
                return
        # If no int found, add one
        if seed.inputs:
            key = self.rng.choice(list(seed.inputs.keys()))
            seed.inputs[key] = self.rng.choice(INTERESTING_UINT256)

    def _mutate_arithmetic_boundary(self, seed: MutationSeed) -> None:
        """Apply arithmetic near overflow/underflow boundaries."""
        for key, val in seed.inputs.items():
            if isinstance(val, int):
                ops = [
                    lambda v: v + 1,
                    lambda v: v - 1,
                    lambda v: v * 2,
                    lambda v: v // 2 if v else 0,
                    lambda v: 2**256 - v if v > 0 else 0,
                    lambda v: v ^ (2**256 - 1),
                ]
                op = self.rng.choice(ops)
                seed.inputs[key] = op(val) % (2**256)
                return

    def _mutate_interesting_address(self, seed: MutationSeed) -> None:
        """Replace an address input with an interesting address."""
        for key, val in seed.inputs.items():
            if isinstance(val, str) and (val.startswith("0x") and len(val) == 42):
                seed.inputs[key] = self.rng.choice(INTERESTING_ADDRESSES)
                return

        # Inject interesting address if there's a recipient/address param
        address_keys = [k for k in seed.inputs if "address" in k.lower() or "recipient" in k.lower()]
        if address_keys:
            seed.inputs[address_keys[0]] = self.rng.choice(INTERESTING_ADDRESSES)

    def _mutate_zero_substitute(self, seed: MutationSeed) -> None:
        """Replace a random input with its zero value."""
        if not seed.inputs:
            return
        key = self.rng.choice(list(seed.inputs.keys()))
        val = seed.inputs[key]
        if isinstance(val, int):
            seed.inputs[key] = 0
        elif isinstance(val, (bytes, bytearray)):
            seed.inputs[key] = b"\x00" * len(val)
        elif isinstance(val, str):
            seed.inputs[key] = "0x" + "0" * (len(val) - 2) if val.startswith("0x") else ""

    def _mutate_max_substitute(self, seed: MutationSeed) -> None:
        """Replace a random input with its max value."""
        if not seed.inputs:
            return
        key = self.rng.choice(list(seed.inputs.keys()))
        val = seed.inputs[key]
        if isinstance(val, int):
            seed.inputs[key] = 2**256 - 1
        elif isinstance(val, (bytes, bytearray)):
            seed.inputs[key] = b"\xff" * len(val)
        elif isinstance(val, str) and val.startswith("0x"):
            seed.inputs[key] = "0x" + "f" * (len(val) - 2)

    # ── ZK Proof Mutators ────────────────────────────────────────────

    def _mutate_corrupt_proof(self, seed: MutationSeed) -> None:
        """Corrupt ZK proof bytes — flips multiple bits to create invalid proofs."""
        proof_keys = [k for k in seed.inputs if "proof" in k.lower()]
        if not proof_keys:
            # Generate a fake proof to test with
            seed.inputs["proof"] = os.urandom(256)
            return

        key = self.rng.choice(proof_keys)
        val = seed.inputs[key]
        if isinstance(val, (bytes, bytearray)):
            data = bytearray(val)
            # Corrupt 1-8 random bytes
            num_corruptions = self.rng.randint(1, min(8, len(data)))
            for _ in range(num_corruptions):
                idx = self.rng.randint(0, len(data) - 1)
                data[idx] = self.rng.randint(0, 255)
            seed.inputs[key] = bytes(data)
        elif isinstance(val, int):
            seed.inputs[key] = val ^ self.rng.randint(1, 2**256 - 1)

    def _mutate_truncate_proof(self, seed: MutationSeed) -> None:
        """Truncate proof bytes — short proofs should be rejected."""
        proof_keys = [k for k in seed.inputs if "proof" in k.lower()]
        if proof_keys:
            key = self.rng.choice(proof_keys)
            val = seed.inputs[key]
            if isinstance(val, (bytes, bytearray)) and len(val) > 4:
                cut = self.rng.randint(1, len(val) // 2)
                seed.inputs[key] = val[:cut]
        else:
            seed.inputs["proof"] = b"\x00" * self.rng.randint(1, 16)

    def _mutate_replay_proof(self, seed: MutationSeed) -> None:
        """Replay a proof from a previous execution — should be rejected."""
        # Mark this seed as a replay attempt
        seed.inputs["_replay"] = True
        # Keep the same proof but change other params
        for key in seed.inputs:
            if "proof" not in key.lower() and isinstance(seed.inputs[key], int):
                seed.inputs[key] = seed.inputs[key] + self.rng.randint(1, 100)
                break

    def _mutate_wrong_verifier(self, seed: MutationSeed) -> None:
        """Use wrong verifier circuit ID — proofs should not verify."""
        circuit_keys = [k for k in seed.inputs if "circuit" in k.lower() or "verifier" in k.lower()]
        if circuit_keys:
            key = self.rng.choice(circuit_keys)
            seed.inputs[key] = os.urandom(32)
        else:
            seed.inputs["verifierCircuit"] = os.urandom(32)

    def _mutate_invalid_public_inputs(self, seed: MutationSeed) -> None:
        """Corrupt public inputs while keeping proof intact."""
        input_keys = [
            k for k in seed.inputs
            if any(x in k.lower() for x in ["state", "hash", "commitment", "root", "input"])
            and "proof" not in k.lower()
        ]
        if input_keys:
            key = self.rng.choice(input_keys)
            val = seed.inputs[key]
            if isinstance(val, int):
                seed.inputs[key] = val ^ self.rng.randint(1, 2**256 - 1)
            elif isinstance(val, (bytes, bytearray)):
                data = bytearray(val)
                if data:
                    data[self.rng.randint(0, len(data) - 1)] ^= 0xFF
                    seed.inputs[key] = bytes(data)

    # ── Nullifier Mutators ───────────────────────────────────────────

    def _mutate_replay_nullifier(self, seed: MutationSeed) -> None:
        """Attempt to reuse a nullifier — double-spend attack."""
        seed.inputs["_nullifier_replay"] = True
        # Duplicate the sequence to execute twice
        if seed.sequence:
            seed.sequence.append(dict(seed.sequence[-1]))

    def _mutate_cross_domain_collision(self, seed: MutationSeed) -> None:
        """Attempt cross-domain nullifier collision."""
        # Use same nullifier but different domain
        domain_keys = [k for k in seed.inputs if "domain" in k.lower() or "chain" in k.lower()]
        if domain_keys:
            key = domain_keys[0]
            seed.inputs[key] = self.rng.choice(SOUL_CHAIN_IDS)
        else:
            seed.inputs["domain"] = self.rng.choice(SOUL_CHAIN_IDS)

        # Keep nullifier the same
        seed.inputs["_cross_domain_test"] = True

    def _mutate_partial_batch_replay(self, seed: MutationSeed) -> None:
        """Test batch nullifier registration with partial replays."""
        nullifier_keys = [k for k in seed.inputs if "nullifier" in k.lower()]
        if nullifier_keys and isinstance(seed.inputs[nullifier_keys[0]], list):
            # Duplicate one nullifier in the batch
            arr = list(seed.inputs[nullifier_keys[0]])
            if arr:
                arr.append(arr[self.rng.randint(0, len(arr) - 1)])
                seed.inputs[nullifier_keys[0]] = arr

    def _mutate_zero_nullifier(self, seed: MutationSeed) -> None:
        """Use zero nullifier — should be rejected."""
        nullifier_keys = [k for k in seed.inputs if "nullifier" in k.lower()]
        if nullifier_keys:
            seed.inputs[nullifier_keys[0]] = 0
        else:
            seed.inputs["nullifier"] = 0

    # ── State Mutators ───────────────────────────────────────────────

    def _mutate_corrupt_state(self, seed: MutationSeed) -> None:
        """Corrupt encrypted state data."""
        state_keys = [k for k in seed.inputs if any(x in k.lower() for x in ["encrypted", "data", "state"])]
        if state_keys:
            key = self.rng.choice(state_keys)
            val = seed.inputs[key]
            if isinstance(val, (bytes, bytearray)):
                data = bytearray(val)
                for i in range(min(4, len(data))):
                    data[self.rng.randint(0, len(data) - 1)] = self.rng.randint(0, 255)
                seed.inputs[key] = bytes(data)
            elif isinstance(val, int):
                seed.inputs[key] = val ^ self.rng.randint(1, 2**128)

    def _mutate_modify_commitment(self, seed: MutationSeed) -> None:
        """Modify commitment value — forged commitments should be rejected."""
        commit_keys = [k for k in seed.inputs if "commitment" in k.lower() or "commit" in k.lower()]
        if commit_keys:
            key = commit_keys[0]
            seed.inputs[key] = int.from_bytes(os.urandom(32), "big")
        else:
            seed.inputs["commitment"] = int.from_bytes(os.urandom(32), "big")

    def _mutate_stale_root(self, seed: MutationSeed) -> None:
        """Use a stale/invalid Merkle root."""
        root_keys = [k for k in seed.inputs if "root" in k.lower()]
        if root_keys:
            seed.inputs[root_keys[0]] = int.from_bytes(os.urandom(32), "big")
        else:
            seed.inputs["root"] = int.from_bytes(os.urandom(32), "big")

    def _mutate_wrong_state_hash(self, seed: MutationSeed) -> None:
        """Use wrong state hash for lock/unlock."""
        hash_keys = [k for k in seed.inputs if "hash" in k.lower() or "stateHash" in k.lower()]
        if hash_keys:
            key = hash_keys[0]
            seed.inputs[key] = int.from_bytes(os.urandom(32), "big")

    # ── Bridge Mutators ──────────────────────────────────────────────

    def _mutate_wrong_chain_id(self, seed: MutationSeed) -> None:
        """Use incorrect chain ID for cross-chain operations."""
        chain_keys = [k for k in seed.inputs if "chain" in k.lower() or "dest" in k.lower()]
        if chain_keys:
            key = chain_keys[0]
            # Pick either invalid (0, max) or different valid chain
            choices = [0, 2**256 - 1, 999999] + SOUL_CHAIN_IDS
            seed.inputs[key] = self.rng.choice(choices)
        else:
            seed.inputs["destChainId"] = self.rng.choice([0, 2**256 - 1, 999999])

    def _mutate_duplicate_relay(self, seed: MutationSeed) -> None:
        """Attempt to relay the same proof twice."""
        seed.inputs["_duplicate_relay"] = True
        if seed.sequence:
            seed.sequence.append(dict(seed.sequence[-1]))

    def _mutate_expired_timelock(self, seed: MutationSeed) -> None:
        """Attempt operations with expired timelock."""
        timelock_keys = [k for k in seed.inputs if "time" in k.lower() or "deadline" in k.lower()]
        if timelock_keys:
            # Set timelock to past (1 = very old timestamp)
            seed.inputs[timelock_keys[0]] = self.rng.choice([0, 1, 2**32 - 1])
        else:
            seed.inputs["timelock"] = 1  # expired

    def _mutate_invalid_bridge_message(self, seed: MutationSeed) -> None:
        """Craft invalid bridge message payload."""
        msg_keys = [k for k in seed.inputs if "data" in k.lower() or "message" in k.lower() or "payload" in k.lower()]
        if msg_keys:
            key = msg_keys[0]
            seed.inputs[key] = os.urandom(self.rng.randint(1, 512))

    # ── Economic Mutators ────────────────────────────────────────────

    def _mutate_flash_loan_sequence(self, seed: MutationSeed) -> None:
        """Generate a flash-loan-style deposit→action→withdraw sequence."""
        seed.sequence = [
            {
                "function": "deposit",
                "inputs": {"commitment": int.from_bytes(os.urandom(32), "big")},
                "value": 10**18,  # 1 ETH
                "same_block": True,
            },
            dict(seed.inputs),  # Original action in middle
            {
                "function": "withdraw",
                "inputs": {
                    "nullifierHash": int.from_bytes(os.urandom(32), "big"),
                    "recipient": self.rng.choice(INTERESTING_ADDRESSES),
                    "root": int.from_bytes(os.urandom(32), "big"),
                    "proof": os.urandom(256),
                },
                "same_block": True,
            },
        ]
        seed.inputs["_flash_loan_test"] = True

    def _mutate_dust_amount(self, seed: MutationSeed) -> None:
        """Use dust amounts to test rounding/economic edge cases."""
        amount_keys = [k for k in seed.inputs if "amount" in k.lower() or "value" in k.lower() or "fee" in k.lower()]
        if amount_keys:
            seed.inputs[amount_keys[0]] = self.rng.choice([0, 1, 2, 100, 999])

    def _mutate_max_uint_amount(self, seed: MutationSeed) -> None:
        """Use max uint256 for amount fields — overflow testing."""
        amount_keys = [k for k in seed.inputs if "amount" in k.lower() or "value" in k.lower()]
        if amount_keys:
            seed.inputs[amount_keys[0]] = 2**256 - 1

    def _mutate_fee_manipulation(self, seed: MutationSeed) -> None:
        """Manipulate fee parameters."""
        fee_keys = [k for k in seed.inputs if "fee" in k.lower() or "relayer" in k.lower()]
        if fee_keys:
            seed.inputs[fee_keys[0]] = self.rng.choice([0, 1, 2**256 - 1, 10**18 * 1000])

    # ── Sequence Mutators ────────────────────────────────────────────

    def _mutate_reorder(self, seed: MutationSeed) -> None:
        """Reorder transactions in a sequence."""
        if len(seed.sequence) >= 2:
            self.rng.shuffle(seed.sequence)
        else:
            # Create a 2-step sequence with reversed order
            seed.sequence = [
                {"function": seed.function_name, "inputs": dict(seed.inputs)},
                {"function": seed.function_name, "inputs": dict(seed.inputs)},
            ]

    def _mutate_skip_step(self, seed: MutationSeed) -> None:
        """Skip a step in a multi-step protocol interaction."""
        seed.inputs["_skip_setup"] = True

    def _mutate_double_execute(self, seed: MutationSeed) -> None:
        """Execute the same operation twice — test idempotency."""
        seed.sequence = [
            {"function": seed.function_name, "inputs": dict(seed.inputs)},
            {"function": seed.function_name, "inputs": dict(seed.inputs)},
        ]
        seed.inputs["_double_execute"] = True

    def _mutate_front_run(self, seed: MutationSeed) -> None:
        """Simulate front-running by inserting a tx before the target."""
        seed.sequence.insert(0, {
            "function": seed.function_name,
            "inputs": dict(seed.inputs),
            "from": self.rng.choice(INTERESTING_ADDRESSES),
            "_front_run": True,
        })

    def _mutate_sandwich(self, seed: MutationSeed) -> None:
        """Simulate sandwich attack — insert txns before and after."""
        attacker_tx = {
            "function": seed.function_name,
            "inputs": dict(seed.inputs),
            "from": self.rng.choice(INTERESTING_ADDRESSES),
            "_sandwich": True,
        }
        seed.sequence = [
            dict(attacker_tx),
            {"function": seed.function_name, "inputs": dict(seed.inputs)},
            dict(attacker_tx),
        ]

    # ── Cross-Contract Mutators ──────────────────────────────────────

    def _mutate_reentrancy(self, seed: MutationSeed) -> None:
        """Set up reentrancy payload."""
        seed.inputs["_reentrancy"] = True
        seed.inputs["_callback_function"] = seed.function_name
        # Point recipient to attacker contract
        for key in seed.inputs:
            if "recipient" in key.lower() or "to" in key.lower():
                seed.inputs[key] = "0xAttackerContract"

    def _mutate_delegatecall(self, seed: MutationSeed) -> None:
        """Inject delegatecall payload."""
        seed.inputs["_delegatecall"] = True
        data_keys = [k for k in seed.inputs if "data" in k.lower()]
        if data_keys:
            # Craft malicious calldata
            seed.inputs[data_keys[0]] = os.urandom(self.rng.randint(4, 256))

    def _mutate_callback(self, seed: MutationSeed) -> None:
        """Manipulate callback parameters."""
        seed.inputs["_callback_manipulation"] = True

    # ── Advanced Mutators (v2) ───────────────────────────────────────

    def _mutate_grammar_aware(self, seed: MutationSeed) -> None:
        """Grammar-aware mutation: generate inputs that match ABI structure.

        Uses knowledge of function signatures and Solidity types to
        produce structurally valid but semantically adversarial inputs.
        """
        func = seed.function_name.lower()

        # Soul Protocol grammar templates for common patterns
        templates = self._grammar_templates.get(func)
        if templates:
            template = self.rng.choice(templates)
            for key, gen_fn in template.items():
                if callable(gen_fn):
                    seed.inputs[key] = gen_fn()
                else:
                    seed.inputs[key] = gen_fn
            return

        # Auto-generate from function signature patterns
        if "deposit" in func:
            seed.inputs.update({
                "commitment": int.from_bytes(os.urandom(32), "big"),
            })
            seed.inputs.setdefault("amount", self.rng.choice([
                0, 1, 10**18, 2**128 - 1, 2**256 - 1,
            ]))
        elif "withdraw" in func:
            seed.inputs.update({
                "nullifierHash": int.from_bytes(os.urandom(32), "big"),
                "root": int.from_bytes(os.urandom(32), "big"),
                "proof": os.urandom(256),
            })
        elif "bridge" in func or "cross" in func:
            seed.inputs.update({
                "destChainId": self.rng.choice(SOUL_CHAIN_IDS),
                "proof": os.urandom(256),
            })
        elif "lock" in func:
            seed.inputs.update({
                "stateHash": int.from_bytes(os.urandom(32), "big"),
                "timelock": self.rng.choice([0, 1, 2**32 - 1, int(time.time()) + 3600]),
            })
        elif "swap" in func:
            seed.inputs.update({
                "hashLock": int.from_bytes(os.urandom(32), "big"),
                "timelock": int(time.time()) + self.rng.choice([-3600, 0, 3600, 86400]),
            })

    def _mutate_dictionary(self, seed: MutationSeed) -> None:
        """Dictionary-based mutation: replace values with learned interesting values.

        Maintains a dictionary of values that have produced new coverage
        or violations, and uses them to replace input fields.
        """
        if not self._dictionary:
            # Bootstrap with Soul Protocol interesting values
            self._dictionary.extend(INTERESTING_UINT256)
            self._dictionary.extend(INTERESTING_ADDRESSES)
            self._dictionary.extend([b"\x00" * 32, b"\xff" * 32, os.urandom(32)])

        if not seed.inputs:
            return

        key = self.rng.choice(list(seed.inputs.keys()))
        val = seed.inputs[key]

        # Select compatible dictionary value
        if isinstance(val, int):
            candidates = [v for v in self._dictionary if isinstance(v, int)]
            if candidates:
                seed.inputs[key] = self.rng.choice(candidates)
        elif isinstance(val, str) and val.startswith("0x"):
            candidates = [v for v in self._dictionary if isinstance(v, str) and v.startswith("0x")]
            if candidates:
                seed.inputs[key] = self.rng.choice(candidates)
        elif isinstance(val, (bytes, bytearray)):
            candidates = [v for v in self._dictionary if isinstance(v, (bytes, bytearray))]
            if candidates:
                seed.inputs[key] = self.rng.choice(candidates)

    def add_to_dictionary(self, value: Any) -> None:
        """Add a value to the mutation dictionary (learned from coverage)."""
        if value not in self._dictionary:
            self._dictionary.append(value)
            # Cap dictionary size
            if len(self._dictionary) > 5000:
                self._dictionary = self._dictionary[-3000:]

    def _mutate_symbolic_guided(self, seed: MutationSeed) -> None:
        """Use symbolic execution results to guide mutation.

        Seeds from symbolic executor target specific branch conditions.
        """
        if self._symbolic_seeds:
            sym_seed = self.rng.choice(self._symbolic_seeds)
            for key, value in sym_seed.items():
                if key in seed.inputs:
                    seed.inputs[key] = value
            return

        # Fallback: arithmetic boundary targeting comparison operators
        for key, val in seed.inputs.items():
            if isinstance(val, int):
                # Target common Solidity comparison boundaries
                targets = [
                    val + 1, val - 1, val * 2, val // 2 if val else 0,
                    val ^ 1, val | 1, val & ~1,
                    2**255, 2**128, 10**18,
                ]
                seed.inputs[key] = self.rng.choice(targets) % (2**256)
                return

    def add_symbolic_seeds(self, seeds: list[dict[str, Any]]) -> None:
        """Add seeds generated by symbolic executor."""
        self._symbolic_seeds.extend(seeds)
        if len(self._symbolic_seeds) > 1000:
            self._symbolic_seeds = self._symbolic_seeds[-500:]

    def _mutate_concolic_guided(self, seed: MutationSeed) -> None:
        """Concolic-guided mutation: use constraint solver results."""
        # Similar to symbolic but for concrete+symbolic hybrid
        self._mutate_symbolic_guided(seed)

    def _mutate_llm_guided(self, seed: MutationSeed) -> None:
        """LLM-guided mutation: apply strategy suggested by LLM oracle.

        The LLM oracle's suggestions are pre-computed and stored as
        grammar templates, which this mutator applies.
        """
        # LLM strategies get pre-loaded into grammar templates
        func = seed.function_name
        templates = self._grammar_templates.get(f"llm_{func}", [])
        if templates:
            template = self.rng.choice(templates)
            for key, val in template.items():
                seed.inputs[key] = val
            return

        # Fallback: havoc-style
        self._mutate_havoc(seed)

    def set_llm_strategies(self, strategies: list[dict[str, Any]]) -> None:
        """Import strategies from LLM oracle into grammar templates."""
        for strategy in strategies:
            func = strategy.get("function", "unknown")
            mutations = strategy.get("mutations", [])
            key = f"llm_{func}"
            if key not in self._grammar_templates:
                self._grammar_templates[key] = []
            self._grammar_templates[key].extend(mutations)

    def _mutate_havoc(self, seed: MutationSeed) -> None:
        """Havoc: stack multiple random mutations.

        Applies 2-8 random mutations in sequence for maximum diversity.
        """
        basic_mutations = [
            MutationType.BIT_FLIP, MutationType.BYTE_SWAP,
            MutationType.BOUNDARY_VALUE, MutationType.ZERO_SUBSTITUTE,
            MutationType.MAX_SUBSTITUTE, MutationType.ARITHMETIC_BOUNDARY,
        ]

        n_stacked = self.rng.randint(2, 8)
        for _ in range(n_stacked):
            mt = self.rng.choice(basic_mutations)
            mutator = self._get_mutator(mt)
            mutator(seed)

    def _mutate_splice(self, seed: MutationSeed) -> None:
        """Splice: combine parts of this seed with sequence data."""
        if seed.sequence and len(seed.sequence) >= 2:
            # Pick a random step and merge its inputs
            step = self.rng.choice(seed.sequence)
            step_inputs = step.get("inputs", {})
            for key, val in step_inputs.items():
                if key in seed.inputs and self.rng.random() < 0.5:
                    seed.inputs[key] = val
        else:
            self._mutate_havoc(seed)

    def _mutate_type_confusion(self, seed: MutationSeed) -> None:
        """Type confusion: use values of wrong Solidity type.

        Tests ABI decoding edge cases by sending values that don't
        match the expected type.
        """
        if not seed.inputs:
            return

        key = self.rng.choice(list(seed.inputs.keys()))
        val = seed.inputs[key]

        # Swap types to cause confusion
        if isinstance(val, int):
            # Int → address (truncated)
            seed.inputs[key] = f"0x{(val % (2**160)):040x}"
        elif isinstance(val, str) and val.startswith("0x") and len(val) == 42:
            # Address → int
            seed.inputs[key] = int(val, 16)
        elif isinstance(val, (bytes, bytearray)):
            # Bytes → int
            seed.inputs[key] = int.from_bytes(val[:32].ljust(32, b"\x00"), "big")
        elif isinstance(val, bool):
            # Bool → int (2, which is invalid for bool)
            seed.inputs[key] = 2

    def _mutate_abi_edge_case(self, seed: MutationSeed) -> None:
        """ABI encoding edge cases: test decoder limits.

        Generates inputs that stress ABI decoding:
        - Extremely long dynamic arrays
        - Nested dynamic types
        - Wrong offset pointers
        - Truncated calldata
        """
        if not seed.inputs:
            return

        key = self.rng.choice(list(seed.inputs.keys()))
        val = seed.inputs[key]

        edge_case = self.rng.choice([
            "huge_array", "empty_string", "padding_mismatch",
            "max_offset", "nested_dynamic",
        ])

        if edge_case == "huge_array":
            seed.inputs[key] = [0] * self.rng.choice([256, 1024, 10000])
        elif edge_case == "empty_string":
            seed.inputs[key] = ""
        elif edge_case == "padding_mismatch":
            if isinstance(val, (bytes, bytearray)):
                # Add extra bytes that shouldn't be there
                seed.inputs[key] = val + os.urandom(self.rng.randint(1, 31))
        elif edge_case == "max_offset":
            seed.inputs[key] = 2**256 - 1
        elif edge_case == "nested_dynamic":
            seed.inputs[key] = [[os.urandom(32)] * 3] * 3

    def _mutate_storage_collision(self, seed: MutationSeed) -> None:
        """Test storage slot collision via crafted proxy patterns.

        Uses known storage slot calculations to craft inputs that
        could cause storage collisions in proxy patterns.
        """
        # Common proxy storage slots
        collision_targets = [
            0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc,  # EIP-1967 impl
            0xa3f0ad74e5423aebfd80d3ef4346578335a9a72aeaee59ff6cb3582b35133d50,  # EIP-1967 beacon
            0xb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103,  # EIP-1967 admin
            0x00,  # slot 0
            0x01,  # slot 1
        ]

        # Try to set inputs that would map to these storage slots
        for key, val in seed.inputs.items():
            if isinstance(val, int):
                seed.inputs[key] = self.rng.choice(collision_targets)
                seed.inputs["_storage_collision_test"] = True
                return

    # ── Helper Methods ───────────────────────────────────────────────

    def _get_invariant_mutations(self, invariant_id: str) -> list[MutationType]:
        """Map invariant IDs to relevant mutation types."""
        mapping = {
            "SOUL-INV-001": [MutationType.REPLAY_NULLIFIER, MutationType.DOUBLE_EXECUTE],
            "SOUL-INV-002": [MutationType.CROSS_DOMAIN_COLLISION, MutationType.ZERO_NULLIFIER],
            "SOUL-INV-003": [MutationType.PARTIAL_BATCH_REPLAY, MutationType.REPLAY_NULLIFIER],
            "SOUL-INV-010": [MutationType.CORRUPT_PROOF, MutationType.TRUNCATE_PROOF, MutationType.WRONG_VERIFIER],
            "SOUL-INV-011": [MutationType.DOUBLE_EXECUTE, MutationType.REPLAY_PROOF],
            "SOUL-INV-012": [MutationType.INTERESTING_ADDRESS],
            "SOUL-INV-013": [MutationType.WRONG_STATE_HASH, MutationType.CORRUPT_ENCRYPTED_STATE],
            "SOUL-INV-020": [MutationType.CORRUPT_PROOF, MutationType.INVALID_PUBLIC_INPUTS],
            "SOUL-INV-021": [MutationType.CORRUPT_PROOF, MutationType.REPLAY_PROOF],
            "SOUL-INV-022": [MutationType.WRONG_VERIFIER, MutationType.CORRUPT_PROOF],
            "SOUL-INV-030": [MutationType.FLASH_LOAN_SEQUENCE, MutationType.MAX_UINT_AMOUNT, MutationType.DUST_AMOUNT],
            "SOUL-INV-031": [MutationType.MODIFY_COMMITMENT, MutationType.STALE_MERKLE_ROOT],
            "SOUL-INV-032": [MutationType.STALE_MERKLE_ROOT],
            "SOUL-INV-033": [MutationType.MAX_UINT_AMOUNT, MutationType.FLASH_LOAN_SEQUENCE],
            "SOUL-INV-040": [MutationType.DUPLICATE_RELAY, MutationType.DOUBLE_EXECUTE],
            "SOUL-INV-041": [MutationType.EXPIRED_TIMELOCK, MutationType.SKIP_STEP],
            "SOUL-INV-042": [MutationType.MAX_UINT_AMOUNT],
            "SOUL-INV-050": [MutationType.CALLBACK_MANIPULATION],
            "SOUL-INV-051": [MutationType.CORRUPT_ENCRYPTED_STATE],
            "SOUL-INV-060": [MutationType.INTERESTING_ADDRESS, MutationType.DELEGATECALL_INJECTION],
            "SOUL-INV-061": [MutationType.SKIP_STEP, MutationType.EXPIRED_TIMELOCK],
            "SOUL-INV-070": [MutationType.DOUBLE_EXECUTE, MutationType.MAX_UINT_AMOUNT],
            "SOUL-INV-080": [MutationType.FLASH_LOAN_SEQUENCE],
            "SOUL-INV-090": [MutationType.CORRUPT_ENCRYPTED_STATE],
        }
        return mapping.get(invariant_id, [])

    def _get_function_mutations(self, function_name: str) -> list[MutationType]:
        """Map function names to relevant mutation types."""
        mapping = {
            "createStateLock": [MutationType.WRONG_CHAIN_ID, MutationType.WRONG_STATE_HASH],
            "unlockWithProof": [MutationType.CORRUPT_PROOF, MutationType.REPLAY_NULLIFIER, MutationType.DOUBLE_EXECUTE],
            "deposit": [MutationType.FLASH_LOAN_SEQUENCE, MutationType.DUST_AMOUNT, MutationType.MODIFY_COMMITMENT],
            "withdraw": [MutationType.REPLAY_NULLIFIER, MutationType.STALE_MERKLE_ROOT, MutationType.FLASH_LOAN_SEQUENCE],
            "registerNullifier": [MutationType.REPLAY_NULLIFIER, MutationType.ZERO_NULLIFIER],
            "submitProof": [MutationType.CORRUPT_PROOF, MutationType.DUPLICATE_RELAY],
            "aggregateAndRelay": [MutationType.DUPLICATE_RELAY, MutationType.WRONG_CHAIN_ID],
            "initiateSwap": [MutationType.EXPIRED_TIMELOCK, MutationType.DUST_AMOUNT],
            "completeSwap": [MutationType.WRONG_STATE_HASH],
            "refundSwap": [MutationType.SKIP_STEP],
            "crossChainTransfer": [MutationType.WRONG_CHAIN_ID, MutationType.CORRUPT_PROOF],
            "cancelLock": [MutationType.INTERESTING_ADDRESS],
            "createContainer": [MutationType.CORRUPT_ENCRYPTED_STATE, MutationType.CORRUPT_PROOF],
            "batchRegister": [MutationType.PARTIAL_BATCH_REPLAY],
            "computeNullifier": [MutationType.CROSS_DOMAIN_COLLISION],
            "registerModule": [MutationType.INTERESTING_ADDRESS, MutationType.DELEGATECALL_INJECTION],
            "executeOperation": [MutationType.DELEGATECALL_INJECTION, MutationType.REENTRANCY_PAYLOAD],
            "pause": [MutationType.INTERESTING_ADDRESS],
            "unpause": [MutationType.INTERESTING_ADDRESS],
            "emergencyWithdraw": [MutationType.INTERESTING_ADDRESS, MutationType.SKIP_STEP],
        }
        return mapping.get(function_name, [MutationType.BIT_FLIP, MutationType.BOUNDARY_VALUE])

    def generate_initial_seeds(
        self,
        contract_name: str,
        functions: list[dict[str, Any]],
    ) -> list[MutationSeed]:
        """Generate initial corpus seeds for a Soul Protocol contract.

        Creates seeds with both valid-looking and adversarial inputs
        for each function in the contract.
        """
        seeds = []

        for func_info in functions:
            func_name = func_info.get("name", "")
            params = func_info.get("parameters", [])

            # Generate base seed with typed defaults
            base_inputs = {}
            for param in params:
                param_name = param.get("name", "")
                param_type = param.get("type", "")
                base_inputs[param_name] = self._generate_typed_value(param_type, param_name)

            # Seed 1: default values
            seeds.append(MutationSeed(
                id=hashlib.md5(f"{contract_name}:{func_name}:default".encode()).hexdigest()[:16],
                function_name=func_name,
                contract_name=contract_name,
                inputs=dict(base_inputs),
            ))

            # Seed 2: zero values
            zero_inputs = {k: self._zero_value(v) for k, v in base_inputs.items()}
            seeds.append(MutationSeed(
                id=hashlib.md5(f"{contract_name}:{func_name}:zero".encode()).hexdigest()[:16],
                function_name=func_name,
                contract_name=contract_name,
                inputs=zero_inputs,
            ))

            # Seed 3: max values
            max_inputs = {k: self._max_value(v) for k, v in base_inputs.items()}
            seeds.append(MutationSeed(
                id=hashlib.md5(f"{contract_name}:{func_name}:max".encode()).hexdigest()[:16],
                function_name=func_name,
                contract_name=contract_name,
                inputs=max_inputs,
            ))

            # Seed 4: random values
            random_inputs = {}
            for param in params:
                param_name = param.get("name", "")
                param_type = param.get("type", "")
                random_inputs[param_name] = self._random_value(param_type)
            seeds.append(MutationSeed(
                id=hashlib.md5(f"{contract_name}:{func_name}:random".encode()).hexdigest()[:16],
                function_name=func_name,
                contract_name=contract_name,
                inputs=random_inputs,
            ))

        return seeds

    def _generate_typed_value(self, sol_type: str, param_name: str = "") -> Any:
        """Generate a plausible value for a Solidity type."""
        if sol_type in ("uint256", "uint128", "uint64", "uint32", "uint16"):
            if "chain" in param_name.lower():
                return 11155111  # Sepolia
            if "amount" in param_name.lower() or "value" in param_name.lower():
                return 10**18  # 1 ETH
            if "time" in param_name.lower() or "deadline" in param_name.lower():
                return int(time.time()) + 3600  # 1 hour from now
            return self.rng.randint(1, 2**64)

        if sol_type == "uint8":
            return self.rng.randint(0, 255)

        if sol_type == "int256":
            return self.rng.randint(-(2**127), 2**127)

        if sol_type == "bytes32":
            return int.from_bytes(os.urandom(32), "big")

        if sol_type == "bytes":
            return os.urandom(self.rng.choice([32, 64, 128, 256]))

        if sol_type == "address":
            return "0x" + os.urandom(20).hex()

        if sol_type == "bool":
            return self.rng.choice([True, False])

        if sol_type == "string":
            return "test_" + os.urandom(8).hex()

        if sol_type.endswith("[]"):
            base_type = sol_type[:-2]
            length = self.rng.randint(1, 5)
            return [self._generate_typed_value(base_type) for _ in range(length)]

        return 0

    def _zero_value(self, val: Any) -> Any:
        """Get zero/empty value for a type."""
        if isinstance(val, int):
            return 0
        if isinstance(val, (bytes, bytearray)):
            return b"\x00" * len(val)
        if isinstance(val, str):
            return "0x" + "0" * 40 if val.startswith("0x") else ""
        if isinstance(val, bool):
            return False
        if isinstance(val, list):
            return []
        return 0

    def _max_value(self, val: Any) -> Any:
        """Get max value for a type."""
        if isinstance(val, int):
            return 2**256 - 1
        if isinstance(val, (bytes, bytearray)):
            return b"\xff" * len(val)
        if isinstance(val, str):
            return "0x" + "f" * 40 if val.startswith("0x") else "x" * 256
        if isinstance(val, bool):
            return True
        if isinstance(val, list):
            return [self._max_value(val[0])] * 10 if val else []
        return 2**256 - 1

    def _random_value(self, sol_type: str) -> Any:
        """Generate a random value for a Solidity type."""
        if "uint" in sol_type or "int" in sol_type:
            return int.from_bytes(os.urandom(32), "big")
        if sol_type == "bytes32":
            return int.from_bytes(os.urandom(32), "big")
        if sol_type == "bytes":
            return os.urandom(self.rng.randint(1, 512))
        if sol_type == "address":
            return "0x" + os.urandom(20).hex()
        if sol_type == "bool":
            return self.rng.choice([True, False])
        return os.urandom(32)


# ── Multi-Transaction Sequence Mutation ──────────────────────────────────────


class SequenceMutationType(str, Enum):
    """Mutation types that operate on entire call sequences."""
    INSERT_RANDOM_TX = "insert_random_tx"
    DELETE_RANDOM_TX = "delete_random_tx"
    SWAP_ADJACENT_TX = "swap_adjacent_tx"
    DUPLICATE_TX = "duplicate_tx"
    MUTATE_SINGLE_TX = "mutate_single_tx"
    SPLICE_SEQUENCES = "splice_sequences"
    INTERLEAVE_SEQUENCES = "interleave_sequences"
    CHANGE_SENDER = "change_sender"
    INSERT_APPROVE_BEFORE = "insert_approve_before"
    ADD_SETUP_TX = "add_setup_tx"
    REVERSE_SEQUENCE = "reverse_sequence"
    TRIM_TAIL = "trim_tail"


@dataclass
class TxCall:
    """A single transaction call in a multi-tx sequence."""
    function: str
    sender: str = ""
    args: dict[str, Any] = field(default_factory=dict)
    value: int = 0
    contract: str = ""

    def clone(self) -> "TxCall":
        return TxCall(
            function=self.function,
            sender=self.sender,
            args=dict(self.args),
            value=self.value,
            contract=self.contract,
        )


@dataclass
class TxSequence:
    """A multi-transaction sequence for stateful fuzzing."""
    id: str
    calls: list[TxCall] = field(default_factory=list)
    mutation_history: list[SequenceMutationType] = field(default_factory=list)
    coverage_hash: str = ""
    interesting_score: float = 0.0
    generation: int = 0
    parent_id: str = ""

    @property
    def length(self) -> int:
        return len(self.calls)

    def clone(self) -> "TxSequence":
        return TxSequence(
            id=hashlib.md5(f"{self.id}:clone:{time.time()}".encode()).hexdigest()[:16],
            calls=[c.clone() for c in self.calls],
            mutation_history=list(self.mutation_history),
            coverage_hash=self.coverage_hash,
            interesting_score=self.interesting_score,
            generation=self.generation,
            parent_id=self.id,
        )


class SequenceMutationEngine:
    """Mutation engine that operates on multi-transaction sequences.

    While SoulMutationEngine mutates individual function inputs,
    SequenceMutationEngine mutates the *ordering*, *composition*,
    and *interleaving* of entire call sequences.

    Used by StatefulFuzzer (engine.fuzzer.stateful) to explore
    state-dependent vulnerabilities that require specific tx orderings.
    """

    def __init__(
        self,
        abi: list[dict[str, Any]],
        inner_mutator: SoulMutationEngine | None = None,
        seed: int | None = None,
        senders: list[str] | None = None,
    ) -> None:
        self._abi = abi
        self._inner = inner_mutator or SoulMutationEngine(seed=seed)
        self._rng = random.Random(seed)
        self._senders = senders or list(INTERESTING_ADDRESSES[:4])
        self._callable_functions = [
            e for e in abi
            if e.get("type") == "function"
            and e.get("stateMutability") not in ("view", "pure")
        ]

        self._weights: dict[SequenceMutationType, float] = {
            SequenceMutationType.INSERT_RANDOM_TX: 8.0,
            SequenceMutationType.DELETE_RANDOM_TX: 5.0,
            SequenceMutationType.SWAP_ADJACENT_TX: 7.0,
            SequenceMutationType.DUPLICATE_TX: 6.0,
            SequenceMutationType.MUTATE_SINGLE_TX: 9.0,
            SequenceMutationType.SPLICE_SEQUENCES: 7.0,
            SequenceMutationType.INTERLEAVE_SEQUENCES: 5.0,
            SequenceMutationType.CHANGE_SENDER: 6.0,
            SequenceMutationType.INSERT_APPROVE_BEFORE: 4.0,
            SequenceMutationType.ADD_SETUP_TX: 4.0,
            SequenceMutationType.REVERSE_SEQUENCE: 3.0,
            SequenceMutationType.TRIM_TAIL: 3.0,
        }

    def select_mutation(self) -> SequenceMutationType:
        """Select a sequence mutation type by weighted random."""
        types = list(self._weights.keys())
        weights = [self._weights[t] for t in types]
        return self._rng.choices(types, weights=weights, k=1)[0]

    def mutate(
        self,
        seq: TxSequence,
        donor: TxSequence | None = None,
    ) -> TxSequence:
        """Apply a random sequence mutation, returning a new TxSequence."""
        mutation_type = self.select_mutation()
        return self.apply_mutation(seq, mutation_type, donor=donor)

    def apply_mutation(
        self,
        seq: TxSequence,
        mutation_type: SequenceMutationType,
        donor: TxSequence | None = None,
    ) -> TxSequence:
        """Apply a specific sequence mutation."""
        new_seq = seq.clone()
        new_seq.generation += 1
        new_seq.parent_id = seq.id
        new_seq.id = hashlib.md5(
            f"{seq.id}:{mutation_type.value}:{time.time()}".encode()
        ).hexdigest()[:16]
        new_seq.mutation_history.append(mutation_type)

        handler = {
            SequenceMutationType.INSERT_RANDOM_TX: self._insert_random_tx,
            SequenceMutationType.DELETE_RANDOM_TX: self._delete_random_tx,
            SequenceMutationType.SWAP_ADJACENT_TX: self._swap_adjacent,
            SequenceMutationType.DUPLICATE_TX: self._duplicate_tx,
            SequenceMutationType.MUTATE_SINGLE_TX: self._mutate_single_tx,
            SequenceMutationType.SPLICE_SEQUENCES: self._splice,
            SequenceMutationType.INTERLEAVE_SEQUENCES: self._interleave,
            SequenceMutationType.CHANGE_SENDER: self._change_sender,
            SequenceMutationType.INSERT_APPROVE_BEFORE: self._insert_approve,
            SequenceMutationType.ADD_SETUP_TX: self._add_setup,
            SequenceMutationType.REVERSE_SEQUENCE: self._reverse,
            SequenceMutationType.TRIM_TAIL: self._trim_tail,
        }.get(mutation_type)

        if handler:
            handler(new_seq, donor)

        return new_seq

    # ── Mutation Operators ───────────────────────────────────────────

    def _insert_random_tx(self, seq: TxSequence, _donor: TxSequence | None) -> None:
        """Insert a random transaction at a random position."""
        tx = self._generate_random_call()
        pos = self._rng.randint(0, len(seq.calls))
        seq.calls.insert(pos, tx)

    def _delete_random_tx(self, seq: TxSequence, _donor: TxSequence | None) -> None:
        """Remove a random transaction from the sequence."""
        if len(seq.calls) > 1:
            idx = self._rng.randint(0, len(seq.calls) - 1)
            seq.calls.pop(idx)

    def _swap_adjacent(self, seq: TxSequence, _donor: TxSequence | None) -> None:
        """Swap two adjacent transactions."""
        if len(seq.calls) >= 2:
            idx = self._rng.randint(0, len(seq.calls) - 2)
            seq.calls[idx], seq.calls[idx + 1] = seq.calls[idx + 1], seq.calls[idx]

    def _duplicate_tx(self, seq: TxSequence, _donor: TxSequence | None) -> None:
        """Duplicate a random transaction (test idempotency)."""
        if seq.calls:
            idx = self._rng.randint(0, len(seq.calls) - 1)
            seq.calls.insert(idx + 1, seq.calls[idx].clone())

    def _mutate_single_tx(self, seq: TxSequence, _donor: TxSequence | None) -> None:
        """Mutate the inputs of a single transaction using the inner mutator."""
        if not seq.calls:
            return
        idx = self._rng.randint(0, len(seq.calls) - 1)
        tx = seq.calls[idx]
        # Create a temporary MutationSeed and mutate it
        temp_seed = MutationSeed(
            id=f"seq-{idx}",
            function_name=tx.function,
            contract_name=tx.contract,
            inputs=dict(tx.args),
            sequence=[],
        )
        mt = self._inner.select_mutation(target_function=tx.function)
        mutated = self._inner.mutate_seed(temp_seed, mt)
        tx.args = dict(mutated.inputs)

    def _splice(self, seq: TxSequence, donor: TxSequence | None) -> None:
        """Splice a segment from a donor sequence into this sequence."""
        if not donor or not donor.calls:
            self._insert_random_tx(seq, None)
            return
        # Take a random slice from donor
        start = self._rng.randint(0, max(0, len(donor.calls) - 1))
        end = self._rng.randint(start + 1, len(donor.calls))
        donor_slice = [c.clone() for c in donor.calls[start:end]]
        # Insert at random position
        pos = self._rng.randint(0, len(seq.calls))
        seq.calls[pos:pos] = donor_slice

    def _interleave(self, seq: TxSequence, donor: TxSequence | None) -> None:
        """Interleave transactions from a donor sequence."""
        if not donor or not donor.calls:
            self._insert_random_tx(seq, None)
            return
        merged: list[TxCall] = []
        a, b = list(seq.calls), [c.clone() for c in donor.calls]
        while a or b:
            if a and (not b or self._rng.random() < 0.5):
                merged.append(a.pop(0))
            elif b:
                merged.append(b.pop(0))
        seq.calls = merged

    def _change_sender(self, seq: TxSequence, _donor: TxSequence | None) -> None:
        """Change the sender of a random transaction."""
        if seq.calls:
            idx = self._rng.randint(0, len(seq.calls) - 1)
            seq.calls[idx].sender = self._rng.choice(self._senders)

    def _insert_approve(self, seq: TxSequence, _donor: TxSequence | None) -> None:
        """Insert an ERC-20 approve() call before a transfer-like tx."""
        for i, tx in enumerate(seq.calls):
            if tx.function in ("transfer", "transferFrom", "deposit", "swap"):
                approve_tx = TxCall(
                    function="approve",
                    sender=tx.sender,
                    args={"spender": tx.contract, "amount": 2**256 - 1},
                    contract=tx.contract,
                )
                seq.calls.insert(i, approve_tx)
                return
        # Fallback: insert generic approve at start
        seq.calls.insert(0, TxCall(
            function="approve",
            sender=self._rng.choice(self._senders),
            args={"spender": "target", "amount": 2**256 - 1},
        ))

    def _add_setup(self, seq: TxSequence, _donor: TxSequence | None) -> None:
        """Prepend a setup transaction (mint, deposit, etc.)."""
        setup_functions = ["mint", "deposit", "initialize", "setUp", "fund"]
        available = [f for f in self._callable_functions if f["name"] in setup_functions]
        if available:
            func = self._rng.choice(available)
            tx = self._make_call_from_abi(func)
            seq.calls.insert(0, tx)
        else:
            self._insert_random_tx(seq, None)

    def _reverse(self, seq: TxSequence, _donor: TxSequence | None) -> None:
        """Reverse the entire sequence."""
        seq.calls.reverse()

    def _trim_tail(self, seq: TxSequence, _donor: TxSequence | None) -> None:
        """Remove trailing transactions."""
        if len(seq.calls) > 2:
            trim = self._rng.randint(1, len(seq.calls) // 2)
            seq.calls = seq.calls[:-trim]

    # ── Helpers ──────────────────────────────────────────────────────

    def _generate_random_call(self) -> TxCall:
        """Generate a random TxCall from the ABI."""
        if self._callable_functions:
            func = self._rng.choice(self._callable_functions)
            return self._make_call_from_abi(func)
        return TxCall(
            function="fallback",
            sender=self._rng.choice(self._senders),
            value=self._rng.randint(0, 10**18),
        )

    def _make_call_from_abi(self, func: dict[str, Any]) -> TxCall:
        """Create a TxCall from an ABI function entry."""
        args: dict[str, Any] = {}
        for inp in func.get("inputs", []):
            name = inp.get("name", f"arg{len(args)}")
            typ = inp.get("type", "uint256")
            args[name] = self._inner._random_value(typ)

        value = 0
        if func.get("stateMutability") == "payable":
            value = self._rng.randint(0, 10**18)

        return TxCall(
            function=func["name"],
            sender=self._rng.choice(self._senders),
            args=args,
            value=value,
        )

    def generate_initial_sequence(self, length: int = 5) -> TxSequence:
        """Generate an initial random sequence."""
        seq = TxSequence(
            id=hashlib.md5(f"init:{time.time()}".encode()).hexdigest()[:16],
        )
        for _ in range(length):
            seq.calls.append(self._generate_random_call())
        return seq
