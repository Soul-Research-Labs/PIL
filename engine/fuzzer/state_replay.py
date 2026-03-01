"""State Snapshot & Replay Engine — time-travel debugging for Soul Protocol.

Checkpoints EVM state at interesting points, replays transactions with
modifications, enables time-travel debugging of violations, and provides
state-delta minimization for reproducing exploits.

Architecture:
  ┌──────────────────────────────────────────────────────────────────┐
  │             STATE  SNAPSHOT  &  REPLAY  ENGINE                  │
  │                                                                  │
  │  ┌──────────┐  ┌────────────┐  ┌──────────────┐  ┌──────────┐ │
  │  │Snapshot  │─►│State       │─►│Transaction   │─►│Replay    │ │
  │  │Manager   │  │Differ      │  │Replayer      │  │Debugger  │ │
  │  │          │  │            │  │              │  │          │ │
  │  └──────────┘  └────────────┘  └──────────────┘  └──────────┘ │
  │       │              │               │                   │      │
  │       ▼              ▼               ▼                   ▼      │
  │  ┌──────────┐  ┌────────────┐  ┌──────────────┐  ┌──────────┐ │
  │  │Fork      │  │Delta       │  │Mutation      │  │Violation │ │
  │  │Manager   │  │Compressor  │  │Replayer      │  │Bisector  │ │
  │  │          │  │            │  │              │  │          │ │
  │  └──────────┘  └────────────┘  └──────────────┘  └──────────┘ │
  │                                                                  │
  │  ┌──────────────────────────────────────────────────────────┐   │
  │  │ Soul Protocol State Patterns (nullifier sets, merkle     │   │
  │  │ trees, privacy pools, bridge escrows, lock states)       │   │
  │  └──────────────────────────────────────────────────────────┘   │
  └──────────────────────────────────────────────────────────────────┘
"""

from __future__ import annotations

import copy
import hashlib
import json
import logging
import time
from collections import deque
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

logger = logging.getLogger(__name__)


# ── Enums ────────────────────────────────────────────────────────────────────

class SnapshotTrigger(Enum):
    """What triggered the snapshot."""
    MANUAL = "manual"
    PERIODIC = "periodic"
    NEW_COVERAGE = "new_coverage"
    INVARIANT_VIOLATION = "invariant_violation"
    LARGE_STATE_CHANGE = "large_state_change"
    EXTERNAL_CALL = "external_call"
    STORAGE_WRITE = "storage_write"
    EVENT_EMISSION = "event_emission"
    PRE_TRANSACTION = "pre_transaction"
    POST_TRANSACTION = "post_transaction"
    CHECKPOINT = "checkpoint"
    FORK_POINT = "fork_point"


class ReplayMode(Enum):
    """Mode for transaction replay."""
    EXACT = "exact"              # Replay exactly as recorded
    MODIFIED = "modified"        # Replay with input modifications
    REVERSED = "reversed"        # Replay in reverse order
    SUBSET = "subset"            # Replay subset of transactions
    SHUFFLED = "shuffled"        # Replay in different order
    ACCELERATED = "accelerated"  # Skip non-essential transactions
    BISECT = "bisect"            # Binary search for minimal repro


class StateDiffType(Enum):
    """Type of state difference."""
    STORAGE_WRITE = "storage_write"
    BALANCE_CHANGE = "balance_change"
    NONCE_CHANGE = "nonce_change"
    CODE_CHANGE = "code_change"
    NULLIFIER_ADD = "nullifier_add"
    MERKLE_UPDATE = "merkle_update"
    LOCK_STATE_CHANGE = "lock_state_change"
    POOL_BALANCE_CHANGE = "pool_balance_change"
    BRIDGE_ESCROW_CHANGE = "bridge_escrow_change"
    ACCESS_CONTROL_CHANGE = "access_control_change"


# ── Data Classes ─────────────────────────────────────────────────────────────

@dataclass
class StorageState:
    """Complete storage state at a point in time."""
    slots: dict[int, int] = field(default_factory=dict)  # slot → value
    balances: dict[str, int] = field(default_factory=dict)  # address → balance
    nonces: dict[str, int] = field(default_factory=dict)  # address → nonce
    code: dict[str, bytes] = field(default_factory=dict)  # address → bytecode

    # Soul Protocol-specific state
    nullifier_set: set[str] = field(default_factory=set)
    merkle_roots: list[str] = field(default_factory=list)
    active_locks: dict[str, dict[str, Any]] = field(default_factory=dict)
    pool_balances: dict[str, int] = field(default_factory=dict)
    bridge_escrows: dict[str, dict[str, Any]] = field(default_factory=dict)
    rate_limit_counters: dict[str, int] = field(default_factory=dict)
    module_registry: dict[str, str] = field(default_factory=dict)

    def hash(self) -> str:
        """Compute state hash for comparison."""
        content = json.dumps({
            "slots": {str(k): str(v) for k, v in sorted(self.slots.items())},
            "balances": dict(sorted(self.balances.items())),
            "nullifiers": sorted(self.nullifier_set),
            "merkle_roots": self.merkle_roots[-5:] if self.merkle_roots else [],
            "locks": len(self.active_locks),
            "pools": dict(sorted(self.pool_balances.items())),
        }, sort_keys=True)
        return hashlib.sha256(content.encode()).hexdigest()[:16]

    def clone(self) -> "StorageState":
        """Deep-copy the state."""
        return StorageState(
            slots=dict(self.slots),
            balances=dict(self.balances),
            nonces=dict(self.nonces),
            code=dict(self.code),
            nullifier_set=set(self.nullifier_set),
            merkle_roots=list(self.merkle_roots),
            active_locks=copy.deepcopy(self.active_locks),
            pool_balances=dict(self.pool_balances),
            bridge_escrows=copy.deepcopy(self.bridge_escrows),
            rate_limit_counters=dict(self.rate_limit_counters),
            module_registry=dict(self.module_registry),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "storage_slots": len(self.slots),
            "accounts": len(self.balances),
            "nullifiers": len(self.nullifier_set),
            "merkle_roots": len(self.merkle_roots),
            "active_locks": len(self.active_locks),
            "pools": len(self.pool_balances),
            "bridge_escrows": len(self.bridge_escrows),
            "hash": self.hash(),
        }


@dataclass
class StateDiff:
    """Difference between two states."""
    diffs: list[dict[str, Any]] = field(default_factory=list)
    added_slots: dict[int, int] = field(default_factory=dict)
    modified_slots: dict[int, tuple[int, int]] = field(default_factory=dict)  # slot → (old, new)
    removed_slots: set[int] = field(default_factory=set)
    balance_changes: dict[str, tuple[int, int]] = field(default_factory=dict)
    new_nullifiers: set[str] = field(default_factory=set)
    merkle_root_changed: bool = False
    lock_changes: dict[str, str] = field(default_factory=dict)  # lock_id → change_type
    pool_balance_delta: dict[str, int] = field(default_factory=dict)

    @property
    def is_empty(self) -> bool:
        return (
            not self.added_slots
            and not self.modified_slots
            and not self.removed_slots
            and not self.balance_changes
            and not self.new_nullifiers
            and not self.merkle_root_changed
            and not self.lock_changes
            and not self.pool_balance_delta
        )

    @property
    def change_count(self) -> int:
        return (
            len(self.added_slots)
            + len(self.modified_slots)
            + len(self.removed_slots)
            + len(self.balance_changes)
            + len(self.new_nullifiers)
            + (1 if self.merkle_root_changed else 0)
            + len(self.lock_changes)
            + len(self.pool_balance_delta)
        )

    @property
    def is_large(self) -> bool:
        return self.change_count > 10

    def to_dict(self) -> dict[str, Any]:
        return {
            "change_count": self.change_count,
            "added_slots": len(self.added_slots),
            "modified_slots": len(self.modified_slots),
            "removed_slots": len(self.removed_slots),
            "balance_changes": len(self.balance_changes),
            "new_nullifiers": len(self.new_nullifiers),
            "merkle_root_changed": self.merkle_root_changed,
            "lock_changes": len(self.lock_changes),
            "pool_balance_delta": self.pool_balance_delta,
            "is_large": self.is_large,
        }


@dataclass
class TransactionRecord:
    """Record of a transaction for replay."""
    tx_id: str = ""
    tx_index: int = 0
    from_address: str = ""
    to_address: str = ""
    function_name: str = ""
    function_selector: str = ""
    calldata: bytes = b""
    value: int = 0
    gas_limit: int = 10_000_000
    inputs: dict[str, Any] = field(default_factory=dict)
    mutation_type: str = ""

    # Execution results
    success: bool = False
    return_data: bytes = b""
    gas_used: int = 0
    revert_reason: str = ""
    events: list[dict[str, Any]] = field(default_factory=list)

    # State tracking
    state_before_hash: str = ""
    state_after_hash: str = ""
    state_diff: StateDiff | None = None

    timestamp: float = 0.0
    block_number: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "tx_id": self.tx_id,
            "tx_index": self.tx_index,
            "from": self.from_address,
            "to": self.to_address,
            "function": self.function_name,
            "selector": self.function_selector,
            "value": self.value,
            "mutation": self.mutation_type,
            "success": self.success,
            "gas_used": self.gas_used,
            "revert_reason": self.revert_reason,
            "event_count": len(self.events),
            "state_diff": self.state_diff.to_dict() if self.state_diff else None,
        }


@dataclass
class StateSnapshot:
    """A checkpoint of the complete state."""
    snapshot_id: str = ""
    timestamp: float = 0.0
    trigger: SnapshotTrigger = SnapshotTrigger.MANUAL
    state: StorageState = field(default_factory=StorageState)
    tx_index: int = 0  # transaction index when snapshot was taken
    campaign_iteration: int = 0
    metadata: dict[str, Any] = field(default_factory=dict)

    # Linkage
    parent_snapshot_id: str = ""
    child_snapshot_ids: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "snapshot_id": self.snapshot_id,
            "timestamp": self.timestamp,
            "trigger": self.trigger.value,
            "tx_index": self.tx_index,
            "campaign_iteration": self.campaign_iteration,
            "state": self.state.to_dict(),
            "parent": self.parent_snapshot_id,
            "children": len(self.child_snapshot_ids),
            "metadata": self.metadata,
        }


@dataclass
class ReplayResult:
    """Result of a transaction replay."""
    mode: ReplayMode = ReplayMode.EXACT
    transactions_replayed: int = 0
    success: bool = False
    violation_reproduced: bool = False
    violation_at_tx: int = -1
    minimal_sequence_length: int = 0
    state_divergence_at: int = -1  # tx index where state diverges
    total_gas: int = 0
    replay_time_sec: float = 0.0
    transaction_results: list[dict[str, Any]] = field(default_factory=list)
    state_diffs: list[StateDiff] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "mode": self.mode.value,
            "transactions_replayed": self.transactions_replayed,
            "success": self.success,
            "violation_reproduced": self.violation_reproduced,
            "violation_at_tx": self.violation_at_tx,
            "minimal_sequence_length": self.minimal_sequence_length,
            "state_divergence_at": self.state_divergence_at,
            "total_gas": self.total_gas,
            "replay_time_sec": round(self.replay_time_sec, 3),
            "transaction_results": self.transaction_results[:50],
        }


# ── State Differ ─────────────────────────────────────────────────────────────

class StateDiffer:
    """Computes differences between two storage states."""

    def diff(self, before: StorageState, after: StorageState) -> StateDiff:
        """Compute the diff between two states."""
        result = StateDiff()

        # Storage slot diffs
        all_slots = set(before.slots.keys()) | set(after.slots.keys())
        for slot in all_slots:
            b_val = before.slots.get(slot)
            a_val = after.slots.get(slot)

            if b_val is None and a_val is not None:
                result.added_slots[slot] = a_val
            elif b_val is not None and a_val is None:
                result.removed_slots.add(slot)
            elif b_val != a_val:
                result.modified_slots[slot] = (b_val, a_val)

        # Balance diffs
        all_addrs = set(before.balances.keys()) | set(after.balances.keys())
        for addr in all_addrs:
            b_bal = before.balances.get(addr, 0)
            a_bal = after.balances.get(addr, 0)
            if b_bal != a_bal:
                result.balance_changes[addr] = (b_bal, a_bal)

        # Nullifier diffs
        result.new_nullifiers = after.nullifier_set - before.nullifier_set

        # Merkle root change
        b_root = before.merkle_roots[-1] if before.merkle_roots else ""
        a_root = after.merkle_roots[-1] if after.merkle_roots else ""
        result.merkle_root_changed = b_root != a_root

        # Lock changes
        all_locks = set(before.active_locks.keys()) | set(after.active_locks.keys())
        for lock_id in all_locks:
            if lock_id not in before.active_locks:
                result.lock_changes[lock_id] = "created"
            elif lock_id not in after.active_locks:
                result.lock_changes[lock_id] = "removed"
            elif before.active_locks[lock_id] != after.active_locks[lock_id]:
                result.lock_changes[lock_id] = "modified"

        # Pool balance deltas
        all_pools = set(before.pool_balances.keys()) | set(after.pool_balances.keys())
        for pool in all_pools:
            b_bal = before.pool_balances.get(pool, 0)
            a_bal = after.pool_balances.get(pool, 0)
            delta = a_bal - b_bal
            if delta != 0:
                result.pool_balance_delta[pool] = delta

        return result

    def summarize(self, diff: StateDiff) -> str:
        """Generate human-readable diff summary."""
        parts: list[str] = []

        if diff.added_slots:
            parts.append(f"+{len(diff.added_slots)} storage slots")
        if diff.modified_slots:
            parts.append(f"~{len(diff.modified_slots)} modified slots")
        if diff.removed_slots:
            parts.append(f"-{len(diff.removed_slots)} removed slots")
        if diff.balance_changes:
            parts.append(f"${len(diff.balance_changes)} balance changes")
        if diff.new_nullifiers:
            parts.append(f"#{len(diff.new_nullifiers)} new nullifiers")
        if diff.merkle_root_changed:
            parts.append("merkle root updated")
        if diff.lock_changes:
            parts.append(f"L{len(diff.lock_changes)} lock changes")
        if diff.pool_balance_delta:
            parts.append(f"P{len(diff.pool_balance_delta)} pool deltas")

        return "; ".join(parts) if parts else "no changes"


# ── Snapshot Manager ─────────────────────────────────────────────────────────

class SnapshotManager:
    """Manages state snapshots for time-travel debugging."""

    def __init__(
        self,
        max_snapshots: int = 500,
        auto_snapshot_interval: int = 100,
    ) -> None:
        self._snapshots: dict[str, StateSnapshot] = {}
        self._snapshot_order: list[str] = []
        self._max_snapshots = max_snapshots
        self._auto_interval = auto_snapshot_interval
        self._snapshot_counter = 0
        self._differ = StateDiffer()

    def take_snapshot(
        self,
        state: StorageState,
        trigger: SnapshotTrigger = SnapshotTrigger.MANUAL,
        tx_index: int = 0,
        iteration: int = 0,
        metadata: dict[str, Any] | None = None,
        parent_id: str = "",
    ) -> StateSnapshot:
        """Take a state snapshot."""
        self._snapshot_counter += 1
        snapshot_id = f"snap-{self._snapshot_counter:06d}-{state.hash()}"

        snapshot = StateSnapshot(
            snapshot_id=snapshot_id,
            timestamp=time.time(),
            trigger=trigger,
            state=state.clone(),
            tx_index=tx_index,
            campaign_iteration=iteration,
            metadata=metadata or {},
            parent_snapshot_id=parent_id,
        )

        # Link to parent
        if parent_id and parent_id in self._snapshots:
            self._snapshots[parent_id].child_snapshot_ids.append(snapshot_id)

        self._snapshots[snapshot_id] = snapshot
        self._snapshot_order.append(snapshot_id)

        # Evict old snapshots if over limit
        while len(self._snapshots) > self._max_snapshots:
            self._evict_oldest()

        logger.debug("Snapshot %s taken (trigger=%s, tx=%d)", snapshot_id, trigger.value, tx_index)
        return snapshot

    def get_snapshot(self, snapshot_id: str) -> StateSnapshot | None:
        """Retrieve a snapshot by ID."""
        return self._snapshots.get(snapshot_id)

    def get_latest(self) -> StateSnapshot | None:
        """Get the most recent snapshot."""
        if self._snapshot_order:
            return self._snapshots.get(self._snapshot_order[-1])
        return None

    def get_nearest(self, tx_index: int) -> StateSnapshot | None:
        """Get the snapshot nearest to (but not after) a transaction index."""
        best: StateSnapshot | None = None
        for snap_id in self._snapshot_order:
            snap = self._snapshots.get(snap_id)
            if snap and snap.tx_index <= tx_index:
                if best is None or snap.tx_index > best.tx_index:
                    best = snap
        return best

    def diff_snapshots(
        self, snapshot_a_id: str, snapshot_b_id: str,
    ) -> StateDiff | None:
        """Compute diff between two snapshots."""
        a = self._snapshots.get(snapshot_a_id)
        b = self._snapshots.get(snapshot_b_id)
        if not a or not b:
            return None
        return self._differ.diff(a.state, b.state)

    def get_timeline(self) -> list[dict[str, Any]]:
        """Get snapshot timeline for visualization."""
        timeline: list[dict[str, Any]] = []
        for snap_id in self._snapshot_order:
            snap = self._snapshots.get(snap_id)
            if snap:
                timeline.append(snap.to_dict())
        return timeline

    def should_auto_snapshot(self, tx_index: int) -> bool:
        """Check if auto-snapshot should be triggered."""
        return tx_index % self._auto_interval == 0

    def _evict_oldest(self) -> None:
        """Evict the oldest non-critical snapshot."""
        # Keep invariant-violation and fork-point snapshots
        for snap_id in list(self._snapshot_order):
            snap = self._snapshots.get(snap_id)
            if snap and snap.trigger not in (
                SnapshotTrigger.INVARIANT_VIOLATION,
                SnapshotTrigger.FORK_POINT,
            ):
                del self._snapshots[snap_id]
                self._snapshot_order.remove(snap_id)
                return

        # Last resort: evict oldest
        if self._snapshot_order:
            old_id = self._snapshot_order.pop(0)
            self._snapshots.pop(old_id, None)

    @property
    def snapshot_count(self) -> int:
        return len(self._snapshots)

    def get_stats(self) -> dict[str, Any]:
        triggers: dict[str, int] = {}
        for snap in self._snapshots.values():
            t = snap.trigger.value
            triggers[t] = triggers.get(t, 0) + 1

        return {
            "total_snapshots": self.snapshot_count,
            "snapshots_by_trigger": triggers,
            "oldest_tx_index": (
                self._snapshots[self._snapshot_order[0]].tx_index
                if self._snapshot_order else 0
            ),
            "newest_tx_index": (
                self._snapshots[self._snapshot_order[-1]].tx_index
                if self._snapshot_order else 0
            ),
        }


# ── Transaction Replayer ─────────────────────────────────────────────────────

class TransactionReplayer:
    """Replays recorded transactions with optional modifications."""

    def __init__(
        self,
        executor: Any | None = None,
        snapshot_manager: SnapshotManager | None = None,
    ) -> None:
        self._executor = executor
        self._snapshot_manager = snapshot_manager or SnapshotManager()
        self._differ = StateDiffer()
        self._recorded_txs: list[TransactionRecord] = []

    def record_transaction(self, tx: TransactionRecord) -> None:
        """Record a transaction for potential replay."""
        tx.tx_index = len(self._recorded_txs)
        self._recorded_txs.append(tx)

    def replay_exact(
        self,
        start_snapshot_id: str = "",
        tx_range: tuple[int, int] | None = None,
    ) -> ReplayResult:
        """Replay transactions exactly as recorded."""
        return self._replay(
            mode=ReplayMode.EXACT,
            start_snapshot_id=start_snapshot_id,
            tx_range=tx_range,
        )

    def replay_modified(
        self,
        modifications: dict[int, dict[str, Any]],
        start_snapshot_id: str = "",
    ) -> ReplayResult:
        """Replay with modifications to specific transactions.

        Args:
            modifications: {tx_index: {field: new_value}}
        """
        return self._replay(
            mode=ReplayMode.MODIFIED,
            start_snapshot_id=start_snapshot_id,
            modifications=modifications,
        )

    def replay_subset(
        self,
        tx_indices: list[int],
        start_snapshot_id: str = "",
    ) -> ReplayResult:
        """Replay only a subset of transactions."""
        return self._replay(
            mode=ReplayMode.SUBSET,
            start_snapshot_id=start_snapshot_id,
            tx_indices=tx_indices,
        )

    def bisect_violation(
        self,
        violation_tx_index: int,
        check_fn: Any | None = None,
    ) -> ReplayResult:
        """Binary search for minimal transaction sequence to reproduce violation."""
        result = ReplayResult(mode=ReplayMode.BISECT)
        start = time.time()

        if violation_tx_index >= len(self._recorded_txs):
            return result

        # Start with full sequence [0, violation_tx_index]
        full_range = list(range(violation_tx_index + 1))
        minimal = self._minimize_sequence(full_range, check_fn)

        result.transactions_replayed = len(minimal)
        result.minimal_sequence_length = len(minimal)
        result.violation_reproduced = len(minimal) < len(full_range)
        result.replay_time_sec = time.time() - start

        return result

    def _replay(
        self,
        mode: ReplayMode,
        start_snapshot_id: str = "",
        tx_range: tuple[int, int] | None = None,
        modifications: dict[int, dict[str, Any]] | None = None,
        tx_indices: list[int] | None = None,
    ) -> ReplayResult:
        """Internal replay implementation."""
        result = ReplayResult(mode=mode)
        start = time.time()

        # Restore state from snapshot if provided
        if start_snapshot_id:
            snapshot = self._snapshot_manager.get_snapshot(start_snapshot_id)
            if snapshot:
                current_state = snapshot.state.clone()
            else:
                current_state = StorageState()
        else:
            current_state = StorageState()

        # Determine transactions to replay
        if tx_indices is not None:
            txs_to_replay = [
                self._recorded_txs[i] for i in tx_indices
                if 0 <= i < len(self._recorded_txs)
            ]
        elif tx_range:
            start_idx, end_idx = tx_range
            txs_to_replay = self._recorded_txs[start_idx:end_idx]
        else:
            txs_to_replay = self._recorded_txs

        # Replay
        for tx in txs_to_replay:
            state_before = current_state.clone()

            # Apply modifications if any
            if modifications and tx.tx_index in modifications:
                tx = self._apply_modification(tx, modifications[tx.tx_index])

            # Execute transaction
            tx_result = self._execute_tx(tx, current_state)
            result.transaction_results.append(tx_result)
            result.transactions_replayed += 1
            result.total_gas += tx_result.get("gas_used", 0)

            # Compute state diff
            state_after = self._get_post_state(current_state, tx_result)
            diff = self._differ.diff(state_before, state_after)
            result.state_diffs.append(diff)

            current_state = state_after

        result.success = True
        result.replay_time_sec = time.time() - start
        return result

    def _execute_tx(
        self,
        tx: TransactionRecord,
        current_state: StorageState,
    ) -> dict[str, Any]:
        """Execute a transaction against executor or simulate."""
        if self._executor:
            try:
                exec_result = self._executor.execute({
                    "from": tx.from_address,
                    "to": tx.to_address,
                    "function": tx.function_name,
                    "inputs": tx.inputs,
                    "value": tx.value,
                    "gas_limit": tx.gas_limit,
                })
                return {
                    "tx_id": tx.tx_id,
                    "success": exec_result.get("success", False),
                    "gas_used": exec_result.get("gas_used", 0),
                    "revert_reason": exec_result.get("revert_reason", ""),
                    "events": exec_result.get("events", []),
                    "state_changes": exec_result.get("state_changes", {}),
                }
            except Exception as e:
                return {
                    "tx_id": tx.tx_id,
                    "success": False,
                    "gas_used": 0,
                    "revert_reason": str(e),
                    "events": [],
                    "state_changes": {},
                }

        # Simulation mode
        return {
            "tx_id": tx.tx_id,
            "success": tx.success,
            "gas_used": tx.gas_used,
            "revert_reason": tx.revert_reason,
            "events": tx.events,
            "state_changes": {},
        }

    def _apply_modification(
        self,
        tx: TransactionRecord,
        mods: dict[str, Any],
    ) -> TransactionRecord:
        """Apply modifications to a transaction for replay."""
        modified = TransactionRecord(
            tx_id=tx.tx_id,
            tx_index=tx.tx_index,
            from_address=mods.get("from", tx.from_address),
            to_address=mods.get("to", tx.to_address),
            function_name=mods.get("function", tx.function_name),
            function_selector=tx.function_selector,
            calldata=mods.get("calldata", tx.calldata),
            value=mods.get("value", tx.value),
            gas_limit=mods.get("gas_limit", tx.gas_limit),
            inputs={**tx.inputs, **mods.get("inputs", {})},
            mutation_type=mods.get("mutation_type", tx.mutation_type),
        )
        return modified

    def _get_post_state(
        self,
        current_state: StorageState,
        tx_result: dict[str, Any],
    ) -> StorageState:
        """Compute post-transaction state."""
        new_state = current_state.clone()

        for change in tx_result.get("state_changes", {}).items():
            if isinstance(change, tuple) and len(change) == 2:
                key, value = change
                if isinstance(key, int):
                    new_state.slots[key] = value

        return new_state

    def _minimize_sequence(
        self,
        tx_indices: list[int],
        check_fn: Any | None = None,
    ) -> list[int]:
        """Delta-debugging minimization of transaction sequence."""
        if len(tx_indices) <= 1:
            return tx_indices

        # Binary search: try removing halves
        mid = len(tx_indices) // 2
        first_half = tx_indices[:mid]
        second_half = tx_indices[mid:]

        # Try just second half (skip first half)
        if check_fn and self._test_sequence(second_half, check_fn):
            return self._minimize_sequence(second_half, check_fn)

        # Try just first half
        if check_fn and self._test_sequence(first_half, check_fn):
            return self._minimize_sequence(first_half, check_fn)

        # Both needed — try removing individual elements
        for i in range(len(tx_indices)):
            reduced = tx_indices[:i] + tx_indices[i + 1:]
            if check_fn and self._test_sequence(reduced, check_fn):
                return self._minimize_sequence(reduced, check_fn)

        return tx_indices  # Cannot reduce further

    def _test_sequence(
        self,
        tx_indices: list[int],
        check_fn: Any,
    ) -> bool:
        """Test if a transaction sequence still triggers the violation."""
        result = self._replay(
            mode=ReplayMode.SUBSET,
            tx_indices=tx_indices,
        )
        return check_fn(result) if check_fn else False

    @property
    def recorded_tx_count(self) -> int:
        return len(self._recorded_txs)


# ── Fork Manager ─────────────────────────────────────────────────────────────

class ForkManager:
    """Manages forked execution paths for exploring alternative scenarios.

    Supports creating forks from snapshots, running divergent transaction
    sequences, and comparing outcomes.
    """

    def __init__(
        self,
        snapshot_manager: SnapshotManager | None = None,
    ) -> None:
        self._snapshot_manager = snapshot_manager or SnapshotManager()
        self._forks: dict[str, dict[str, Any]] = {}
        self._fork_counter = 0

    def create_fork(
        self,
        from_snapshot_id: str,
        description: str = "",
    ) -> str:
        """Create a new fork from a snapshot."""
        snapshot = self._snapshot_manager.get_snapshot(from_snapshot_id)
        if not snapshot:
            raise ValueError(f"Snapshot {from_snapshot_id} not found")

        self._fork_counter += 1
        fork_id = f"fork-{self._fork_counter:04d}"

        # Take fork-point snapshot
        fork_snapshot = self._snapshot_manager.take_snapshot(
            state=snapshot.state,
            trigger=SnapshotTrigger.FORK_POINT,
            tx_index=snapshot.tx_index,
            metadata={"fork_id": fork_id, "description": description},
            parent_id=from_snapshot_id,
        )

        self._forks[fork_id] = {
            "id": fork_id,
            "from_snapshot": from_snapshot_id,
            "fork_snapshot": fork_snapshot.snapshot_id,
            "description": description,
            "created_at": time.time(),
            "transactions": [],
            "current_state": snapshot.state.clone(),
        }

        logger.info("Fork %s created from snapshot %s", fork_id, from_snapshot_id)
        return fork_id

    def execute_on_fork(
        self,
        fork_id: str,
        tx: TransactionRecord,
    ) -> dict[str, Any]:
        """Execute a transaction on a forked state."""
        fork = self._forks.get(fork_id)
        if not fork:
            raise ValueError(f"Fork {fork_id} not found")

        fork["transactions"].append(tx.to_dict())

        return {
            "fork_id": fork_id,
            "tx_index": len(fork["transactions"]) - 1,
            "executed": True,
        }

    def compare_forks(
        self,
        fork_a_id: str,
        fork_b_id: str,
    ) -> dict[str, Any]:
        """Compare final states of two forks."""
        fork_a = self._forks.get(fork_a_id)
        fork_b = self._forks.get(fork_b_id)

        if not fork_a or not fork_b:
            return {"error": "Fork not found"}

        differ = StateDiffer()
        diff = differ.diff(fork_a["current_state"], fork_b["current_state"])

        return {
            "fork_a": fork_a_id,
            "fork_b": fork_b_id,
            "fork_a_txs": len(fork_a["transactions"]),
            "fork_b_txs": len(fork_b["transactions"]),
            "state_diff": diff.to_dict(),
            "diff_summary": differ.summarize(diff),
        }

    def get_fork_tree(self) -> list[dict[str, Any]]:
        """Get fork tree for visualization."""
        return [
            {
                "id": f["id"],
                "from_snapshot": f["from_snapshot"],
                "description": f["description"],
                "tx_count": len(f["transactions"]),
                "created_at": f["created_at"],
            }
            for f in self._forks.values()
        ]

    @property
    def fork_count(self) -> int:
        return len(self._forks)


# ── Violation Bisector ───────────────────────────────────────────────────────

class ViolationBisector:
    """Binary search through state history to find exact violation point."""

    def __init__(
        self,
        snapshot_manager: SnapshotManager,
        replayer: TransactionReplayer,
    ) -> None:
        self._snapshot_manager = snapshot_manager
        self._replayer = replayer

    def bisect(
        self,
        violation_invariant: str,
        check_fn: Any | None = None,
    ) -> dict[str, Any]:
        """Find the exact transaction that first causes a violation."""
        snapshots = self._snapshot_manager.get_timeline()
        if not snapshots:
            return {"error": "No snapshots available"}

        total_txs = self._replayer.recorded_tx_count
        if total_txs == 0:
            return {"error": "No transactions recorded"}

        # Binary search over transaction indices
        lo, hi = 0, total_txs - 1
        result_tx = -1

        while lo <= hi:
            mid = (lo + hi) // 2

            # Replay [0..mid] and check invariant
            replay_result = self._replayer.replay_exact(
                tx_range=(0, mid + 1),
            )

            if self._check_violation(replay_result, violation_invariant, check_fn):
                result_tx = mid
                hi = mid - 1
            else:
                lo = mid + 1

        return {
            "invariant": violation_invariant,
            "first_violation_tx": result_tx,
            "total_transactions": total_txs,
            "search_steps": int(math.log2(total_txs)) + 1 if total_txs > 0 else 0,
        }

    def _check_violation(
        self,
        replay_result: ReplayResult,
        invariant: str,
        check_fn: Any | None,
    ) -> bool:
        """Check if replay result contains the target violation."""
        if check_fn:
            return check_fn(replay_result)

        # Simple heuristic: check if any transaction failed unexpectedly
        for tx_result in replay_result.transaction_results:
            if not tx_result.get("success", True) and invariant in str(tx_result):
                return True

        return False


# ── Main State Replay Engine ─────────────────────────────────────────────────

class StateReplayEngine:
    """Complete state snapshot & replay engine for Soul Protocol.

    Provides time-travel debugging, transaction replay with modifications,
    fork management for counterfactual analysis, and violation bisection.

    Usage:
        engine = StateReplayEngine()
        # Record transactions during fuzzing
        engine.record_transaction(tx)
        # Take snapshots at interesting points
        engine.take_snapshot(state, trigger=SnapshotTrigger.NEW_COVERAGE)
        # Replay to reproduce a violation
        result = engine.replay_exact(start_snapshot="snap-001")
        # Minimize violation sequence
        minimal = engine.bisect_violation("SOUL-INV-001")
    """

    def __init__(
        self,
        executor: Any | None = None,
        max_snapshots: int = 500,
        auto_snapshot_interval: int = 100,
    ) -> None:
        self._snapshot_manager = SnapshotManager(
            max_snapshots=max_snapshots,
            auto_snapshot_interval=auto_snapshot_interval,
        )
        self._replayer = TransactionReplayer(
            executor=executor,
            snapshot_manager=self._snapshot_manager,
        )
        self._fork_manager = ForkManager(
            snapshot_manager=self._snapshot_manager,
        )
        self._bisector = ViolationBisector(
            snapshot_manager=self._snapshot_manager,
            replayer=self._replayer,
        )
        self._differ = StateDiffer()
        self._current_state = StorageState()
        self._tx_counter = 0

    def record_transaction(
        self,
        function_name: str,
        inputs: dict[str, Any],
        from_address: str = "",
        value: int = 0,
        success: bool = True,
        gas_used: int = 0,
        revert_reason: str = "",
        events: list[dict[str, Any]] | None = None,
        state_changes: dict[str, Any] | None = None,
    ) -> TransactionRecord:
        """Record a transaction and optionally auto-snapshot."""
        self._tx_counter += 1
        tx = TransactionRecord(
            tx_id=f"tx-{self._tx_counter:08d}",
            tx_index=self._tx_counter - 1,
            from_address=from_address,
            function_name=function_name,
            inputs=inputs,
            value=value,
            success=success,
            gas_used=gas_used,
            revert_reason=revert_reason,
            events=events or [],
            timestamp=time.time(),
            state_before_hash=self._current_state.hash(),
        )

        # Apply state changes
        if state_changes:
            self._apply_state_changes(state_changes)
        tx.state_after_hash = self._current_state.hash()

        self._replayer.record_transaction(tx)

        # Auto-snapshot check
        if self._snapshot_manager.should_auto_snapshot(self._tx_counter):
            self.take_snapshot(
                trigger=SnapshotTrigger.PERIODIC,
            )

        return tx

    def take_snapshot(
        self,
        trigger: SnapshotTrigger = SnapshotTrigger.MANUAL,
        metadata: dict[str, Any] | None = None,
        iteration: int = 0,
    ) -> StateSnapshot:
        """Take a snapshot of the current state."""
        return self._snapshot_manager.take_snapshot(
            state=self._current_state,
            trigger=trigger,
            tx_index=self._tx_counter,
            iteration=iteration,
            metadata=metadata,
        )

    def replay_exact(
        self,
        start_snapshot: str = "",
        tx_range: tuple[int, int] | None = None,
    ) -> ReplayResult:
        """Replay transactions exactly."""
        return self._replayer.replay_exact(start_snapshot, tx_range)

    def replay_modified(
        self,
        modifications: dict[int, dict[str, Any]],
        start_snapshot: str = "",
    ) -> ReplayResult:
        """Replay with modifications."""
        return self._replayer.replay_modified(modifications, start_snapshot)

    def replay_subset(
        self,
        tx_indices: list[int],
        start_snapshot: str = "",
    ) -> ReplayResult:
        """Replay subset of transactions."""
        return self._replayer.replay_subset(tx_indices, start_snapshot)

    def bisect_violation(
        self,
        invariant: str,
        check_fn: Any | None = None,
    ) -> dict[str, Any]:
        """Find minimal transaction to reproduce violation."""
        return self._bisector.bisect(invariant, check_fn)

    def create_fork(
        self,
        from_snapshot: str,
        description: str = "",
    ) -> str:
        """Create a fork for counterfactual analysis."""
        return self._fork_manager.create_fork(from_snapshot, description)

    def compare_forks(self, fork_a: str, fork_b: str) -> dict[str, Any]:
        """Compare two forked execution paths."""
        return self._fork_manager.compare_forks(fork_a, fork_b)

    def get_state_at_snapshot(self, snapshot_id: str) -> StorageState | None:
        """Get state at a specific snapshot."""
        snap = self._snapshot_manager.get_snapshot(snapshot_id)
        return snap.state if snap else None

    def diff_states(
        self, snapshot_a: str, snapshot_b: str,
    ) -> StateDiff | None:
        """Diff states between two snapshots."""
        return self._snapshot_manager.diff_snapshots(snapshot_a, snapshot_b)

    def update_soul_state(
        self,
        nullifiers: set[str] | None = None,
        merkle_root: str = "",
        locks: dict[str, dict[str, Any]] | None = None,
        pool_balances: dict[str, int] | None = None,
        bridge_escrows: dict[str, dict[str, Any]] | None = None,
    ) -> None:
        """Update Soul Protocol-specific state."""
        if nullifiers:
            self._current_state.nullifier_set.update(nullifiers)
        if merkle_root:
            self._current_state.merkle_roots.append(merkle_root)
        if locks:
            self._current_state.active_locks.update(locks)
        if pool_balances:
            self._current_state.pool_balances.update(pool_balances)
        if bridge_escrows:
            self._current_state.bridge_escrows.update(bridge_escrows)

    def _apply_state_changes(self, changes: dict[str, Any]) -> None:
        """Apply state changes to current state."""
        for key, value in changes.items():
            if key.startswith("slot_"):
                slot = int(key.split("_")[1])
                self._current_state.slots[slot] = value
            elif key.startswith("balance_"):
                addr = key.split("_", 1)[1]
                self._current_state.balances[addr] = value
            elif key == "nullifier":
                self._current_state.nullifier_set.add(str(value))
            elif key == "merkle_root":
                self._current_state.merkle_roots.append(str(value))
            elif key.startswith("lock_"):
                lock_id = key.split("_", 1)[1]
                self._current_state.active_locks[lock_id] = value
            elif key.startswith("pool_"):
                pool = key.split("_", 1)[1]
                self._current_state.pool_balances[pool] = value

    def get_stats(self) -> dict[str, Any]:
        return {
            "transactions_recorded": self._tx_counter,
            "snapshots": self._snapshot_manager.get_stats(),
            "forks": self._fork_manager.fork_count,
            "current_state": self._current_state.to_dict(),
        }

    def get_timeline(self) -> list[dict[str, Any]]:
        """Get snapshot timeline."""
        return self._snapshot_manager.get_timeline()


# Import math for bisector
import math
