//! L1 ↔ L2 state synchronization for Hydra heads.
//!
//! Tracks which snapshots have been committed to L1 and provides a
//! state diff between the latest committed snapshot and the current
//! L2 state so the bridge can know what changed.

use ff::PrimeField;
use pil_primitives::types::Base;
use serde::{Deserialize, Serialize};

use crate::snapshot::Snapshot;

/// Tracks committed snapshot state for L1 ↔ L2 synchronization.
#[derive(Debug, Clone)]
pub struct L1SyncState {
    /// Snapshot number last committed to L1.
    committed_snapshot: Option<u64>,
    /// Pool root at last L1 commit.
    committed_root: Option<Base>,
    /// L1 epoch at last commit.
    committed_l1_epoch: Option<u64>,
    /// Pending snapshots waiting for L1 confirmation.
    pending: Vec<PendingCommit>,
}

/// A snapshot pending L1 confirmation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PendingCommit {
    /// The snapshot number being committed.
    pub snapshot_number: u64,
    /// The snapshot ID (hex) used as on-chain identifier.
    pub snapshot_id_hex: String,
    /// Pool root at this snapshot.
    pub pool_root_bytes: Vec<u8>,
    /// Target L1 epoch.
    pub target_l1_epoch: u64,
}

/// Diff between committed L1 state and current L2 state.
#[derive(Debug, Clone)]
pub struct StateDiff {
    /// Number of new notes since last commit.
    pub new_notes: u64,
    /// Number of new nullifiers since last commit.
    pub new_nullifiers: u64,
    /// Number of uncommitted snapshots.
    pub uncommitted_snapshots: u64,
    /// Current L2 pool root.
    pub current_root: Base,
    /// Last committed root (if any).
    pub committed_root: Option<Base>,
}

/// Errors from L1 sync operations.
#[derive(Debug, thiserror::Error)]
pub enum SyncError {
    #[error("snapshot {0} is already committed")]
    AlreadyCommitted(u64),
    #[error("snapshot {0} is already pending")]
    AlreadyPending(u64),
    #[error("no pending commit for snapshot {0}")]
    NoPendingCommit(u64),
    #[error("mismatched snapshot ID: expected {expected}, got {got}")]
    SnapshotIdMismatch { expected: String, got: String },
}

impl L1SyncState {
    /// Create a new sync tracker (nothing committed yet).
    pub fn new() -> Self {
        Self {
            committed_snapshot: None,
            committed_root: None,
            committed_l1_epoch: None,
            pending: Vec::new(),
        }
    }

    /// Last snapshot number committed to L1.
    pub fn committed_snapshot(&self) -> Option<u64> {
        self.committed_snapshot
    }

    /// Pool root at last committed snapshot.
    pub fn committed_root(&self) -> Option<Base> {
        self.committed_root
    }

    /// L1 epoch of the last commitment.
    pub fn committed_l1_epoch(&self) -> Option<u64> {
        self.committed_l1_epoch
    }

    /// Number of pending (unconfirmed) L1 commits.
    pub fn pending_count(&self) -> usize {
        self.pending.len()
    }

    /// Submit a snapshot for L1 commitment.
    pub fn submit_for_commit(
        &mut self,
        snapshot: &Snapshot,
        target_l1_epoch: u64,
    ) -> Result<PendingCommit, SyncError> {
        let sn = snapshot.snapshot_number;

        // Reject if already committed
        if let Some(committed) = self.committed_snapshot {
            if sn <= committed {
                return Err(SyncError::AlreadyCommitted(sn));
            }
        }

        // Reject if already pending
        if self.pending.iter().any(|p| p.snapshot_number == sn) {
            return Err(SyncError::AlreadyPending(sn));
        }

        let root_bytes: [u8; 32] = snapshot.pool_root.into();
        let commit = PendingCommit {
            snapshot_number: sn,
            snapshot_id_hex: snapshot.snapshot_id_hex(),
            pool_root_bytes: root_bytes.to_vec(),
            target_l1_epoch,
        };
        self.pending.push(commit.clone());
        Ok(commit)
    }

    /// Confirm that a snapshot has been settled on L1.
    pub fn confirm_commit(
        &mut self,
        snapshot_number: u64,
        l1_epoch: u64,
        snapshot_id_hex: &str,
    ) -> Result<(), SyncError> {
        let idx = self
            .pending
            .iter()
            .position(|p| p.snapshot_number == snapshot_number)
            .ok_or(SyncError::NoPendingCommit(snapshot_number))?;

        let pending = &self.pending[idx];
        if pending.snapshot_id_hex != snapshot_id_hex {
            return Err(SyncError::SnapshotIdMismatch {
                expected: pending.snapshot_id_hex.clone(),
                got: snapshot_id_hex.to_string(),
            });
        }

        let root_bytes: [u8; 32] = pending
            .pool_root_bytes
            .as_slice()
            .try_into()
            .unwrap_or([0u8; 32]);
        self.committed_root = Some(Base::from_repr_vartime(root_bytes).unwrap_or(Base::from(0u64)));
        self.committed_snapshot = Some(snapshot_number);
        self.committed_l1_epoch = Some(l1_epoch);

        // Remove this and all older pending commits
        self.pending.retain(|p| p.snapshot_number > snapshot_number);
        Ok(())
    }

    /// Compute the state diff between committed state and current L2 state.
    pub fn state_diff(
        &self,
        current_root: Base,
        current_notes: u64,
        current_nullifiers: u64,
        committed_notes: u64,
        committed_nullifiers: u64,
    ) -> StateDiff {
        StateDiff {
            new_notes: current_notes.saturating_sub(committed_notes),
            new_nullifiers: current_nullifiers.saturating_sub(committed_nullifiers),
            uncommitted_snapshots: self.pending.len() as u64,
            current_root,
            committed_root: self.committed_root,
        }
    }
}

impl Default for L1SyncState {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_snapshot(number: u64) -> Snapshot {
        Snapshot {
            snapshot_number: number,
            pool_root: Base::from(number + 1),
            nullifier_count: number * 2,
            note_count: number * 3 + 1,
            l2_tx_count: 5,
        }
    }

    #[test]
    fn submit_and_confirm() {
        let mut sync = L1SyncState::new();
        let snap = make_snapshot(0);

        let commit = sync.submit_for_commit(&snap, 10).unwrap();
        assert_eq!(commit.snapshot_number, 0);
        assert_eq!(sync.pending_count(), 1);

        sync.confirm_commit(0, 10, &commit.snapshot_id_hex).unwrap();
        assert_eq!(sync.committed_snapshot(), Some(0));
        assert_eq!(sync.committed_l1_epoch(), Some(10));
        assert_eq!(sync.pending_count(), 0);
    }

    #[test]
    fn reject_duplicate_pending() {
        let mut sync = L1SyncState::new();
        let snap = make_snapshot(0);

        sync.submit_for_commit(&snap, 10).unwrap();
        assert!(sync.submit_for_commit(&snap, 11).is_err());
    }

    #[test]
    fn reject_already_committed() {
        let mut sync = L1SyncState::new();
        let s0 = make_snapshot(0);
        let commit = sync.submit_for_commit(&s0, 10).unwrap();
        sync.confirm_commit(0, 10, &commit.snapshot_id_hex).unwrap();

        assert!(sync.submit_for_commit(&s0, 11).is_err());
    }

    #[test]
    fn confirm_clears_older_pending() {
        let mut sync = L1SyncState::new();
        let s0 = make_snapshot(0);
        let s1 = make_snapshot(1);
        let s2 = make_snapshot(2);

        let _c0 = sync.submit_for_commit(&s0, 10).unwrap();
        sync.submit_for_commit(&s1, 11).unwrap();
        sync.submit_for_commit(&s2, 12).unwrap();
        assert_eq!(sync.pending_count(), 3);

        // Confirming s1 clears s0 and s1, keeps s2
        let c1_id = sync
            .pending
            .iter()
            .find(|p| p.snapshot_number == 1)
            .unwrap()
            .snapshot_id_hex
            .clone();
        sync.confirm_commit(1, 11, &c1_id).unwrap();
        assert_eq!(sync.pending_count(), 1);
        assert_eq!(sync.committed_snapshot(), Some(1));
    }

    #[test]
    fn mismatched_id_rejected() {
        let mut sync = L1SyncState::new();
        let snap = make_snapshot(0);
        sync.submit_for_commit(&snap, 10).unwrap();

        assert!(sync.confirm_commit(0, 10, "wrong_id").is_err());
    }

    #[test]
    fn state_diff_computation() {
        let sync = L1SyncState::new();
        let diff = sync.state_diff(Base::from(42u64), 10, 5, 3, 1);
        assert_eq!(diff.new_notes, 7);
        assert_eq!(diff.new_nullifiers, 4);
        assert!(diff.committed_root.is_none());
    }
}
