//! Snapshot types and policies for Hydra L2 → L1 state commits.

use pil_primitives::types::Base;
use serde::{Deserialize, Serialize};

/// Policy for when to take L2 snapshots.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum SnapshotPolicy {
    /// Snapshot every N L2 transactions.
    EveryNTransactions(u32),
    /// Only snapshot on explicit request (manual or close).
    Manual,
}

/// A snapshot of the L2 pool state at a point in time.
#[derive(Debug, Clone)]
pub struct Snapshot {
    /// Sequential snapshot number.
    pub snapshot_number: u64,
    /// Merkle root of the L2 pool at snapshot time.
    pub pool_root: Base,
    /// Number of nullifiers spent in the L2 pool.
    pub nullifier_count: u64,
    /// Number of notes in the L2 pool.
    pub note_count: u64,
    /// Number of L2 transactions since the previous snapshot.
    pub l2_tx_count: u32,
}

impl Snapshot {
    /// Unique identifier bytes for this snapshot (for signing / hashing).
    pub fn snapshot_id(&self) -> Vec<u8> {
        use blake2::{Blake2b512, Digest};
        let mut hasher = Blake2b512::new();
        hasher.update(self.snapshot_number.to_le_bytes());
        // Include pool root in the commitment to bind the hash to L2 state
        let root_bytes: [u8; 32] = self.pool_root.into();
        hasher.update(root_bytes);
        hasher.update(self.nullifier_count.to_le_bytes());
        hasher.update(self.note_count.to_le_bytes());
        hasher.update(self.l2_tx_count.to_le_bytes());
        hasher.finalize().to_vec()
    }

    /// Hex-encoded snapshot ID.
    pub fn snapshot_id_hex(&self) -> String {
        hex::encode(self.snapshot_id())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ff::Field;

    #[test]
    fn snapshot_id_deterministic() {
        let s1 = Snapshot {
            snapshot_number: 0,
            pool_root: Base::ZERO,
            nullifier_count: 10,
            note_count: 20,
            l2_tx_count: 5,
        };
        let s2 = s1.clone();
        assert_eq!(s1.snapshot_id(), s2.snapshot_id());
        assert!(!s1.snapshot_id_hex().is_empty());
    }

    #[test]
    fn different_snapshots_different_ids() {
        let s1 = Snapshot {
            snapshot_number: 0,
            pool_root: Base::ZERO,
            nullifier_count: 10,
            note_count: 20,
            l2_tx_count: 5,
        };
        let s2 = Snapshot {
            snapshot_number: 1,
            ..s1.clone()
        };
        assert_ne!(s1.snapshot_id(), s2.snapshot_id());
    }
}
