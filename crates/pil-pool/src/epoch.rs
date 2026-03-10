use ff::Field;
use pil_primitives::{hash::poseidon_hash2, types::Base};

/// Epoch-based nullifier partitioning for cross-chain synchronization.
///
/// Epochs define time-bounded windows. At the end of each epoch, the
/// nullifier set is finalized into a Merkle root that can be published
/// to other chains for cross-chain nullifier verification.
#[derive(Clone)]
pub struct EpochManager {
    /// Current epoch number.
    current_epoch: u64,
    /// Finalized epoch roots (epoch_number → nullifier Merkle root).
    finalized_roots: Vec<(u64, Base)>,
    /// Epoch duration in seconds (default: 3600 = 1 hour).
    _epoch_duration_secs: u64,
    /// Timestamp of current epoch start.
    _epoch_start: u64,
}

impl EpochManager {
    pub fn new(epoch_duration_secs: u64) -> Self {
        Self {
            current_epoch: 0,
            finalized_roots: Vec::new(),
            _epoch_duration_secs: epoch_duration_secs,
            _epoch_start: 0,
        }
    }

    /// Finalize the current epoch with a nullifier root and advance to the next.
    pub fn finalize_epoch(&mut self, nullifier_root: Base) {
        self.finalized_roots
            .push((self.current_epoch, nullifier_root));
        self.current_epoch += 1;
        // In production: self.epoch_start = current_timestamp();
    }

    /// Get the finalized root for a specific epoch.
    pub fn epoch_root(&self, epoch: u64) -> Option<Base> {
        self.finalized_roots
            .iter()
            .find(|(e, _)| *e == epoch)
            .map(|(_, root)| *root)
    }

    /// Get all finalized epoch roots (for cross-chain publishing).
    pub fn all_epoch_roots(&self) -> &[(u64, Base)] {
        &self.finalized_roots
    }

    /// Current epoch number.
    pub fn current_epoch(&self) -> u64 {
        self.current_epoch
    }

    /// Compute a summary root over all epoch roots (for bridge verification).
    pub fn summary_root(&self) -> Base {
        let mut acc = Base::ZERO;
        for (_, root) in &self.finalized_roots {
            acc = poseidon_hash2(acc, *root);
        }
        acc
    }
}
