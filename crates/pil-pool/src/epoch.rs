use ff::Field;
use pil_primitives::{hash::poseidon_hash2, types::Base};
use std::time::{SystemTime, UNIX_EPOCH};

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
    epoch_duration_secs: u64,
    /// Unix timestamp of current epoch start.
    epoch_start: u64,
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

impl EpochManager {
    pub fn new(epoch_duration_secs: u64) -> Self {
        Self {
            current_epoch: 0,
            finalized_roots: Vec::new(),
            epoch_duration_secs,
            epoch_start: unix_now(),
        }
    }

    /// Check whether the current epoch has exceeded its duration and should be finalized.
    pub fn should_finalize(&self) -> bool {
        unix_now().saturating_sub(self.epoch_start) >= self.epoch_duration_secs
    }

    /// Finalize the current epoch with a Merkle root and advance to the next.
    pub fn finalize_epoch(&mut self, nullifier_root: Base) {
        self.finalized_roots
            .push((self.current_epoch, nullifier_root));
        self.current_epoch += 1;
        self.epoch_start = unix_now();
    }

    /// Configured epoch duration.
    pub fn epoch_duration_secs(&self) -> u64 {
        self.epoch_duration_secs
    }

    /// Unix timestamp when the current epoch started.
    pub fn epoch_start(&self) -> u64 {
        self.epoch_start
    }

    /// Seconds remaining in the current epoch (0 if overdue).
    pub fn time_remaining(&self) -> u64 {
        let elapsed = unix_now().saturating_sub(self.epoch_start);
        self.epoch_duration_secs.saturating_sub(elapsed)
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
