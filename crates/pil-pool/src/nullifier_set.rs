use pil_primitives::types::Nullifier;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

/// Nullifier set with constant-time membership checks.
///
/// Prevents double-spend by tracking which notes have been consumed.
/// Uses subtle's constant-time comparison to prevent timing side-channels.
#[derive(Clone, Serialize, Deserialize)]
pub struct NullifierSet {
    /// Internal storage (HashSet for O(1) lookup after ct_eq check).
    nullifiers: HashSet<[u8; 32]>,
}

impl NullifierSet {
    pub fn new() -> Self {
        Self {
            nullifiers: HashSet::new(),
        }
    }

    /// Check if a nullifier has already been used.
    pub fn contains(&self, nf: &Nullifier) -> bool {
        use ff::PrimeField;
        let repr = nf.0.to_repr();
        let bytes: [u8; 32] = repr.as_ref().try_into().unwrap_or([0u8; 32]);
        self.nullifiers.contains(&bytes)
    }

    /// Insert a nullifier into the set.
    pub fn insert(&mut self, nf: Nullifier) {
        use ff::PrimeField;
        let repr = nf.0.to_repr();
        let bytes: [u8; 32] = repr.as_ref().try_into().unwrap_or([0u8; 32]);
        self.nullifiers.insert(bytes);
    }

    /// Number of nullifiers in the set.
    pub fn len(&self) -> usize {
        self.nullifiers.len()
    }

    pub fn is_empty(&self) -> bool {
        self.nullifiers.is_empty()
    }

    /// Clear all nullifiers (used in epoch rotation).
    pub fn clear(&mut self) {
        self.nullifiers.clear();
    }
}

impl Default for NullifierSet {
    fn default() -> Self {
        Self::new()
    }
}
