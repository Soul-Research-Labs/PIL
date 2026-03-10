//! # pil-tree
//!
//! Append-only incremental Merkle tree using Poseidon hashing.
//! Depth 32 supports up to 2^32 (~4 billion) note commitments.

use ff::Field;
use pil_primitives::{hash::poseidon_hash2, types::Base};

pub const TREE_DEPTH: usize = 32;

/// Pre-computed "empty" hashes for each level (zero-value subtrees).
fn empty_hashes() -> [Base; TREE_DEPTH] {
    let mut hashes = [Base::ZERO; TREE_DEPTH];
    // Level 0: hash of empty leaf
    hashes[0] = Base::ZERO;
    for i in 1..TREE_DEPTH {
        let prev = hashes[i - 1];
        hashes[i] = poseidon_hash2(prev, prev);
    }
    hashes
}

/// Incremental Merkle tree that only stores the frontier (right-most path).
///
/// This is memory-efficient: O(depth) storage instead of O(2^depth).
/// Supports append-only operation matching the privacy pool's note insertion model.
#[derive(Clone)]
pub struct IncrementalMerkleTree {
    /// The frontier: one node per level on the path to the next empty leaf.
    frontier: [Base; TREE_DEPTH],
    /// Number of leaves inserted so far.
    leaf_count: u64,
    /// Cached root (recomputed on each insertion).
    root: Base,
}

impl IncrementalMerkleTree {
    /// Create a new empty Merkle tree.
    pub fn new() -> Self {
        let empties = empty_hashes();
        // Compute the root of the empty tree
        let mut root = Base::ZERO;
        for empty in &empties {
            root = poseidon_hash2(root, *empty);
        }
        Self {
            frontier: [Base::ZERO; TREE_DEPTH],
            leaf_count: 0,
            root,
        }
    }

    /// Append a leaf (note commitment) and return its index.
    pub fn append(&mut self, leaf: Base) -> Result<u64, TreeError> {
        let idx = self.leaf_count;
        if idx >= (1u64 << TREE_DEPTH) {
            return Err(TreeError::TreeFull);
        }

        let empties = empty_hashes();
        let mut current = leaf;
        let mut index = idx;

        for (level, empty) in empties.iter().enumerate() {
            if index & 1 == 0 {
                // Left child: store in frontier, pair with empty right sibling
                self.frontier[level] = current;
                current = poseidon_hash2(current, *empty);
            } else {
                // Right child: pair with frontier (left sibling)
                current = poseidon_hash2(self.frontier[level], current);
            }
            index >>= 1;
        }

        self.root = current;
        self.leaf_count = idx + 1;
        Ok(idx)
    }

    /// Get the current Merkle root.
    pub fn root(&self) -> Base {
        self.root
    }

    /// Get the number of leaves.
    pub fn leaf_count(&self) -> u64 {
        self.leaf_count
    }

    /// Generate a Merkle authentication path for a given leaf index.
    /// Returns sibling hashes from leaf to root.
    ///
    /// Note: This simplified version works correctly for the most recently
    /// inserted subtrees. A full implementation would store all leaves
    /// or use a different data structure.
    pub fn authentication_path(&self, leaf_idx: u64) -> Result<MerklePath, TreeError> {
        if leaf_idx >= self.leaf_count {
            return Err(TreeError::LeafNotFound(leaf_idx));
        }

        let empties = empty_hashes();
        let mut siblings = [Base::ZERO; TREE_DEPTH];
        let mut index = leaf_idx;

        for level in 0..TREE_DEPTH {
            if index & 1 == 0 {
                // We're the left child; sibling is on the right
                siblings[level] = empties[level];
            } else {
                // We're the right child; sibling is on the left (in frontier)
                siblings[level] = self.frontier[level];
            }
            index >>= 1;
        }

        Ok(MerklePath {
            siblings,
            leaf_index: leaf_idx,
        })
    }
}

impl Default for IncrementalMerkleTree {
    fn default() -> Self {
        Self::new()
    }
}

/// A Merkle authentication path (sibling hashes + leaf index).
#[derive(Debug, Clone)]
pub struct MerklePath {
    pub siblings: [Base; TREE_DEPTH],
    pub leaf_index: u64,
}

impl MerklePath {
    /// Verify that a leaf at this path produces the expected root.
    pub fn verify(&self, leaf: Base, expected_root: Base) -> bool {
        let mut current = leaf;
        let mut index = self.leaf_index;

        for level in 0..TREE_DEPTH {
            if index & 1 == 0 {
                current = poseidon_hash2(current, self.siblings[level]);
            } else {
                current = poseidon_hash2(self.siblings[level], current);
            }
            index >>= 1;
        }

        current == expected_root
    }
}

#[derive(Debug, thiserror::Error)]
pub enum TreeError {
    #[error("tree is full (2^{} leaves)", TREE_DEPTH)]
    TreeFull,
    #[error("leaf index {0} not found")]
    LeafNotFound(u64),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_tree_has_root() {
        let tree = IncrementalMerkleTree::new();
        assert_ne!(tree.root(), Base::ZERO);
        assert_eq!(tree.leaf_count(), 0);
    }

    #[test]
    fn append_changes_root() {
        let mut tree = IncrementalMerkleTree::new();
        let old_root = tree.root();
        tree.append(Base::from(42u64)).unwrap();
        assert_ne!(tree.root(), old_root);
        assert_eq!(tree.leaf_count(), 1);
    }

    #[test]
    fn multiple_appends_sequential_indices() {
        let mut tree = IncrementalMerkleTree::new();
        for i in 0..10 {
            let idx = tree.append(Base::from(i)).unwrap();
            assert_eq!(idx, i);
        }
        assert_eq!(tree.leaf_count(), 10);
    }

    #[test]
    fn merkle_path_verification() {
        let mut tree = IncrementalMerkleTree::new();
        let leaf = Base::from(12345u64);
        let idx = tree.append(leaf).unwrap();
        let path = tree.authentication_path(idx).unwrap();
        assert!(path.verify(leaf, tree.root()));
    }
}
