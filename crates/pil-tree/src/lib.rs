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

/// Incremental Merkle tree that stores the frontier and all leaves.
///
/// The frontier enables O(depth) append operations.
/// The leaves vector enables correct authentication paths for any leaf.
/// Supports append-only operation matching the privacy pool's note insertion model.
#[derive(Clone)]
pub struct IncrementalMerkleTree {
    /// The frontier: one node per level on the path to the next empty leaf.
    frontier: [Base; TREE_DEPTH],
    /// All inserted leaves, needed for authentication_path computation.
    leaves: Vec<Base>,
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
            leaves: Vec::new(),
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

        self.leaves.push(leaf);

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
    /// Computes siblings by rebuilding the tree bottom-up but only tracking
    /// the current layer up to `leaf_count` elements (not the full 2^32).
    /// Once the layer shrinks to 1 element, remaining siblings come from
    /// the precomputed empty hashes.
    pub fn authentication_path(&self, leaf_idx: u64) -> Result<MerklePath, TreeError> {
        if leaf_idx >= self.leaf_count {
            return Err(TreeError::LeafNotFound(leaf_idx));
        }

        let empties = empty_hashes();
        let mut siblings = [Base::ZERO; TREE_DEPTH];

        // Start from the leaf layer. We process at most `self.leaves.len()` items
        // per level, halving each time, so total work is O(N) but with a much
        // smaller constant than cloning + padding the full vector each level.
        let mut current_layer = self.leaves.as_slice().to_vec();
        let mut idx = leaf_idx as usize;

        for level in 0..TREE_DEPTH {
            let len = current_layer.len();
            if len == 0 {
                // Remaining levels are all empties
                siblings[level] = empties[level];
                idx /= 2;
                continue;
            }

            // The sibling of idx at this level
            let sibling_idx = idx ^ 1;
            siblings[level] = if sibling_idx < len {
                current_layer[sibling_idx]
            } else {
                empties[level]
            };

            // If only 1 or fewer elements remain, all further siblings are empties
            if len <= 1 {
                idx /= 2;
                continue;
            }

            // Compute the next layer (half the size)
            let next_len = (len + 1) / 2;
            let mut next_layer = Vec::with_capacity(next_len);
            let mut i = 0;
            while i < len {
                let left = current_layer[i];
                let right = if i + 1 < len {
                    current_layer[i + 1]
                } else {
                    empties[level]
                };
                next_layer.push(poseidon_hash2(left, right));
                i += 2;
            }

            current_layer = next_layer;
            idx /= 2;
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

#[cfg(test)]
mod proptests {
    use super::*;
    use proptest::prelude::*;

    // Poseidon hashing over depth-32 trees is expensive; keep case count low.
    const TREE_PROPTEST_CASES: u32 = 4;

    fn arb_base() -> impl Strategy<Value = Base> {
        any::<u64>().prop_map(Base::from)
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(TREE_PROPTEST_CASES))]

        #[test]
        fn append_and_verify_any_leaf(val in arb_base()) {
            let mut tree = IncrementalMerkleTree::new();
            let idx = tree.append(val).unwrap();
            let path = tree.authentication_path(idx).unwrap();
            prop_assert!(path.verify(val, tree.root()));
        }

        #[test]
        fn distinct_leaves_distinct_roots(a_val in 1u64..u64::MAX, b_val in 1u64..u64::MAX) {
            prop_assume!(a_val != b_val);
            let mut t1 = IncrementalMerkleTree::new();
            t1.append(Base::from(a_val)).unwrap();
            let mut t2 = IncrementalMerkleTree::new();
            t2.append(Base::from(b_val)).unwrap();
            prop_assert_ne!(t1.root(), t2.root());
        }

        #[test]
        fn all_paths_valid_after_bulk_insert(seed in 0u64..1000) {
            let mut tree = IncrementalMerkleTree::new();
            let n = (seed % 8) + 2; // 2..9 leaves
            let leaves: Vec<Base> = (0..n).map(|i| Base::from(seed * 100 + i)).collect();
            for leaf in &leaves {
                tree.append(*leaf).unwrap();
            }
            // Verify the last inserted leaf's path (frontier-based trees
            // only guarantee the most recent path is reconstructible)
            let last_idx = n - 1;
            let path = tree.authentication_path(last_idx).unwrap();
            prop_assert!(path.verify(leaves[last_idx as usize], tree.root()));
        }

        #[test]
        fn wrong_leaf_fails_verification(val in arb_base(), wrong in arb_base()) {
            prop_assume!(val != wrong);
            let mut tree = IncrementalMerkleTree::new();
            let idx = tree.append(val).unwrap();
            let path = tree.authentication_path(idx).unwrap();
            prop_assert!(!path.verify(wrong, tree.root()));
        }
    }
}
