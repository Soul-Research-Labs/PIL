use pil_primitives::types::{Base, Commitment, Nullifier};
use pil_tree::IncrementalMerkleTree;

use super::nullifier_set::NullifierSet;

/// The core privacy pool state machine.
///
/// Manages:
/// - Merkle tree of note commitments
/// - Nullifier registry (spent note tracking)
/// - Pool balance accounting
/// - Deposit/transfer/withdraw operations
#[derive(Clone)]
pub struct PrivacyPool {
    /// Merkle tree storing all note commitments.
    tree: IncrementalMerkleTree,
    /// Set of spent nullifiers.
    nullifiers: NullifierSet,
    /// Total value in the pool (sum of all unspent notes).
    pool_balance: u64,
    /// Asset balances (asset_id → total).
    asset_balances: std::collections::HashMap<u64, u64>,
}

impl PrivacyPool {
    pub fn new() -> Self {
        Self {
            tree: IncrementalMerkleTree::new(),
            nullifiers: NullifierSet::new(),
            pool_balance: 0,
            asset_balances: std::collections::HashMap::new(),
        }
    }

    /// Deposit: add a note commitment to the tree and increase pool balance.
    pub fn deposit(
        &mut self,
        commitment: Commitment,
        value: u64,
        asset_id: u64,
    ) -> Result<DepositReceipt, PoolError> {
        let leaf_index = self
            .tree
            .append(commitment.0)
            .map_err(|e| PoolError::TreeError(e.to_string()))?;

        self.pool_balance = self
            .pool_balance
            .checked_add(value)
            .ok_or(PoolError::Overflow)?;

        let asset_bal = self.asset_balances.entry(asset_id).or_insert(0);
        *asset_bal = asset_bal.checked_add(value).ok_or(PoolError::Overflow)?;

        Ok(DepositReceipt {
            leaf_index,
            root: self.tree.root(),
            pool_balance: self.pool_balance,
        })
    }

    /// Process a transfer: verify nullifiers are fresh, add new commitments.
    pub fn process_transfer(
        &mut self,
        nullifiers: &[Nullifier],
        new_commitments: &[Commitment],
        _proof_bytes: &[u8], // Verified by pil-verifier before calling this
    ) -> Result<TransferReceipt, PoolError> {
        // Check nullifiers are fresh
        for nf in nullifiers {
            if self.nullifiers.contains(nf) {
                return Err(PoolError::NullifierAlreadySpent);
            }
        }

        // Insert nullifiers
        for nf in nullifiers {
            self.nullifiers.insert(*nf);
        }

        // Append new note commitments
        let mut leaf_indices = Vec::new();
        for cm in new_commitments {
            let idx = self
                .tree
                .append(cm.0)
                .map_err(|e| PoolError::TreeError(e.to_string()))?;
            leaf_indices.push(idx);
        }

        Ok(TransferReceipt {
            leaf_indices,
            root: self.tree.root(),
            nullifiers_spent: nullifiers.len(),
        })
    }

    /// Process a withdrawal: verify nullifiers, add change commitments, decrease balance.
    pub fn process_withdraw(
        &mut self,
        nullifiers: &[Nullifier],
        change_commitments: &[Commitment],
        exit_value: u64,
        asset_id: u64,
        _proof_bytes: &[u8],
    ) -> Result<WithdrawReceipt, PoolError> {
        // Check nullifiers are fresh
        for nf in nullifiers {
            if self.nullifiers.contains(nf) {
                return Err(PoolError::NullifierAlreadySpent);
            }
        }

        // Check pool has sufficient balance
        if self.pool_balance < exit_value {
            return Err(PoolError::InsufficientBalance);
        }

        // Check per-asset balance is sufficient
        let asset_bal = self.asset_balances.get(&asset_id).copied().unwrap_or(0);
        if asset_bal < exit_value {
            return Err(PoolError::InsufficientBalance);
        }

        // Insert nullifiers
        for nf in nullifiers {
            self.nullifiers.insert(*nf);
        }

        // Append change commitments
        let mut leaf_indices = Vec::new();
        for cm in change_commitments {
            let idx = self
                .tree
                .append(cm.0)
                .map_err(|e| PoolError::TreeError(e.to_string()))?;
            leaf_indices.push(idx);
        }

        self.pool_balance -= exit_value;
        // Safe: we verified asset_bal >= exit_value above
        *self.asset_balances.get_mut(&asset_id).unwrap() -= exit_value;

        Ok(WithdrawReceipt {
            leaf_indices,
            root: self.tree.root(),
            exit_value,
        })
    }

    /// Get the current Merkle root.
    pub fn root(&self) -> Base {
        self.tree.root()
    }

    /// Get total pool balance.
    pub fn balance(&self) -> u64 {
        self.pool_balance
    }

    /// Get total note count.
    pub fn note_count(&self) -> u64 {
        self.tree.leaf_count()
    }

    /// Get nullifier count.
    pub fn nullifier_count(&self) -> usize {
        self.nullifiers.len()
    }

    /// Check if a nullifier has been spent.
    pub fn is_nullifier_spent(&self, nf: &Nullifier) -> bool {
        self.nullifiers.contains(nf)
    }

    /// Generate a Merkle authentication path for a given leaf index.
    /// Returns the sibling hashes needed to prove membership.
    pub fn authentication_path(&self, leaf_idx: u64) -> Result<pil_tree::MerklePath, PoolError> {
        self.tree
            .authentication_path(leaf_idx)
            .map_err(|e| PoolError::TreeError(e.to_string()))
    }
}

impl Default for PrivacyPool {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone)]
pub struct DepositReceipt {
    pub leaf_index: u64,
    pub root: Base,
    pub pool_balance: u64,
}

#[derive(Debug, Clone)]
pub struct TransferReceipt {
    pub leaf_indices: Vec<u64>,
    pub root: Base,
    pub nullifiers_spent: usize,
}

#[derive(Debug, Clone)]
pub struct WithdrawReceipt {
    pub leaf_indices: Vec<u64>,
    pub root: Base,
    pub exit_value: u64,
}

#[derive(Debug, thiserror::Error)]
pub enum PoolError {
    #[error("nullifier already spent (double-spend attempt)")]
    NullifierAlreadySpent,
    #[error("insufficient pool balance")]
    InsufficientBalance,
    #[error("balance overflow")]
    Overflow,
    #[error("merkle tree error: {0}")]
    TreeError(String),
    #[error("invalid proof")]
    InvalidProof,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_commitment(val: u64) -> Commitment {
        Commitment(Base::from(val))
    }

    fn test_nullifier(val: u64) -> Nullifier {
        Nullifier(Base::from(val))
    }

    #[test]
    fn deposit_increases_balance() {
        let mut pool = PrivacyPool::new();
        let receipt = pool.deposit(test_commitment(1), 100, 0).unwrap();
        assert_eq!(receipt.pool_balance, 100);
        assert_eq!(pool.note_count(), 1);
    }

    #[test]
    fn double_spend_rejected() {
        let mut pool = PrivacyPool::new();
        pool.deposit(test_commitment(1), 100, 0).unwrap();

        let nf = test_nullifier(42);
        pool.process_transfer(&[nf], &[test_commitment(2)], &[])
            .unwrap();

        // Second use of same nullifier should fail
        let result = pool.process_transfer(&[nf], &[test_commitment(3)], &[]);
        assert!(matches!(result, Err(PoolError::NullifierAlreadySpent)));
    }

    #[test]
    fn withdraw_decreases_balance() {
        let mut pool = PrivacyPool::new();
        pool.deposit(test_commitment(1), 100, 0).unwrap();

        let nf = test_nullifier(1);
        pool.process_withdraw(&[nf], &[test_commitment(2)], 70, 0, &[])
            .unwrap();
        assert_eq!(pool.balance(), 30);
    }
}
