//! Hydra L2 pool state management.
//!
//! Wraps the core `PrivacyPool` with Hydra-specific state tracking.

use pil_pool::PrivacyPool;
use pil_primitives::domain::{ChainDomain, DomainSeparator};
use pil_primitives::types::{Base, Commitment, Nullifier};

/// State of a privacy pool running inside a Hydra head.
#[derive(Clone)]
pub struct HydraPoolState {
    /// The privacy pool instance (same as L1, isomorphic).
    pool: PrivacyPool,
    /// Domain separator for this head's chain.
    domain: DomainSeparator,
    /// Total L2 deposits.
    total_deposited: u64,
    /// Total L2 withdrawals.
    total_withdrawn: u64,
}

impl HydraPoolState {
    /// Create a fresh L2 pool state for a given chain domain.
    pub fn new(chain_domain: ChainDomain) -> Self {
        Self {
            pool: PrivacyPool::new(),
            domain: DomainSeparator::new(chain_domain, 0),
            total_deposited: 0,
            total_withdrawn: 0,
        }
    }

    /// Deposit a note into the L2 pool.
    pub fn deposit(
        &mut self,
        commitment: Commitment,
        value: u64,
        asset_id: u64,
    ) -> Result<(), pil_pool::pool::PoolError> {
        self.pool.deposit(commitment, value, asset_id)?;
        self.total_deposited += value;
        Ok(())
    }

    /// Spend nullifiers and create new commitments (L2 transfer).
    pub fn transfer(
        &mut self,
        nullifiers: &[Nullifier],
        new_commitments: &[Commitment],
    ) -> Result<(), pil_pool::pool::PoolError> {
        self.pool
            .process_transfer(nullifiers, new_commitments, &[])?;
        Ok(())
    }

    /// Withdraw from the L2 pool.
    pub fn withdraw(
        &mut self,
        nullifiers: &[Nullifier],
        change_commitments: &[Commitment],
        exit_value: u64,
        asset_id: u64,
    ) -> Result<(), pil_pool::pool::PoolError> {
        self.pool
            .process_withdraw(nullifiers, change_commitments, exit_value, asset_id, &[])?;
        self.total_withdrawn += exit_value;
        Ok(())
    }

    /// Current Merkle root of the L2 pool.
    pub fn pool_root(&self) -> Base {
        self.pool.root()
    }

    /// Number of notes in the L2 pool.
    pub fn note_count(&self) -> u64 {
        self.pool.note_count()
    }

    /// Number of spent nullifiers.
    pub fn nullifier_count(&self) -> usize {
        self.pool.nullifier_count()
    }

    /// Current L2 pool balance.
    pub fn balance(&self) -> u64 {
        self.pool.balance()
    }

    /// Domain separator for this head.
    pub fn domain(&self) -> &DomainSeparator {
        &self.domain
    }

    /// Total value deposited into this L2 pool.
    pub fn total_deposited(&self) -> u64 {
        self.total_deposited
    }

    /// Total value withdrawn from this L2 pool.
    pub fn total_withdrawn(&self) -> u64 {
        self.total_withdrawn
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pil_note::{keys::SpendingKey, note::Note};
    use rand::rngs::OsRng;

    #[test]
    fn hydra_pool_deposit_and_withdraw() {
        let mut state = HydraPoolState::new(ChainDomain::CardanoPreprod);
        let sk = SpendingKey::random(&mut OsRng);

        let note = Note::new(500, sk.owner(), 0);
        state.deposit(note.commitment(), 500, 0).unwrap();

        assert_eq!(state.balance(), 500);
        assert_eq!(state.note_count(), 1);
        assert_eq!(state.total_deposited(), 500);

        let nf = pil_note::derive_nullifier_v2(
            sk.to_base(),
            note.commitment(),
            state.domain(),
        );
        state.withdraw(&[nf], &[], 500, 0).unwrap();

        assert_eq!(state.balance(), 0);
        assert_eq!(state.total_withdrawn(), 500);
    }

    #[test]
    fn hydra_pool_double_spend_rejected() {
        let mut state = HydraPoolState::new(ChainDomain::CardanoMainnet);
        let sk = SpendingKey::random(&mut OsRng);

        let note = Note::new(100, sk.owner(), 0);
        state.deposit(note.commitment(), 100, 0).unwrap();

        let nf = pil_note::derive_nullifier_v2(
            sk.to_base(),
            note.commitment(),
            state.domain(),
        );

        state.withdraw(&[nf], &[], 100, 0).unwrap();
        assert!(state.withdraw(&[nf], &[], 100, 0).is_err());
    }
}
