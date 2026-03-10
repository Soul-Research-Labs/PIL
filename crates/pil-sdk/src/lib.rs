//! # pil-sdk
//!
//! High-level orchestrator for the Privacy Interoperability Layer.
//!
//! Provides a unified API for deposit, private transfer, and withdrawal
//! across Cardano, Cosmos, and other supported chains.
//!
//! ## Usage
//!
//! ```no_run
//! use pil_sdk::Pil;
//! use pil_primitives::domain::ChainDomain;
//!
//! let mut pil = Pil::init(ChainDomain::CardanoMainnet).unwrap();
//!
//! // Deposit 100 ADA into the shielded pool
//! pil.deposit(100).unwrap();
//!
//! // Private transfer to a recipient on the same chain
//! let recipient_owner = pasta_curves::pallas::Base::from(0xBEEFu64);
//! pil.send(recipient_owner, 70).unwrap();
//!
//! // Withdraw 30 ADA back to a public address
//! pil.withdraw(30).unwrap();
//!
//! // Cross-chain: send to a recipient on Cosmos Hub
//! // pil.cross_chain_send(ChainDomain::CosmosHub, recipient_owner, 50).unwrap();
//! ```

use ff::Field;
use pasta_curves::pallas;
use pil_client::{Wallet, TxRecord};
use pil_note::{keys::SpendingKey, note::Note};
use pil_pool::PrivacyPool;
use pil_primitives::{
    domain::{ChainDomain, DomainSeparator},
    types::{Base, Commitment},
};
use pil_prover::ProvingKeys;

/// The main PIL orchestrator.
pub struct Pil {
    /// Proving keys for ZK circuits.
    pub keys: ProvingKeys,
    /// The privacy pool state.
    pub pool: PrivacyPool,
    /// Client wallet.
    pub wallet: Wallet,
    /// Spending key.
    spending_key: SpendingKey,
    /// Active chain domain.
    pub chain: ChainDomain,
    /// Domain separator for nullifiers.
    domain: DomainSeparator,
}

impl Pil {
    /// Initialize PIL for a specific chain.
    pub fn init(chain: ChainDomain) -> Result<Self, PilError> {
        let keys = ProvingKeys::setup().map_err(|e| PilError::Init(e.to_string()))?;
        let mut rng = rand::thread_rng();
        let spending_key = SpendingKey::random(&mut rng);
        let owner = spending_key.owner();
        let owner_hex = format!("{owner:?}");
        let domain = DomainSeparator::new(chain, 0);

        Ok(Self {
            keys,
            pool: PrivacyPool::new(),
            wallet: Wallet::new(owner_hex),
            spending_key,
            chain,
            domain,
        })
    }

    /// Initialize from an existing spending key.
    pub fn from_key(chain: ChainDomain, spending_key: SpendingKey) -> Result<Self, PilError> {
        let keys = ProvingKeys::setup().map_err(|e| PilError::Init(e.to_string()))?;
        let owner = spending_key.owner();
        let owner_hex = format!("{owner:?}");
        let domain = DomainSeparator::new(chain, 0);

        Ok(Self {
            keys,
            pool: PrivacyPool::new(),
            wallet: Wallet::new(owner_hex),
            spending_key,
            chain,
            domain,
        })
    }

    /// Deposit value into the shielded pool.
    pub fn deposit(&mut self, value: u64) -> Result<DepositResult, PilError> {
        let owner = self.spending_key.owner();
        let note = Note::new(value, owner, 0);
        let commitment = note.commitment();

        let receipt = self
            .pool
            .deposit(commitment, value, 0)
            .map_err(|e| PilError::Pool(e.to_string()))?;

        self.wallet.add_note(note, receipt.leaf_index);
        self.wallet
            .record_tx(TxRecord::Deposit {
                value,
                asset_id: 0,
                leaf_index: receipt.leaf_index,
            });

        Ok(DepositResult {
            leaf_index: receipt.leaf_index,
            root: receipt.root,
            pool_balance: receipt.pool_balance,
        })
    }

    /// Private transfer to a recipient.
    pub fn send(&mut self, recipient_owner: Base, value: u64) -> Result<SendResult, PilError> {
        // Select input notes
        let selected = self
            .wallet
            .select_notes(value, 0)
            .map_err(|e| PilError::Wallet(e.to_string()))?;

        let input_total: u64 = selected.iter().map(|n| n.note.value).sum();
        let change = input_total - value;

        // Collect data before releasing the borrow on wallet
        let selected_leaf_indices: Vec<u64> = selected.iter().map(|n| n.leaf_index).collect();
        let nullifiers: Vec<_> = selected
            .iter()
            .map(|n| {
                pil_note::derive_nullifier_v2(self.spending_key.to_base(), n.note.commitment(), &self.domain)
            })
            .collect();
        drop(selected);

        // Create output notes
        let recipient_note = Note::new(value, recipient_owner, 0);
        let change_note = Note::new(change, self.spending_key.owner(), 0);

        let recipient_cm = recipient_note.commitment();
        let change_cm = change_note.commitment();

        // Process transfer in the pool
        let receipt = self
            .pool
            .process_transfer(
                &nullifiers,
                &[recipient_cm, change_cm],
                &[], // Proof bytes (generated separately)
            )
            .map_err(|e| PilError::Pool(e.to_string()))?;

        // Update wallet
        for idx in &selected_leaf_indices {
            self.wallet.mark_spent(*idx);
        }
        self.wallet.add_note(change_note, receipt.leaf_indices[1]);
        self.wallet.record_tx(TxRecord::Send {
            value,
            asset_id: 0,
            recipient_owner: format!("{recipient_owner:?}"),
        });

        Ok(SendResult {
            nullifiers_spent: receipt.nullifiers_spent,
            leaf_indices: receipt.leaf_indices,
            root: receipt.root,
        })
    }

    /// Withdraw value from the shielded pool.
    pub fn withdraw(&mut self, value: u64) -> Result<WithdrawResult, PilError> {
        let selected = self
            .wallet
            .select_notes(value, 0)
            .map_err(|e| PilError::Wallet(e.to_string()))?;

        let input_total: u64 = selected.iter().map(|n| n.note.value).sum();
        let change = input_total - value;

        let selected_leaf_indices: Vec<u64> = selected.iter().map(|n| n.leaf_index).collect();
        let nullifiers: Vec<_> = selected
            .iter()
            .map(|n| {
                pil_note::derive_nullifier_v2(self.spending_key.to_base(), n.note.commitment(), &self.domain)
            })
            .collect();
        drop(selected);

        let change_note = Note::new(change, self.spending_key.owner(), 0);
        let change_cm = change_note.commitment();

        let receipt = self
            .pool
            .process_withdraw(&nullifiers, &[change_cm], value, 0, &[])
            .map_err(|e| PilError::Pool(e.to_string()))?;

        for idx in &selected_leaf_indices {
            self.wallet.mark_spent(*idx);
        }
        if change > 0 {
            self.wallet.add_note(change_note, receipt.leaf_indices[0]);
        }
        self.wallet.record_tx(TxRecord::Withdraw {
            value,
            asset_id: 0,
        });

        Ok(WithdrawResult {
            exit_value: value,
            leaf_indices: receipt.leaf_indices,
            root: receipt.root,
        })
    }

    /// Get the wallet balance.
    pub fn balance(&self) -> u64 {
        self.wallet.balance()
    }

    /// Get the pool balance.
    pub fn pool_balance(&self) -> u64 {
        self.pool.balance()
    }
}

#[derive(Debug)]
pub struct DepositResult {
    pub leaf_index: u64,
    pub root: Base,
    pub pool_balance: u64,
}

#[derive(Debug)]
pub struct SendResult {
    pub nullifiers_spent: usize,
    pub leaf_indices: Vec<u64>,
    pub root: Base,
}

#[derive(Debug)]
pub struct WithdrawResult {
    pub exit_value: u64,
    pub leaf_indices: Vec<u64>,
    pub root: Base,
}

#[derive(Debug, thiserror::Error)]
pub enum PilError {
    #[error("initialization failed: {0}")]
    Init(String),
    #[error("pool error: {0}")]
    Pool(String),
    #[error("wallet error: {0}")]
    Wallet(String),
    #[error("proof error: {0}")]
    Proof(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn e2e_deposit_send_withdraw() {
        let mut pil = Pil::init(ChainDomain::CardanoMainnet).unwrap();

        // Deposit
        let dep = pil.deposit(100).unwrap();
        assert_eq!(dep.pool_balance, 100);
        assert_eq!(pil.balance(), 100);

        // Send
        let recipient = Base::from(0xBEEFu64);
        let send = pil.send(recipient, 70).unwrap();
        assert_eq!(send.nullifiers_spent, 1);
        assert_eq!(pil.balance(), 30); // change

        // Withdraw
        let wd = pil.withdraw(30).unwrap();
        assert_eq!(wd.exit_value, 30);
        assert_eq!(pil.balance(), 0);
    }
}
