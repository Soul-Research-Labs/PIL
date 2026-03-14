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
//! pil.cross_chain_send(ChainDomain::CosmosHub, recipient_owner, 50).unwrap();
//! ```

use ff::Field;
use halo2_proofs::circuit::Value;
use pil_circuits::transfer::TransferCircuit;
use pil_circuits::withdraw::WithdrawCircuit;
use pil_client::{TxRecord, Wallet};
use pil_note::{keys::SpendingKey, note::Note};
use pil_pool::PrivacyPool;
use pil_primitives::{
    domain::{ChainDomain, DomainSeparator},
    types::Base,
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
        self.wallet.record_tx(TxRecord::Deposit {
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
                pil_note::derive_nullifier_v2(
                    self.spending_key.to_base(),
                    n.note.commitment(),
                    &self.domain,
                )
            })
            .collect();

        // Gather witness values for circuit
        let input_values: Vec<Base> = selected.iter().map(|n| Base::from(n.note.value)).collect();
        let input_randomness: Vec<Base> = selected.iter().map(|n| n.note.randomness).collect();

        // Retrieve real Merkle authentication paths for input notes
        let merkle_paths: Vec<_> = selected
            .iter()
            .map(|n| self.pool.authentication_path(n.leaf_index))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| PilError::Pool(e.to_string()))?;
        drop(selected);

        // Create output notes
        let recipient_note = Note::new(value, recipient_owner, 0);
        let change_note = Note::new(change, self.spending_key.owner(), 0);

        let recipient_cm = recipient_note.commitment();
        let change_cm = change_note.commitment();

        // Build Merkle witness arrays from real paths
        let mut merkle_siblings = [[Value::known(Base::ZERO); 32]; 2];
        let mut merkle_indices = [Value::known(0u64); 2];
        for (i, path) in merkle_paths.iter().enumerate().take(2) {
            for (level, sibling) in path.siblings.iter().enumerate() {
                merkle_siblings[i][level] = Value::known(*sibling);
            }
            merkle_indices[i] = Value::known(path.leaf_index);
        }

        // Build transfer circuit
        let circuit = TransferCircuit {
            spending_key: Value::known(self.spending_key.to_base()),
            input_values: [
                Value::known(input_values.first().copied().unwrap_or(Base::ZERO)),
                Value::known(input_values.get(1).copied().unwrap_or(Base::ZERO)),
            ],
            input_randomness: [
                Value::known(input_randomness.first().copied().unwrap_or(Base::ZERO)),
                Value::known(input_randomness.get(1).copied().unwrap_or(Base::ZERO)),
            ],
            input_asset_ids: [Value::known(Base::ZERO); 2],
            output_values: [
                Value::known(Base::from(value)),
                Value::known(Base::from(change)),
            ],
            output_owners: [
                Value::known(recipient_owner),
                Value::known(self.spending_key.owner()),
            ],
            output_randomness: [
                Value::known(recipient_note.randomness),
                Value::known(change_note.randomness),
            ],
            output_asset_ids: [Value::known(Base::ZERO); 2],
            fee: Value::known(Base::ZERO),
            merkle_siblings,
            merkle_indices,
            domain_tag: Value::known(self.domain.to_domain_tag()),
        };

        // Generate ZK proof
        let proof_bytes = pil_prover::prove_transfer(&self.keys, circuit, &[&[]])
            .map_err(|e| PilError::Proof(e.to_string()))?;

        // Process transfer in the pool
        let receipt = self
            .pool
            .process_transfer(&nullifiers, &[recipient_cm, change_cm], &proof_bytes)
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
                pil_note::derive_nullifier_v2(
                    self.spending_key.to_base(),
                    n.note.commitment(),
                    &self.domain,
                )
            })
            .collect();

        let input_values: Vec<Base> = selected.iter().map(|n| Base::from(n.note.value)).collect();
        let input_randomness: Vec<Base> = selected.iter().map(|n| n.note.randomness).collect();

        // Retrieve Merkle authentication paths for input notes
        let merkle_paths: Vec<_> = selected
            .iter()
            .map(|n| self.pool.authentication_path(n.leaf_index))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| PilError::Pool(e.to_string()))?;
        drop(selected);

        let change_note = Note::new(change, self.spending_key.owner(), 0);
        let change_cm = change_note.commitment();

        // Build Merkle witness arrays from real paths
        let mut merkle_siblings = [[Value::known(Base::ZERO); 32]; 2];
        let mut merkle_indices = [Value::known(0u64); 2];
        for (i, path) in merkle_paths.iter().enumerate().take(2) {
            for (level, sibling) in path.siblings.iter().enumerate() {
                merkle_siblings[i][level] = Value::known(*sibling);
            }
            merkle_indices[i] = Value::known(path.leaf_index);
        }

        // Build withdraw circuit
        let circuit = WithdrawCircuit {
            spending_key: Value::known(self.spending_key.to_base()),
            input_values: [
                Value::known(input_values.first().copied().unwrap_or(Base::ZERO)),
                Value::known(input_values.get(1).copied().unwrap_or(Base::ZERO)),
            ],
            input_randomness: [
                Value::known(input_randomness.first().copied().unwrap_or(Base::ZERO)),
                Value::known(input_randomness.get(1).copied().unwrap_or(Base::ZERO)),
            ],
            input_asset_ids: [Value::known(Base::ZERO); 2],
            output_values: [Value::known(Base::from(change)), Value::known(Base::ZERO)],
            output_owners: [
                Value::known(self.spending_key.owner()),
                Value::known(Base::ZERO),
            ],
            output_randomness: [
                Value::known(change_note.randomness),
                Value::known(Base::ZERO),
            ],
            output_asset_ids: [Value::known(Base::ZERO); 2],
            exit_value: Value::known(Base::from(value)),
            fee: Value::known(Base::ZERO),
            merkle_siblings,
            merkle_indices,
            domain_tag: Value::known(self.domain.to_domain_tag()),
        };

        // Generate ZK proof
        let proof_bytes = pil_prover::prove_withdraw(&self.keys, circuit, &[&[]])
            .map_err(|e| PilError::Proof(e.to_string()))?;

        let receipt = self
            .pool
            .process_withdraw(&nullifiers, &[change_cm], value, 0, &proof_bytes)
            .map_err(|e| PilError::Pool(e.to_string()))?;

        for idx in &selected_leaf_indices {
            self.wallet.mark_spent(*idx);
        }
        if change > 0 {
            self.wallet.add_note(change_note, receipt.leaf_indices[0]);
        }
        self.wallet
            .record_tx(TxRecord::Withdraw { value, asset_id: 0 });

        Ok(WithdrawResult {
            exit_value: value,
            leaf_indices: receipt.leaf_indices,
            root: receipt.root,
        })
    }

    /// Cross-chain private transfer: spend notes on the current chain
    /// and produce output commitments tagged with the destination chain's domain.
    ///
    /// The resulting proof and commitments must be relayed to the destination
    /// chain by the bridge relayer (pil-bridge).
    pub fn cross_chain_send(
        &mut self,
        dest_chain: ChainDomain,
        recipient_owner: Base,
        value: u64,
    ) -> Result<CrossChainSendResult, PilError> {
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
                pil_note::derive_nullifier_v2(
                    self.spending_key.to_base(),
                    n.note.commitment(),
                    &self.domain,
                )
            })
            .collect();

        let input_values: Vec<Base> = selected.iter().map(|n| Base::from(n.note.value)).collect();
        let input_randomness: Vec<Base> = selected.iter().map(|n| n.note.randomness).collect();

        // Retrieve real Merkle authentication paths for input notes
        let merkle_paths: Vec<_> = selected
            .iter()
            .map(|n| self.pool.authentication_path(n.leaf_index))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| PilError::Pool(e.to_string()))?;
        drop(selected);

        // Output notes use the DESTINATION chain's domain for cross-chain isolation
        let dest_domain = DomainSeparator::new(dest_chain, 0);

        let recipient_note = Note::new(value, recipient_owner, 0);
        let change_note = Note::new(change, self.spending_key.owner(), 0);

        let recipient_cm = recipient_note.commitment();
        let change_cm = change_note.commitment();

        // Build Merkle witness arrays from real paths
        let mut merkle_siblings = [[Value::known(Base::ZERO); 32]; 2];
        let mut merkle_indices = [Value::known(0u64); 2];
        for (i, path) in merkle_paths.iter().enumerate().take(2) {
            for (level, sibling) in path.siblings.iter().enumerate() {
                merkle_siblings[i][level] = Value::known(*sibling);
            }
            merkle_indices[i] = Value::known(path.leaf_index);
        }

        // Embed destination domain tag in the circuit's output asset IDs
        // This ensures the proof binds to the destination chain
        let dest_tag = dest_domain.to_domain_tag();

        // Build transfer circuit (same circuit, but output domain differs)
        let circuit = TransferCircuit {
            spending_key: Value::known(self.spending_key.to_base()),
            input_values: [
                Value::known(input_values.first().copied().unwrap_or(Base::ZERO)),
                Value::known(input_values.get(1).copied().unwrap_or(Base::ZERO)),
            ],
            input_randomness: [
                Value::known(input_randomness.first().copied().unwrap_or(Base::ZERO)),
                Value::known(input_randomness.get(1).copied().unwrap_or(Base::ZERO)),
            ],
            input_asset_ids: [Value::known(Base::ZERO); 2],
            output_values: [
                Value::known(Base::from(value)),
                Value::known(Base::from(change)),
            ],
            output_owners: [
                Value::known(recipient_owner),
                Value::known(self.spending_key.owner()),
            ],
            output_randomness: [
                Value::known(recipient_note.randomness),
                Value::known(change_note.randomness),
            ],
            output_asset_ids: [Value::known(dest_tag), Value::known(Base::ZERO)],
            fee: Value::known(Base::ZERO),
            merkle_siblings,
            merkle_indices,
            domain_tag: Value::known(self.domain.to_domain_tag()),
        };

        let proof_bytes = pil_prover::prove_transfer(&self.keys, circuit, &[&[]])
            .map_err(|e| PilError::Proof(e.to_string()))?;

        let receipt = self
            .pool
            .process_transfer(&nullifiers, &[recipient_cm, change_cm], &proof_bytes)
            .map_err(|e| PilError::Pool(e.to_string()))?;

        for idx in &selected_leaf_indices {
            self.wallet.mark_spent(*idx);
        }
        self.wallet.add_note(change_note, receipt.leaf_indices[1]);
        self.wallet.record_tx(TxRecord::Send {
            value,
            asset_id: 0,
            recipient_owner: format!("{recipient_owner:?}"),
        });

        Ok(CrossChainSendResult {
            source_chain: self.chain,
            dest_chain,
            nullifiers_spent: receipt.nullifiers_spent,
            leaf_indices: receipt.leaf_indices,
            root: receipt.root,
            proof_bytes,
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

#[derive(Debug)]
pub struct CrossChainSendResult {
    pub source_chain: ChainDomain,
    pub dest_chain: ChainDomain,
    pub nullifiers_spent: usize,
    pub leaf_indices: Vec<u64>,
    pub root: Base,
    pub proof_bytes: Vec<u8>,
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
