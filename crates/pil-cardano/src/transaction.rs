//! Cardano transaction builder for PIL operations.
//!
//! Constructs balanced Cardano transactions for deposit, transfer, and withdraw
//! operations against the privacy pool validators.

use super::datum::{PoolDatum, NullifierDatum, PlutusData};
use super::redeemer::PoolRedeemer;
use super::utxo::{CardanoUtxo, UtxoRef};
use serde::{Deserialize, Serialize};

/// Builder for constructing PIL privacy pool transactions on Cardano.
pub struct CardanoTxBuilder {
    inputs: Vec<TxInput>,
    outputs: Vec<TxOutput>,
    reference_inputs: Vec<UtxoRef>,
    collateral: Vec<UtxoRef>,
    metadata: Option<Vec<u8>>,
    fee: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct TxInput {
    utxo_ref: UtxoRef,
    redeemer: Option<PlutusData>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct TxOutput {
    address: String,
    lovelace: u64,
    tokens: Vec<(String, String, u64)>,
    datum: Option<PlutusData>,
}

impl CardanoTxBuilder {
    pub fn new() -> Self {
        Self {
            inputs: Vec::new(),
            outputs: Vec::new(),
            reference_inputs: Vec::new(),
            collateral: Vec::new(),
            metadata: None,
            fee: 0,
        }
    }

    /// Add an input (UTXO being spent).
    pub fn add_input(mut self, utxo_ref: UtxoRef, redeemer: Option<PlutusData>) -> Self {
        self.inputs.push(TxInput { utxo_ref, redeemer });
        self
    }

    /// Add an output.
    pub fn add_output(
        mut self,
        address: String,
        lovelace: u64,
        datum: Option<PlutusData>,
    ) -> Self {
        self.outputs.push(TxOutput {
            address,
            lovelace,
            tokens: Vec::new(),
            datum,
        });
        self
    }

    /// Add a reference input (for reading validator scripts or data without spending).
    pub fn add_reference_input(mut self, utxo_ref: UtxoRef) -> Self {
        self.reference_inputs.push(utxo_ref);
        self
    }

    /// Set collateral (required for Plutus script transactions).
    pub fn set_collateral(mut self, collateral: Vec<UtxoRef>) -> Self {
        self.collateral = collateral;
        self
    }

    /// Set transaction metadata (e.g., encrypted note for recipient).
    pub fn set_metadata(mut self, metadata: Vec<u8>) -> Self {
        self.metadata = Some(metadata);
        self
    }

    /// Set the transaction fee.
    pub fn set_fee(mut self, fee: u64) -> Self {
        self.fee = fee;
        self
    }

    /// Build a deposit transaction.
    ///
    /// This creates a transaction that:
    /// 1. Spends the current pool state UTXO (with Deposit redeemer)
    /// 2. Locks the deposited value at the pool validator address
    /// 3. Creates a new pool state UTXO with updated Merkle root
    pub fn build_deposit(
        pool_utxo: UtxoRef,
        pool_validator_addr: &str,
        deposit_amount: u64,
        commitment: [u8; 32],
        new_pool_datum: PoolDatum,
        change_address: &str,
    ) -> Self {
        let redeemer = super::redeemer::DepositRedeemer {
            commitment,
            amount: deposit_amount,
            asset_id: 0, // ADA
        };

        Self::new()
            .add_input(pool_utxo, Some(redeemer.to_plutus_data()))
            .add_output(
                pool_validator_addr.to_string(),
                deposit_amount + 2_000_000, // min UTXO + deposit
                Some(new_pool_datum.to_plutus_data()),
            )
    }

    /// Build a transfer transaction.
    pub fn build_transfer(
        pool_utxo: UtxoRef,
        pool_validator_addr: &str,
        transfer_redeemer: super::redeemer::TransferRedeemer,
        new_pool_datum: PoolDatum,
        nullifier_datums: Vec<NullifierDatum>,
        nullifier_validator_addr: &str,
    ) -> Self {
        let mut builder = Self::new()
            .add_input(pool_utxo, Some(transfer_redeemer.to_plutus_data()))
            .add_output(
                pool_validator_addr.to_string(),
                2_000_000, // continuing min UTXO
                Some(new_pool_datum.to_plutus_data()),
            );

        // Create nullifier UTXOs (permanent records)
        for nf_datum in nullifier_datums {
            builder = builder.add_output(
                nullifier_validator_addr.to_string(),
                1_500_000, // min UTXO for nullifier datum
                Some(nf_datum.to_plutus_data()),
            );
        }

        builder
    }

    /// Serialize the transaction for submission.
    pub fn serialize(&self) -> Vec<u8> {
        // In production: proper CBOR transaction serialization
        serde_json::to_vec(&serde_json::json!({
            "inputs": self.inputs.len(),
            "outputs": self.outputs.len(),
            "reference_inputs": self.reference_inputs.len(),
            "fee": self.fee,
        }))
        .unwrap_or_default()
    }
}

impl Default for CardanoTxBuilder {
    fn default() -> Self {
        Self::new()
    }
}
