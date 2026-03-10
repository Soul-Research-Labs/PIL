//! Redeemer types for Cardano validator interactions.
//!
//! Redeemers are the "action" data provided when spending a validator UTXO.
//! They tell the on-chain validator what operation is being performed.

use super::datum::PlutusData;
use serde::{Deserialize, Serialize};

/// Top-level redeemer for the privacy pool validator.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PoolRedeemer {
    Deposit(DepositRedeemer),
    Transfer(TransferRedeemer),
    Withdraw(WithdrawRedeemer),
    FinalizeEpoch(FinalizeEpochRedeemer),
}

impl PoolRedeemer {
    pub fn to_plutus_data(&self) -> PlutusData {
        match self {
            Self::Deposit(r) => r.to_plutus_data(),
            Self::Transfer(r) => r.to_plutus_data(),
            Self::Withdraw(r) => r.to_plutus_data(),
            Self::FinalizeEpoch(r) => r.to_plutus_data(),
        }
    }
}

/// Deposit redeemer: add value to the shielded pool.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DepositRedeemer {
    /// Note commitment being added.
    pub commitment: [u8; 32],
    /// Deposit amount (must match the ADA/token value in the transaction).
    pub amount: u64,
    /// Asset identifier (policy_id hash for native tokens, 0 for ADA).
    pub asset_id: u64,
}

impl DepositRedeemer {
    pub fn to_plutus_data(&self) -> PlutusData {
        PlutusData::Constr {
            tag: 0, // Deposit variant
            fields: vec![
                PlutusData::Bytes(self.commitment.to_vec()),
                PlutusData::Integer(self.amount as i128),
                PlutusData::Integer(self.asset_id as i128),
            ],
        }
    }
}

/// Transfer redeemer: private transfer within the shielded pool.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransferRedeemer {
    /// ZK proof bytes (wrapped in ProofEnvelope for metadata resistance).
    pub proof: Vec<u8>,
    /// Merkle root the proof was generated against.
    pub merkle_root: [u8; 32],
    /// Nullifiers being spent.
    pub nullifiers: Vec<[u8; 32]>,
    /// New note commitments being created.
    pub output_commitments: Vec<[u8; 32]>,
    /// Domain separation for cross-chain nullifiers.
    pub domain_chain_id: u32,
    pub domain_app_id: u32,
}

impl TransferRedeemer {
    pub fn to_plutus_data(&self) -> PlutusData {
        PlutusData::Constr {
            tag: 1, // Transfer variant
            fields: vec![
                PlutusData::Bytes(self.proof.clone()),
                PlutusData::Bytes(self.merkle_root.to_vec()),
                PlutusData::List(
                    self.nullifiers
                        .iter()
                        .map(|n| PlutusData::Bytes(n.to_vec()))
                        .collect(),
                ),
                PlutusData::List(
                    self.output_commitments
                        .iter()
                        .map(|c| PlutusData::Bytes(c.to_vec()))
                        .collect(),
                ),
                PlutusData::Integer(self.domain_chain_id as i128),
                PlutusData::Integer(self.domain_app_id as i128),
            ],
        }
    }
}

/// Withdraw redeemer: exit value from the shielded pool to a public address.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WithdrawRedeemer {
    /// ZK proof bytes.
    pub proof: Vec<u8>,
    /// Merkle root.
    pub merkle_root: [u8; 32],
    /// Nullifiers being spent.
    pub nullifiers: Vec<[u8; 32]>,
    /// Change note commitments (remaining value stays shielded).
    pub change_commitments: Vec<[u8; 32]>,
    /// Exit value (goes to the public withdrawal address).
    pub exit_value: u64,
    /// Withdrawal destination address (Shelley address bytes).
    pub destination_address: Vec<u8>,
}

impl WithdrawRedeemer {
    pub fn to_plutus_data(&self) -> PlutusData {
        PlutusData::Constr {
            tag: 2, // Withdraw variant
            fields: vec![
                PlutusData::Bytes(self.proof.clone()),
                PlutusData::Bytes(self.merkle_root.to_vec()),
                PlutusData::List(
                    self.nullifiers
                        .iter()
                        .map(|n| PlutusData::Bytes(n.to_vec()))
                        .collect(),
                ),
                PlutusData::List(
                    self.change_commitments
                        .iter()
                        .map(|c| PlutusData::Bytes(c.to_vec()))
                        .collect(),
                ),
                PlutusData::Integer(self.exit_value as i128),
                PlutusData::Bytes(self.destination_address.clone()),
            ],
        }
    }
}

/// Epoch finalization redeemer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FinalizeEpochRedeemer {
    /// The nullifier Merkle root for this epoch.
    pub nullifier_root: [u8; 32],
    /// Epoch number being finalized.
    pub epoch: u64,
}

impl FinalizeEpochRedeemer {
    pub fn to_plutus_data(&self) -> PlutusData {
        PlutusData::Constr {
            tag: 3, // FinalizeEpoch variant
            fields: vec![
                PlutusData::Bytes(self.nullifier_root.to_vec()),
                PlutusData::Integer(self.epoch as i128),
            ],
        }
    }
}
