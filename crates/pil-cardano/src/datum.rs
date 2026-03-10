//! Datum types for Cardano eUTXO model.
//!
//! In Cardano's eUTXO model, each UTXO can carry a typed data payload (datum).
//! The privacy pool state is maintained across multiple UTXOs:
//!
//! - **Pool UTXO**: Contains the Merkle root and pool metadata
//! - **Nullifier UTXOs**: Each spent nullifier is recorded as a UTXO datum
//! - **Epoch UTXO**: Contains the current epoch state

use pil_primitives::types::Base;
use serde::{Deserialize, Serialize};

/// Datum attached to the main privacy pool state UTXO.
///
/// This UTXO is a "continuing output" — each transaction that modifies
/// the pool must consume this UTXO and produce a new one with updated state.
/// (CIP-68 / continuing state pattern)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PoolDatum {
    /// Current Merkle root of the note commitment tree.
    pub merkle_root: [u8; 32],
    /// Total number of note commitments.
    pub note_count: u64,
    /// Current epoch number.
    pub current_epoch: u64,
    /// Pool NFT identifier (policy_id preventing UTXO duplication).
    pub pool_nft_policy: [u8; 28],
    /// Admin public key hash (for governance operations).
    pub admin_pkh: [u8; 28],
}

impl PoolDatum {
    /// Encode as CBOR for Plutus datum.
    pub fn to_plutus_data(&self) -> PlutusData {
        PlutusData::Constr {
            tag: 0,
            fields: vec![
                PlutusData::Bytes(self.merkle_root.to_vec()),
                PlutusData::Integer(self.note_count as i128),
                PlutusData::Integer(self.current_epoch as i128),
                PlutusData::Bytes(self.pool_nft_policy.to_vec()),
                PlutusData::Bytes(self.admin_pkh.to_vec()),
            ],
        }
    }
}

/// Datum for nullifier UTXO entries.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NullifierDatum {
    /// The nullifier hash.
    pub nullifier: [u8; 32],
    /// Epoch in which this nullifier was spent.
    pub epoch: u64,
    /// Domain separator (chain_id, app_id) for cross-chain isolation.
    pub domain_chain_id: u32,
    pub domain_app_id: u32,
}

impl NullifierDatum {
    pub fn to_plutus_data(&self) -> PlutusData {
        PlutusData::Constr {
            tag: 1,
            fields: vec![
                PlutusData::Bytes(self.nullifier.to_vec()),
                PlutusData::Integer(self.epoch as i128),
                PlutusData::Integer(self.domain_chain_id as i128),
                PlutusData::Integer(self.domain_app_id as i128),
            ],
        }
    }
}

/// Simplified Plutus data representation for serialization.
/// In production, use a proper CBOR library (minicbor or pallas-codec).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PlutusData {
    Constr { tag: u64, fields: Vec<PlutusData> },
    Integer(i128),
    Bytes(Vec<u8>),
    List(Vec<PlutusData>),
    Map(Vec<(PlutusData, PlutusData)>),
}

impl PlutusData {
    /// Encode to CBOR bytes (simplified — production should use minicbor).
    pub fn to_cbor(&self) -> Vec<u8> {
        // Placeholder: proper CBOR encoding
        serde_json::to_vec(self).unwrap_or_default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pool_datum_serialization() {
        let datum = PoolDatum {
            merkle_root: [0xAB; 32],
            note_count: 42,
            current_epoch: 5,
            pool_nft_policy: [0xCD; 28],
            admin_pkh: [0xEF; 28],
        };
        let plutus = datum.to_plutus_data();
        let cbor = plutus.to_cbor();
        assert!(!cbor.is_empty());
    }
}
