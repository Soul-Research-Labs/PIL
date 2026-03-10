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
    /// Encode to CBOR bytes (RFC 7049 / RFC 8949).
    ///
    /// Plutus datum CBOR follows the Cardano ledger encoding:
    /// - Constr: tag(121 + n) for n < 7, else tag(1280 + n), then array of fields
    /// - Integer: CBOR integer (major type 0/1)
    /// - Bytes: CBOR byte string (major type 2)
    /// - List: CBOR array (major type 4)
    /// - Map: CBOR map (major type 5)
    pub fn to_cbor(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        self.encode_cbor(&mut buf);
        buf
    }

    fn encode_cbor(&self, buf: &mut Vec<u8>) {
        match self {
            PlutusData::Constr { tag, fields } => {
                // Plutus uses CBOR tags 121..127 for constructors 0..6,
                // and 1280+ for constructors >= 7.
                let cbor_tag = if *tag < 7 { 121 + tag } else { 1280 + tag };
                Self::encode_tag(buf, cbor_tag);
                Self::encode_array_header(buf, fields.len());
                for f in fields {
                    f.encode_cbor(buf);
                }
            }
            PlutusData::Integer(v) => {
                if *v >= 0 {
                    Self::encode_uint(buf, 0, *v as u64);
                } else {
                    // CBOR major type 1: negative integer = -1 - n
                    Self::encode_uint(buf, 1, (-1 - *v) as u64);
                }
            }
            PlutusData::Bytes(bytes) => {
                Self::encode_uint(buf, 2, bytes.len() as u64);
                buf.extend_from_slice(bytes);
            }
            PlutusData::List(items) => {
                Self::encode_array_header(buf, items.len());
                for item in items {
                    item.encode_cbor(buf);
                }
            }
            PlutusData::Map(entries) => {
                Self::encode_uint(buf, 5, entries.len() as u64);
                for (k, v) in entries {
                    k.encode_cbor(buf);
                    v.encode_cbor(buf);
                }
            }
        }
    }

    /// Encode a CBOR unsigned integer with the given major type (0..7).
    fn encode_uint(buf: &mut Vec<u8>, major: u8, value: u64) {
        let mt = major << 5;
        if value < 24 {
            buf.push(mt | value as u8);
        } else if value <= 0xFF {
            buf.push(mt | 24);
            buf.push(value as u8);
        } else if value <= 0xFFFF {
            buf.push(mt | 25);
            buf.extend_from_slice(&(value as u16).to_be_bytes());
        } else if value <= 0xFFFF_FFFF {
            buf.push(mt | 26);
            buf.extend_from_slice(&(value as u32).to_be_bytes());
        } else {
            buf.push(mt | 27);
            buf.extend_from_slice(&value.to_be_bytes());
        }
    }

    /// Encode a CBOR array header (major type 4).
    fn encode_array_header(buf: &mut Vec<u8>, len: usize) {
        Self::encode_uint(buf, 4, len as u64);
    }

    /// Encode a CBOR tag (major type 6).
    fn encode_tag(buf: &mut Vec<u8>, tag: u64) {
        Self::encode_uint(buf, 6, tag);
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
        // First byte should be CBOR tag 121 (constructor 0): 0xd8 0x79
        assert_eq!(cbor[0], 0xd8); // tag initial byte
        assert_eq!(cbor[1], 121);  // tag value for constructor 0
    }

    #[test]
    fn cbor_integer_encoding() {
        let data = PlutusData::Integer(42);
        let cbor = data.to_cbor();
        // CBOR: major type 0, value 42 (< 256) → 0x18 0x2a
        assert_eq!(cbor, vec![0x18, 42]);
    }

    #[test]
    fn cbor_small_integer() {
        let data = PlutusData::Integer(10);
        let cbor = data.to_cbor();
        // CBOR: value < 24 → single byte 0x0a
        assert_eq!(cbor, vec![0x0a]);
    }

    #[test]
    fn cbor_negative_integer() {
        let data = PlutusData::Integer(-1);
        let cbor = data.to_cbor();
        // CBOR: major type 1, value 0 → 0x20
        assert_eq!(cbor, vec![0x20]);
    }

    #[test]
    fn cbor_bytes_encoding() {
        let data = PlutusData::Bytes(vec![0xDE, 0xAD]);
        let cbor = data.to_cbor();
        // CBOR: major type 2, length 2, then bytes
        assert_eq!(cbor, vec![0x42, 0xDE, 0xAD]);
    }

    #[test]
    fn nullifier_datum_roundtrip() {
        let datum = NullifierDatum {
            nullifier: [0x11; 32],
            epoch: 3,
            domain_chain_id: 1,
            domain_app_id: 0,
        };
        let cbor = datum.to_plutus_data().to_cbor();
        assert!(!cbor.is_empty());
        // Constructor 1 → tag 122 → 0xd8 0x7a
        assert_eq!(cbor[0], 0xd8);
        assert_eq!(cbor[1], 122);
    }
}
