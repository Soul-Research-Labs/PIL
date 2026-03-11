//! Cardano transaction builder for PIL operations.
//!
//! Constructs balanced Cardano transactions for deposit, transfer, and withdraw
//! operations against the privacy pool validators.
//!
//! Serializes to Cardano-compatible CBOR format following the Shelley-era
//! transaction specification (CIP-0021).

use super::datum::{NullifierDatum, PlutusData, PoolDatum};
use super::utxo::UtxoRef;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Builder for constructing PIL privacy pool transactions on Cardano.
pub struct CardanoTxBuilder {
    inputs: Vec<TxInput>,
    outputs: Vec<TxOutput>,
    reference_inputs: Vec<UtxoRef>,
    collateral: Vec<UtxoRef>,
    metadata: Option<Vec<u8>>,
    fee: u64,
    ttl: Option<u64>,
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
            ttl: None,
        }
    }

    /// Add an input (UTXO being spent).
    pub fn add_input(mut self, utxo_ref: UtxoRef, redeemer: Option<PlutusData>) -> Self {
        self.inputs.push(TxInput { utxo_ref, redeemer });
        self
    }

    /// Add an output.
    pub fn add_output(mut self, address: String, lovelace: u64, datum: Option<PlutusData>) -> Self {
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

    /// Set the transaction TTL (time-to-live) as an absolute slot number.
    pub fn set_ttl(mut self, ttl: u64) -> Self {
        self.ttl = Some(ttl);
        self
    }

    /// Estimate the minimum transaction fee.
    ///
    /// Fee = base_fee + size_coeff * tx_size_bytes
    /// Cardano mainnet: base_fee = 155381, size_coeff = 44 lovelace/byte
    pub fn estimate_fee(&self) -> u64 {
        let base_fee: u64 = 155_381;
        let size_coeff: u64 = 44;

        // Estimate transaction size in bytes
        let input_size = self.inputs.len() as u64 * 180;
        let output_size = self.outputs.len() as u64 * 160;
        let ref_input_size = self.reference_inputs.len() as u64 * 40;
        let collateral_size = self.collateral.len() as u64 * 40;
        let metadata_size = self.metadata.as_ref().map(|m| m.len() as u64).unwrap_or(0);
        // Redeemer/script witness overhead
        let script_overhead: u64 =
            self.inputs.iter().filter(|i| i.redeemer.is_some()).count() as u64 * 200;

        let estimated_size = input_size
            + output_size
            + ref_input_size
            + collateral_size
            + metadata_size
            + script_overhead
            + 50; // CBOR framing overhead

        base_fee + size_coeff * estimated_size
    }

    /// Minimum collateral required (150% of fee, Cardano protocol parameter).
    pub fn min_collateral(&self) -> u64 {
        let fee = if self.fee > 0 {
            self.fee
        } else {
            self.estimate_fee()
        };
        fee * 3 / 2 // 150%
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
        _change_address: &str,
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

    /// Serialize the transaction body to CBOR.
    ///
    /// Follows the Cardano transaction body format:
    /// ```text
    /// transaction_body = {
    ///   0: set<transaction_input>,   ; inputs
    ///   1: [* transaction_output],   ; outputs
    ///   2: coin,                     ; fee
    ///   ? 3: uint,                   ; ttl
    ///   ? 7: auxiliary_data_hash,    ; metadata hash
    ///   ? 13: set<transaction_input>,; collateral inputs
    ///   ? 18: set<transaction_input>,; reference inputs
    /// }
    /// ```
    pub fn serialize(&self) -> Vec<u8> {
        let mut cbor = CborEncoder::new();

        // Count the number of map entries
        let mut map_len = 3u64; // inputs, outputs, fee always present
        if self.ttl.is_some() {
            map_len += 1;
        }
        if self.metadata.is_some() {
            map_len += 1;
        }
        if !self.collateral.is_empty() {
            map_len += 1;
        }
        if !self.reference_inputs.is_empty() {
            map_len += 1;
        }

        cbor.write_map(map_len);

        // Key 0: inputs (set of [tx_hash, index])
        cbor.write_uint(0);
        cbor.write_array(self.inputs.len() as u64);
        for input in &self.inputs {
            cbor.write_array(2);
            cbor.write_bytes(&input.utxo_ref.tx_hash);
            cbor.write_uint(input.utxo_ref.output_index as u64);
        }

        // Key 1: outputs ([address_bytes, amount] or [address_bytes, [amount, multiasset]])
        cbor.write_uint(1);
        cbor.write_array(self.outputs.len() as u64);
        for output in &self.outputs {
            let addr_bytes = hex::decode(&output.address).unwrap_or_default();
            if let Some(datum) = &output.datum {
                // Post-Alonzo output with datum: map format
                cbor.write_map(3);
                cbor.write_uint(0); // address
                cbor.write_bytes(&addr_bytes);
                cbor.write_uint(1); // amount
                cbor.write_uint(output.lovelace);
                cbor.write_uint(2); // datum option (inline datum = [1, datum_cbor])
                cbor.write_array(2);
                cbor.write_uint(1); // inline datum tag
                let datum_bytes = datum.to_cbor();
                cbor.write_bytes(&datum_bytes);
            } else {
                // Simple output: [address, amount]
                cbor.write_array(2);
                cbor.write_bytes(&addr_bytes);
                cbor.write_uint(output.lovelace);
            }
        }

        // Key 2: fee
        cbor.write_uint(2);
        cbor.write_uint(self.fee);

        // Key 3: TTL (optional)
        if let Some(ttl) = self.ttl {
            cbor.write_uint(3);
            cbor.write_uint(ttl);
        }

        // Key 7: auxiliary data hash (optional)
        if let Some(ref metadata) = self.metadata {
            cbor.write_uint(7);
            let hash: [u8; 32] = Sha256::digest(metadata).into();
            cbor.write_bytes(&hash);
        }

        // Key 13: collateral inputs (optional)
        if !self.collateral.is_empty() {
            cbor.write_uint(13);
            cbor.write_array(self.collateral.len() as u64);
            for col in &self.collateral {
                cbor.write_array(2);
                cbor.write_bytes(&col.tx_hash);
                cbor.write_uint(col.output_index as u64);
            }
        }

        // Key 18: reference inputs (optional)
        if !self.reference_inputs.is_empty() {
            cbor.write_uint(18);
            cbor.write_array(self.reference_inputs.len() as u64);
            for ri in &self.reference_inputs {
                cbor.write_array(2);
                cbor.write_bytes(&ri.tx_hash);
                cbor.write_uint(ri.output_index as u64);
            }
        }

        cbor.into_bytes()
    }

    /// Compute the transaction hash (Blake2b-256 of the serialized tx body).
    pub fn tx_hash(&self) -> [u8; 32] {
        // Cardano uses Blake2b-256 for tx hashes.
        // Here we use SHA-256 as a placeholder since blake2 isn't imported yet.
        let body = self.serialize();
        Sha256::digest(&body).into()
    }
}

impl Default for CardanoTxBuilder {
    fn default() -> Self {
        Self::new()
    }
}

/// Minimal CBOR encoder following RFC 7049 for Cardano transaction serialization.
struct CborEncoder {
    buf: Vec<u8>,
}

impl CborEncoder {
    fn new() -> Self {
        Self {
            buf: Vec::with_capacity(512),
        }
    }

    fn into_bytes(self) -> Vec<u8> {
        self.buf
    }

    /// Encode an unsigned integer (major type 0).
    fn write_uint(&mut self, value: u64) {
        self.write_type_and_length(0, value);
    }

    /// Encode a byte string (major type 2).
    fn write_bytes(&mut self, data: &[u8]) {
        self.write_type_and_length(2, data.len() as u64);
        self.buf.extend_from_slice(data);
    }

    /// Encode an array header (major type 4).
    fn write_array(&mut self, len: u64) {
        self.write_type_and_length(4, len);
    }

    /// Encode a map header (major type 5).
    fn write_map(&mut self, len: u64) {
        self.write_type_and_length(5, len);
    }

    /// Write a CBOR type header with its length.
    fn write_type_and_length(&mut self, major: u8, value: u64) {
        let major_bits = major << 5;
        if value < 24 {
            self.buf.push(major_bits | value as u8);
        } else if value <= u8::MAX as u64 {
            self.buf.push(major_bits | 24);
            self.buf.push(value as u8);
        } else if value <= u16::MAX as u64 {
            self.buf.push(major_bits | 25);
            self.buf.extend_from_slice(&(value as u16).to_be_bytes());
        } else if value <= u32::MAX as u64 {
            self.buf.push(major_bits | 26);
            self.buf.extend_from_slice(&(value as u32).to_be_bytes());
        } else {
            self.buf.push(major_bits | 27);
            self.buf.extend_from_slice(&value.to_be_bytes());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cbor_encoder_uint() {
        let mut enc = CborEncoder::new();
        enc.write_uint(0);
        assert_eq!(enc.into_bytes(), vec![0x00]);

        let mut enc = CborEncoder::new();
        enc.write_uint(23);
        assert_eq!(enc.into_bytes(), vec![0x17]);

        let mut enc = CborEncoder::new();
        enc.write_uint(24);
        assert_eq!(enc.into_bytes(), vec![0x18, 0x18]);

        let mut enc = CborEncoder::new();
        enc.write_uint(1000);
        assert_eq!(enc.into_bytes(), vec![0x19, 0x03, 0xe8]);
    }

    #[test]
    fn cbor_encoder_bytes() {
        let mut enc = CborEncoder::new();
        enc.write_bytes(&[0x01, 0x02, 0x03]);
        assert_eq!(enc.into_bytes(), vec![0x43, 0x01, 0x02, 0x03]);
    }

    #[test]
    fn cbor_encoder_array() {
        let mut enc = CborEncoder::new();
        enc.write_array(3);
        enc.write_uint(1);
        enc.write_uint(2);
        enc.write_uint(3);
        assert_eq!(enc.into_bytes(), vec![0x83, 0x01, 0x02, 0x03]);
    }

    #[test]
    fn cbor_encoder_map() {
        let mut enc = CborEncoder::new();
        enc.write_map(1);
        enc.write_uint(0);
        enc.write_uint(42);
        // Map with 1 entry: {0: 42}
        assert_eq!(enc.into_bytes(), vec![0xa1, 0x00, 0x18, 0x2a]);
    }

    #[test]
    fn tx_builder_serialize_produces_cbor() {
        let utxo = UtxoRef {
            tx_hash: [0xABu8; 32],
            output_index: 0,
        };

        let tx = CardanoTxBuilder::new()
            .add_input(utxo.clone(), None)
            .add_output("00".repeat(28), 2_000_000, None)
            .set_fee(200_000)
            .set_ttl(50_000_000);

        let cbor = tx.serialize();
        // Should start with a CBOR map header (0xa4 = map of 4 entries)
        assert_eq!(cbor[0], 0xa4);
        assert!(!cbor.is_empty());
    }

    #[test]
    fn tx_builder_estimate_fee() {
        let utxo = UtxoRef {
            tx_hash: [0u8; 32],
            output_index: 0,
        };

        let tx = CardanoTxBuilder::new()
            .add_input(utxo.clone(), None)
            .add_output("addr".to_string(), 2_000_000, None);

        let fee = tx.estimate_fee();
        // Should be > base fee
        assert!(fee > 155_381);
    }

    #[test]
    fn tx_builder_min_collateral() {
        let tx = CardanoTxBuilder::new().set_fee(200_000);
        assert_eq!(tx.min_collateral(), 300_000);
    }

    #[test]
    fn tx_hash_deterministic() {
        let utxo = UtxoRef {
            tx_hash: [1u8; 32],
            output_index: 0,
        };

        let tx1 = CardanoTxBuilder::new()
            .add_input(utxo.clone(), None)
            .add_output("00".to_string(), 1_000_000, None)
            .set_fee(170_000);

        let tx2 = CardanoTxBuilder::new()
            .add_input(utxo, None)
            .add_output("00".to_string(), 1_000_000, None)
            .set_fee(170_000);

        assert_eq!(tx1.tx_hash(), tx2.tx_hash());
    }
}
