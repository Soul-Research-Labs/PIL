//! Serialisation helpers for Groth16 proofs and keys.
//!
//! Provides compact serialisation formats suitable for:
//! - Cardano transaction metadata (CBOR)
//! - On-chain datum fields (hex-encoded bytes)

use ark_bls12_381::Bls12_381;
use ark_groth16::{Proof, VerifyingKey};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};

/// Serialise a Groth16 proof to bytes (compressed, ~192 bytes).
pub fn proof_to_bytes(proof: &Proof<Bls12_381>) -> Vec<u8> {
    let mut buf = Vec::new();
    proof
        .serialize_compressed(&mut buf)
        .expect("proof serialisation");
    buf
}

/// Deserialise a Groth16 proof from bytes.
pub fn proof_from_bytes(bytes: &[u8]) -> Result<Proof<Bls12_381>, SerialiseError> {
    Proof::deserialize_compressed(bytes).map_err(|e| SerialiseError::Deserialise(e.to_string()))
}

/// Serialise a verifying key to bytes.
pub fn vk_to_bytes(vk: &VerifyingKey<Bls12_381>) -> Vec<u8> {
    let mut buf = Vec::new();
    vk.serialize_compressed(&mut buf).expect("vk serialisation");
    buf
}

/// Deserialise a verifying key from bytes.
pub fn vk_from_bytes(bytes: &[u8]) -> Result<VerifyingKey<Bls12_381>, SerialiseError> {
    VerifyingKey::deserialize_compressed(bytes)
        .map_err(|e| SerialiseError::Deserialise(e.to_string()))
}

/// Serialise proof to hex string (for Cardano datum fields).
pub fn proof_to_hex(proof: &Proof<Bls12_381>) -> String {
    hex::encode(proof_to_bytes(proof))
}

/// Deserialise proof from hex string.
pub fn proof_from_hex(hex_str: &str) -> Result<Proof<Bls12_381>, SerialiseError> {
    let bytes = hex::decode(hex_str).map_err(|e| SerialiseError::Deserialise(e.to_string()))?;
    proof_from_bytes(&bytes)
}

#[derive(Debug, thiserror::Error)]
pub enum SerialiseError {
    #[error("deserialisation failed: {0}")]
    Deserialise(String),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::prover::WrapperProver;
    use ark_bls12_381::Fr as BlsFr;

    #[test]
    fn proof_roundtrip_serialisation() {
        let (pk, _vk) = WrapperProver::setup().unwrap();
        let inputs = vec![BlsFr::from(42u64)];
        let wrapper_proof = WrapperProver::prove(&pk, inputs, 0).unwrap();

        // Serialise and deserialise
        let bytes = proof_to_bytes(&wrapper_proof.groth16_proof);
        assert!(
            bytes.len() < 256,
            "Proof should be compact: {} bytes",
            bytes.len()
        );

        let recovered = proof_from_bytes(&bytes).unwrap();

        // Re-serialise should be identical
        let bytes2 = proof_to_bytes(&recovered);
        assert_eq!(bytes, bytes2);
    }

    #[test]
    fn proof_hex_roundtrip() {
        let (pk, _vk) = WrapperProver::setup().unwrap();
        let inputs = vec![BlsFr::from(99u64)];
        let wrapper_proof = WrapperProver::prove(&pk, inputs, 1).unwrap();

        let hex_str = proof_to_hex(&wrapper_proof.groth16_proof);
        let recovered = proof_from_hex(&hex_str).unwrap();
        assert_eq!(
            proof_to_bytes(&wrapper_proof.groth16_proof),
            proof_to_bytes(&recovered)
        );
    }
}
