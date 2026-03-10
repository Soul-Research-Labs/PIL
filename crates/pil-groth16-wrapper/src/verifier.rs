//! Groth16 proof verification for the wrapper circuit.
//!
//! This verifier can run off-chain (in Rust) or its logic can be
//! replicated on-chain in Plutus V3 using BLS12-381 primitives.

use ark_bls12_381::Bls12_381;
use ark_groth16::{Groth16, VerifyingKey};
use ark_snark::SNARK;

use crate::prover::WrapperProof;

/// Wrapper verifying key (BLS12-381 Groth16).
pub struct WrapperVerifyingKey {
    pub vk: VerifyingKey<Bls12_381>,
}

/// Wrapper verifier.
pub struct WrapperVerifier;

impl WrapperVerifier {
    /// Verify a wrapper proof.
    ///
    /// The single public input is the hash of the inner proof's public inputs.
    pub fn verify(
        vk: &WrapperVerifyingKey,
        proof: &WrapperProof,
    ) -> Result<bool, WrapperVerifierError> {
        let public_inputs = vec![proof.public_inputs_hash];

        Groth16::<Bls12_381>::verify(&vk.vk, &public_inputs, &proof.groth16_proof)
            .map_err(|e| WrapperVerifierError::Verification(e.to_string()))
    }
}

#[derive(Debug, thiserror::Error)]
pub enum WrapperVerifierError {
    #[error("verification failed: {0}")]
    Verification(String),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::prover::WrapperProver;
    use ark_bls12_381::Fr as BlsFr;

    #[test]
    fn groth16_wrapper_prove_and_verify() {
        // Setup
        let (pk, vk) = WrapperProver::setup().unwrap();

        // Inner proof public inputs (simulated)
        let inner_inputs = vec![
            BlsFr::from(100u64), // merkle_root
            BlsFr::from(200u64), // nullifier_0
            BlsFr::from(300u64), // nullifier_1
            BlsFr::from(400u64), // output_commitment_0
            BlsFr::from(500u64), // output_commitment_1
        ];

        // Prove
        let proof = WrapperProver::prove(&pk, inner_inputs, 0).unwrap();

        // Verify
        let valid = WrapperVerifier::verify(&vk, &proof).unwrap();
        assert!(valid, "Wrapper proof should be valid");
    }
}
