//! Groth16 proof generation for the wrapper circuit.

use ark_bls12_381::{Bls12_381, Fr as BlsFr};
use ark_groth16::{Groth16, ProvingKey};
use ark_snark::SNARK;
use ark_std::rand::rngs::OsRng;

use crate::circuit::{compute_inputs_hash, WrapperCircuit};

/// Wrapper proving key (BLS12-381 Groth16).
pub struct WrapperProvingKey {
    pub pk: ProvingKey<Bls12_381>,
}

/// Wrapper prover: generates BLS12-381 Groth16 proofs from inner proof public inputs.
pub struct WrapperProver;

impl WrapperProver {
    /// Generate proving and verifying keys (requires a trusted setup).
    /// The circuit is small (~2K constraints).
    pub fn setup(
    ) -> Result<(WrapperProvingKey, crate::verifier::WrapperVerifyingKey), WrapperProverError> {
        let empty_circuit = WrapperCircuit::empty();
        let (pk, vk) = Groth16::<Bls12_381>::circuit_specific_setup(empty_circuit, &mut OsRng)
            .map_err(|e| WrapperProverError::Setup(e.to_string()))?;

        Ok((
            WrapperProvingKey { pk },
            crate::verifier::WrapperVerifyingKey { vk },
        ))
    }

    /// Generate a Groth16 proof wrapping the inner proof's public inputs.
    ///
    /// `inner_public_inputs` are the Halo2 proof's public inputs encoded
    /// as BLS12-381 scalar field elements.
    pub fn prove(
        pk: &WrapperProvingKey,
        inner_public_inputs: Vec<BlsFr>,
        proof_type: u8,
    ) -> Result<WrapperProof, WrapperProverError> {
        let hash = compute_inputs_hash(&inner_public_inputs, proof_type);
        let circuit = WrapperCircuit::new(inner_public_inputs.clone(), hash, proof_type);

        let proof = Groth16::<Bls12_381>::prove(&pk.pk, circuit, &mut OsRng)
            .map_err(|e| WrapperProverError::ProofGeneration(e.to_string()))?;

        Ok(WrapperProof {
            groth16_proof: proof,
            public_inputs_hash: hash,
        })
    }
}

/// A Groth16 wrapper proof.
pub struct WrapperProof {
    /// The Groth16 proof (192 bytes serialised: 2 G1 + 1 G2 points).
    pub groth16_proof: ark_groth16::Proof<Bls12_381>,
    /// Hash of the inner public inputs (the Groth16 proof's public input).
    pub public_inputs_hash: BlsFr,
}

#[derive(Debug, thiserror::Error)]
pub enum WrapperProverError {
    #[error("setup failed: {0}")]
    Setup(String),
    #[error("proof generation failed: {0}")]
    ProofGeneration(String),
}
