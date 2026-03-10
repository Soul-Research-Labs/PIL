//! # pil-verifier
//!
//! ZK proof verification for PIL. Verifies transfer and withdraw proofs
//! using the IPA commitment scheme (no trusted setup).
//!
//! Uses `vesta::Affine` as commitment curve (matching the prover).

use halo2_proofs::{
    plonk::{self, verify_proof, SingleVerifier, VerifyingKey},
    poly::commitment::Params,
    transcript::{Blake2bRead, Challenge255},
};
use pasta_curves::{pallas, vesta};

/// Verify a transfer proof.
pub fn verify_transfer(
    params: &Params<vesta::Affine>,
    vk: &VerifyingKey<vesta::Affine>,
    proof_bytes: &[u8],
    public_inputs: &[&[pallas::Base]],
) -> Result<(), VerifierError> {
    let strategy = SingleVerifier::new(params);
    let mut transcript =
        Blake2bRead::<_, vesta::Affine, Challenge255<_>>::init(proof_bytes);

    verify_proof(
        params,
        vk,
        strategy,
        &[public_inputs],
        &mut transcript,
    )
    .map_err(|e| VerifierError::InvalidProof(format!("transfer: {e}")))?;

    Ok(())
}

/// Verify a withdraw proof.
pub fn verify_withdraw(
    params: &Params<vesta::Affine>,
    vk: &VerifyingKey<vesta::Affine>,
    proof_bytes: &[u8],
    public_inputs: &[&[pallas::Base]],
) -> Result<(), VerifierError> {
    let strategy = SingleVerifier::new(params);
    let mut transcript =
        Blake2bRead::<_, vesta::Affine, Challenge255<_>>::init(proof_bytes);

    verify_proof(
        params,
        vk,
        strategy,
        &[public_inputs],
        &mut transcript,
    )
    .map_err(|e| VerifierError::InvalidProof(format!("withdraw: {e}")))?;

    Ok(())
}

/// Batch-verify multiple proofs (amortized cost per proof is lower).
pub fn batch_verify(
    params: &Params<vesta::Affine>,
    vk: &VerifyingKey<vesta::Affine>,
    proofs: &[(Vec<u8>, Vec<Vec<pallas::Base>>)],
) -> Result<(), VerifierError> {
    for (i, (proof_bytes, pi)) in proofs.iter().enumerate() {
        let pi_refs: Vec<&[pallas::Base]> = pi.iter().map(|v| v.as_slice()).collect();
        let strategy = SingleVerifier::new(params);
        let mut transcript =
            Blake2bRead::<_, vesta::Affine, Challenge255<_>>::init(proof_bytes.as_slice());

        verify_proof(
            params,
            vk,
            strategy,
            &[&pi_refs],
            &mut transcript,
        )
        .map_err(|e| VerifierError::InvalidProof(format!("batch[{i}]: {e}")))?;
    }
    Ok(())
}

#[derive(Debug, thiserror::Error)]
pub enum VerifierError {
    #[error("invalid proof: {0}")]
    InvalidProof(String),
}
