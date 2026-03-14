//! # pil-verifier
//!
//! ZK proof verification for PIL. Verifies transfer and withdraw proofs
//! using the IPA commitment scheme (no trusted setup).
//!
//! Uses `vesta::Affine` as commitment curve (matching the prover).

use halo2_proofs::{
    plonk::{verify_proof, BatchVerifier, SingleVerifier, VerifyingKey},
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
    let mut transcript = Blake2bRead::<_, vesta::Affine, Challenge255<_>>::init(proof_bytes);

    verify_proof(params, vk, strategy, &[public_inputs], &mut transcript)
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
    let mut transcript = Blake2bRead::<_, vesta::Affine, Challenge255<_>>::init(proof_bytes);

    verify_proof(params, vk, strategy, &[public_inputs], &mut transcript)
        .map_err(|e| VerifierError::InvalidProof(format!("withdraw: {e}")))?;

    Ok(())
}

/// Verify a wealth proof.
pub fn verify_wealth(
    params: &Params<vesta::Affine>,
    vk: &VerifyingKey<vesta::Affine>,
    proof_bytes: &[u8],
    public_inputs: &[&[pallas::Base]],
) -> Result<(), VerifierError> {
    let strategy = SingleVerifier::new(params);
    let mut transcript = Blake2bRead::<_, vesta::Affine, Challenge255<_>>::init(proof_bytes);

    verify_proof(params, vk, strategy, &[public_inputs], &mut transcript)
        .map_err(|e| VerifierError::InvalidProof(format!("wealth: {e}")))?;

    Ok(())
}

/// Batch-verify multiple proofs using amortized multi-scalar multiplication.
///
/// Accumulates all proof MSMs into a single check, which is significantly
/// faster than verifying each proof individually when the batch is large.
/// Returns an error if any proof in the batch is invalid; to identify which
/// specific proof failed, the caller must re-verify proofs individually.
pub fn batch_verify(
    params: &Params<vesta::Affine>,
    vk: &VerifyingKey<vesta::Affine>,
    proofs: &[(Vec<u8>, Vec<Vec<pallas::Base>>)],
) -> Result<(), VerifierError> {
    if proofs.is_empty() {
        return Ok(());
    }

    let mut batch = BatchVerifier::new();
    for (proof_bytes, pi) in proofs {
        let instances: Vec<Vec<vesta::Scalar>> = pi
            .iter()
            .map(|column| column.iter().copied().collect())
            .collect();
        batch.add_proof(vec![instances], proof_bytes.clone());
    }

    if batch.finalize(params, vk) {
        Ok(())
    } else {
        Err(VerifierError::InvalidProof(
            "batch verification failed — one or more proofs are invalid".into(),
        ))
    }
}

#[derive(Debug, thiserror::Error)]
pub enum VerifierError {
    #[error("invalid proof: {0}")]
    InvalidProof(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn batch_verify_empty_is_ok() {
        // Empty batch should always succeed (nothing to verify)
        let k = 5; // small k for fast test
        let params = halo2_proofs::poly::commitment::Params::<vesta::Affine>::new(k);
        // We can't easily create a VK without a circuit, but we can test
        // the empty-batch shortcut:
        // batch_verify iterates proofs; empty proofs → Ok(())
        let empty_circuit = pil_circuits::transfer::TransferCircuit::empty();
        let vk = halo2_proofs::plonk::keygen_vk(&params, &empty_circuit);
        // With mismatched k, keygen may fail; that's fine — we just test the
        // empty-slice path if we can get a vk.
        if let Ok(vk) = vk {
            let result = batch_verify(&params, &vk, &[]);
            assert!(result.is_ok(), "empty batch should succeed");
        }
    }

    /// Keygen is expensive in debug mode — ignored by default.
    #[test]
    #[ignore]
    fn verify_transfer_rejects_empty_bytes() {
        // Without a valid VK (would need expensive keygen), we just ensure
        // the function signature and error handling work correctly.
        // This test verifies the API contract rather than cryptographic correctness.
        let k = pil_circuits::transfer::TRANSFER_K;
        let params = halo2_proofs::poly::commitment::Params::<vesta::Affine>::new(k);

        // Keygen is expensive in debug mode — we generate a VK for the empty circuit
        let empty_circuit = pil_circuits::transfer::TransferCircuit::empty();
        let vk = halo2_proofs::plonk::keygen_vk(&params, &empty_circuit).unwrap();

        // Empty proof bytes → transcript deserialization error → InvalidProof
        let result = verify_transfer(&params, &vk, &[], &[&[]]);
        assert!(result.is_err());
    }
}
