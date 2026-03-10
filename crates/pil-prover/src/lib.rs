//! # pil-prover
//!
//! ZK proof generation for PIL. Handles proving key setup and proof creation
//! for transfer, withdraw, and wealth proof circuits.
//!
//! Supports both synchronous and async (tokio::spawn_blocking) proof generation.
//!
//! Note: We use `vesta::Affine` as the commitment curve because
//! `<vesta::Affine as CurveAffine>::Scalar = vesta::Scalar = pallas::Base`,
//! which matches our circuit field (pallas::Base).

use halo2_proofs::{
    plonk::{create_proof, keygen_pk, keygen_vk, ProvingKey, VerifyingKey},
    poly::commitment::Params,
    transcript::{Blake2bWrite, Challenge255},
};
use pasta_curves::{pallas, vesta};
use pil_circuits::{transfer::TransferCircuit, withdraw::WithdrawCircuit};
use rand::rngs::OsRng;

/// Proving keys for all PIL circuit types.
pub struct ProvingKeys {
    pub transfer_pk: ProvingKey<vesta::Affine>,
    pub transfer_vk: VerifyingKey<vesta::Affine>,
    pub withdraw_pk: ProvingKey<vesta::Affine>,
    pub withdraw_vk: VerifyingKey<vesta::Affine>,
    pub params_transfer: Params<vesta::Affine>,
    pub params_withdraw: Params<vesta::Affine>,
}

impl ProvingKeys {
    /// Generate all proving keys. This is expensive (~seconds).
    pub fn setup() -> Result<Self, ProverError> {
        tracing::info!("Generating PIL proving keys...");

        // Transfer circuit setup
        let params_transfer = Params::<vesta::Affine>::new(pil_circuits::transfer::TRANSFER_K);
        let transfer_empty = TransferCircuit::empty();
        let transfer_vk = keygen_vk(&params_transfer, &transfer_empty)
            .map_err(|e| ProverError::Setup(format!("transfer vk: {e}")))?;
        let transfer_pk = keygen_pk(&params_transfer, transfer_vk.clone(), &transfer_empty)
            .map_err(|e| ProverError::Setup(format!("transfer pk: {e}")))?;

        // Withdraw circuit setup
        let params_withdraw = Params::<vesta::Affine>::new(pil_circuits::withdraw::WITHDRAW_K);
        let withdraw_empty = WithdrawCircuit::empty();
        let withdraw_vk = keygen_vk(&params_withdraw, &withdraw_empty)
            .map_err(|e| ProverError::Setup(format!("withdraw vk: {e}")))?;
        let withdraw_pk = keygen_pk(&params_withdraw, withdraw_vk.clone(), &withdraw_empty)
            .map_err(|e| ProverError::Setup(format!("withdraw pk: {e}")))?;

        tracing::info!("PIL proving keys generated successfully");

        Ok(Self {
            transfer_pk,
            transfer_vk,
            withdraw_pk,
            withdraw_vk,
            params_transfer,
            params_withdraw,
        })
    }
}

/// Generate a transfer proof.
pub fn prove_transfer(
    keys: &ProvingKeys,
    circuit: TransferCircuit,
    public_inputs: &[&[pallas::Base]],
) -> Result<Vec<u8>, ProverError> {
    let mut transcript = Blake2bWrite::<_, vesta::Affine, Challenge255<_>>::init(vec![]);

    create_proof(
        &keys.params_transfer,
        &keys.transfer_pk,
        &[circuit],
        &[public_inputs],
        OsRng,
        &mut transcript,
    )
    .map_err(|e| ProverError::ProofGeneration(format!("transfer: {e}")))?;

    Ok(transcript.finalize())
}

/// Generate a withdraw proof.
pub fn prove_withdraw(
    keys: &ProvingKeys,
    circuit: WithdrawCircuit,
    public_inputs: &[&[pallas::Base]],
) -> Result<Vec<u8>, ProverError> {
    let mut transcript = Blake2bWrite::<_, vesta::Affine, Challenge255<_>>::init(vec![]);

    create_proof(
        &keys.params_withdraw,
        &keys.withdraw_pk,
        &[circuit],
        &[public_inputs],
        OsRng,
        &mut transcript,
    )
    .map_err(|e| ProverError::ProofGeneration(format!("withdraw: {e}")))?;

    Ok(transcript.finalize())
}

/// Async proof generation wrapper for non-blocking server contexts.
pub async fn prove_transfer_async(
    keys: std::sync::Arc<ProvingKeys>,
    circuit: TransferCircuit,
    public_inputs: Vec<Vec<pallas::Base>>,
) -> Result<Vec<u8>, ProverError> {
    tokio::task::spawn_blocking(move || {
        let pi_refs: Vec<&[pallas::Base]> = public_inputs.iter().map(|v| v.as_slice()).collect();
        prove_transfer(&keys, circuit, &pi_refs)
    })
    .await
    .map_err(|e| ProverError::ProofGeneration(format!("async join: {e}")))?
}

/// Async withdraw proof generation wrapper.
pub async fn prove_withdraw_async(
    keys: std::sync::Arc<ProvingKeys>,
    circuit: WithdrawCircuit,
    public_inputs: Vec<Vec<pallas::Base>>,
) -> Result<Vec<u8>, ProverError> {
    tokio::task::spawn_blocking(move || {
        let pi_refs: Vec<&[pallas::Base]> = public_inputs.iter().map(|v| v.as_slice()).collect();
        prove_withdraw(&keys, circuit, &pi_refs)
    })
    .await
    .map_err(|e| ProverError::ProofGeneration(format!("async join: {e}")))?
}

#[derive(Debug, thiserror::Error)]
pub enum ProverError {
    #[error("key setup failed: {0}")]
    Setup(String),
    #[error("proof generation failed: {0}")]
    ProofGeneration(String),
}

#[cfg(test)]
mod tests {
    use super::*;
    use pil_circuits::transfer::TransferCircuit;
    use pil_circuits::withdraw::WithdrawCircuit;

    /// Proving key setup + proof generation is expensive in debug mode (~30s+).
    /// These tests are ignored by default but run in release mode CI.
    #[test]
    #[ignore]
    fn proving_keys_setup_succeeds() {
        let keys = ProvingKeys::setup();
        assert!(
            keys.is_ok(),
            "ProvingKeys::setup() failed: {:?}",
            keys.err()
        );
    }

    #[test]
    #[ignore]
    fn prove_transfer_produces_bytes() {
        let keys = ProvingKeys::setup().unwrap();
        let circuit = TransferCircuit::empty();
        let result = prove_transfer(&keys, circuit, &[&[]]);
        assert!(result.is_ok(), "prove_transfer failed: {:?}", result.err());
        assert!(!result.unwrap().is_empty());
    }

    #[test]
    #[ignore]
    fn prove_withdraw_produces_bytes() {
        let keys = ProvingKeys::setup().unwrap();
        let circuit = WithdrawCircuit::empty();
        let result = prove_withdraw(&keys, circuit, &[&[]]);
        assert!(result.is_ok(), "prove_withdraw failed: {:?}", result.err());
        assert!(!result.unwrap().is_empty());
    }

    #[test]
    fn prover_error_display() {
        let e = ProverError::Setup("test error".into());
        assert_eq!(format!("{e}"), "key setup failed: test error");
        let e = ProverError::ProofGeneration("gen fail".into());
        assert_eq!(format!("{e}"), "proof generation failed: gen fail");
    }
}
