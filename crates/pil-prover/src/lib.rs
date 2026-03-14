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
use pil_circuits::{
    transfer::TransferCircuit,
    wealth::WealthProofCircuit,
    withdraw::WithdrawCircuit,
};
use rand::rngs::OsRng;

/// Proving keys for all PIL circuit types.
pub struct ProvingKeys {
    pub transfer_pk: ProvingKey<vesta::Affine>,
    pub transfer_vk: VerifyingKey<vesta::Affine>,
    pub withdraw_pk: ProvingKey<vesta::Affine>,
    pub withdraw_vk: VerifyingKey<vesta::Affine>,
    pub wealth_pk: ProvingKey<vesta::Affine>,
    pub wealth_vk: VerifyingKey<vesta::Affine>,
    pub params_transfer: Params<vesta::Affine>,
    pub params_withdraw: Params<vesta::Affine>,
    pub params_wealth: Params<vesta::Affine>,
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

        // Wealth proof circuit setup
        let params_wealth = Params::<vesta::Affine>::new(pil_circuits::wealth::WEALTH_K);
        let wealth_empty = WealthProofCircuit::empty(pil_circuits::wealth::MAX_WEALTH_NOTES);
        let wealth_vk = keygen_vk(&params_wealth, &wealth_empty)
            .map_err(|e| ProverError::Setup(format!("wealth vk: {e}")))?;
        let wealth_pk = keygen_pk(&params_wealth, wealth_vk.clone(), &wealth_empty)
            .map_err(|e| ProverError::Setup(format!("wealth pk: {e}")))?;

        tracing::info!("PIL proving keys generated successfully");

        Ok(Self {
            transfer_pk,
            transfer_vk,
            withdraw_pk,
            withdraw_vk,
            wealth_pk,
            wealth_vk,
            params_transfer,
            params_withdraw,
            params_wealth,
        })
    }

    /// Save the IPA Params to a directory.
    ///
    /// Writes `transfer_params.bin` and `withdraw_params.bin`.
    /// PK/VK are not serialized because halo2_proofs 0.3 doesn't support it;
    /// they are regenerated from params on load (which is fast since the
    /// expensive random point generation is already done in the params).
    pub fn save_params(&self, dir: &std::path::Path) -> Result<(), ProverError> {
        std::fs::create_dir_all(dir).map_err(|e| ProverError::Io(format!("create dir: {e}")))?;

        let transfer_path = dir.join("transfer_params.bin");
        let mut f = std::fs::File::create(&transfer_path)
            .map_err(|e| ProverError::Io(format!("create {}: {e}", transfer_path.display())))?;
        self.params_transfer
            .write(&mut f)
            .map_err(|e| ProverError::Io(format!("write transfer params: {e}")))?;

        let withdraw_path = dir.join("withdraw_params.bin");
        let mut f = std::fs::File::create(&withdraw_path)
            .map_err(|e| ProverError::Io(format!("create {}: {e}", withdraw_path.display())))?;
        self.params_withdraw
            .write(&mut f)
            .map_err(|e| ProverError::Io(format!("write withdraw params: {e}")))?;

        let wealth_path = dir.join("wealth_params.bin");
        let mut f = std::fs::File::create(&wealth_path)
            .map_err(|e| ProverError::Io(format!("create {}: {e}", wealth_path.display())))?;
        self.params_wealth
            .write(&mut f)
            .map_err(|e| ProverError::Io(format!("write wealth params: {e}")))?;

        tracing::info!("Saved params to {}", dir.display());
        Ok(())
    }

    /// Load params from a directory and regenerate PK/VK.
    ///
    /// Reads `transfer_params.bin`, `withdraw_params.bin`, and `wealth_params.bin`,
    /// then runs keygen (deterministic from params) to recover PK/VK.
    pub fn load_params(dir: &std::path::Path) -> Result<Self, ProverError> {
        let transfer_path = dir.join("transfer_params.bin");
        let mut f = std::fs::File::open(&transfer_path)
            .map_err(|e| ProverError::Io(format!("open {}: {e}", transfer_path.display())))?;
        let params_transfer = Params::<vesta::Affine>::read(&mut f)
            .map_err(|e| ProverError::Io(format!("read transfer params: {e}")))?;

        let withdraw_path = dir.join("withdraw_params.bin");
        let mut f = std::fs::File::open(&withdraw_path)
            .map_err(|e| ProverError::Io(format!("open {}: {e}", withdraw_path.display())))?;
        let params_withdraw = Params::<vesta::Affine>::read(&mut f)
            .map_err(|e| ProverError::Io(format!("read withdraw params: {e}")))?;

        let wealth_path = dir.join("wealth_params.bin");
        let mut f = std::fs::File::open(&wealth_path)
            .map_err(|e| ProverError::Io(format!("open {}: {e}", wealth_path.display())))?;
        let params_wealth = Params::<vesta::Affine>::read(&mut f)
            .map_err(|e| ProverError::Io(format!("read wealth params: {e}")))?;

        Self::from_params(params_transfer, params_withdraw, params_wealth)
    }

    /// Regenerate PK/VK from pre-existing Params.
    fn from_params(
        params_transfer: Params<vesta::Affine>,
        params_withdraw: Params<vesta::Affine>,
        params_wealth: Params<vesta::Affine>,
    ) -> Result<Self, ProverError> {
        tracing::info!("Regenerating PK/VK from loaded params...");

        let transfer_empty = TransferCircuit::empty();
        let transfer_vk = keygen_vk(&params_transfer, &transfer_empty)
            .map_err(|e| ProverError::Setup(format!("transfer vk: {e}")))?;
        let transfer_pk = keygen_pk(&params_transfer, transfer_vk.clone(), &transfer_empty)
            .map_err(|e| ProverError::Setup(format!("transfer pk: {e}")))?;

        let withdraw_empty = WithdrawCircuit::empty();
        let withdraw_vk = keygen_vk(&params_withdraw, &withdraw_empty)
            .map_err(|e| ProverError::Setup(format!("withdraw vk: {e}")))?;
        let withdraw_pk = keygen_pk(&params_withdraw, withdraw_vk.clone(), &withdraw_empty)
            .map_err(|e| ProverError::Setup(format!("withdraw pk: {e}")))?;

        let wealth_empty = WealthProofCircuit::empty(pil_circuits::wealth::MAX_WEALTH_NOTES);
        let wealth_vk = keygen_vk(&params_wealth, &wealth_empty)
            .map_err(|e| ProverError::Setup(format!("wealth vk: {e}")))?;
        let wealth_pk = keygen_pk(&params_wealth, wealth_vk.clone(), &wealth_empty)
            .map_err(|e| ProverError::Setup(format!("wealth pk: {e}")))?;

        tracing::info!("PK/VK regenerated from params");

        Ok(Self {
            transfer_pk,
            transfer_vk,
            withdraw_pk,
            withdraw_vk,
            wealth_pk,
            wealth_vk,
            params_transfer,
            params_withdraw,
            params_wealth,
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

/// Generate a wealth proof.
pub fn prove_wealth(
    keys: &ProvingKeys,
    circuit: WealthProofCircuit,
    public_inputs: &[&[pallas::Base]],
) -> Result<Vec<u8>, ProverError> {
    let mut transcript = Blake2bWrite::<_, vesta::Affine, Challenge255<_>>::init(vec![]);

    create_proof(
        &keys.params_wealth,
        &keys.wealth_pk,
        &[circuit],
        &[public_inputs],
        OsRng,
        &mut transcript,
    )
    .map_err(|e| ProverError::ProofGeneration(format!("wealth: {e}")))?;

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

/// Async wealth proof generation wrapper.
pub async fn prove_wealth_async(
    keys: std::sync::Arc<ProvingKeys>,
    circuit: WealthProofCircuit,
    public_inputs: Vec<Vec<pallas::Base>>,
) -> Result<Vec<u8>, ProverError> {
    tokio::task::spawn_blocking(move || {
        let pi_refs: Vec<&[pallas::Base]> = public_inputs.iter().map(|v| v.as_slice()).collect();
        prove_wealth(&keys, circuit, &pi_refs)
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
    #[error("I/O error: {0}")]
    Io(String),
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
        let e = ProverError::Io("disk full".into());
        assert_eq!(format!("{e}"), "I/O error: disk full");
    }

    #[test]
    fn params_save_load_roundtrip() {
        let keys = ProvingKeys::setup().unwrap();
        let dir = std::env::temp_dir().join("pil_prover_test_params");
        let _ = std::fs::remove_dir_all(&dir);

        keys.save_params(&dir).unwrap();
        assert!(dir.join("transfer_params.bin").exists());
        assert!(dir.join("withdraw_params.bin").exists());
        assert!(dir.join("wealth_params.bin").exists());

        // Verify we can load params and regenerate PK/VK without error
        let _loaded = ProvingKeys::load_params(&dir).unwrap();

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn load_params_missing_dir_returns_error() {
        let result = ProvingKeys::load_params(std::path::Path::new("/nonexistent/path"));
        assert!(result.is_err());
    }
}
