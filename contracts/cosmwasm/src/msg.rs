use cosmwasm_schema::cw_serde;
use cosmwasm_std::Uint128;

/// Message sent to initialize the privacy pool contract.
#[cw_serde]
pub struct InstantiateMsg {
    /// Chain domain ID for cross-chain nullifier isolation.
    pub chain_domain_id: u32,
    /// Application domain ID.
    pub app_id: u32,
    /// Epoch duration in seconds (default: 3600).
    pub epoch_duration_secs: u64,
    /// Optional IBC channel for epoch root sync.
    pub ibc_epoch_channel: Option<String>,
    /// Native token denomination for the pool (e.g. "uatom", "uosmo").
    pub denom: String,
    /// Committee verifier addresses (hex-encoded ed25519 pubkeys).
    /// These verify Groth16 proofs off-chain and provide attestations.
    #[serde(default)]
    pub proof_verifier_committee: Vec<String>,
    /// Minimum number of committee attestations required.
    #[serde(default = "default_committee_threshold")]
    pub committee_threshold: u32,
}

fn default_committee_threshold() -> u32 {
    1
}

/// Execute messages — state-modifying operations on the privacy pool.
#[cw_serde]
pub enum ExecuteMsg {
    /// Deposit funds into the shielded pool.
    /// Must send native tokens with the message (info.funds).
    Deposit {
        /// Hex-encoded note commitment (32 bytes = 64 hex chars).
        commitment: String,
    },
    /// Private transfer within the shielded pool.
    Transfer {
        /// Hex-encoded ZK proof bytes (Groth16 BLS12-381).
        proof: String,
        /// Hex-encoded expected Merkle root (must match current state).
        merkle_root: String,
        /// Hex-encoded nullifiers for spent notes.
        nullifiers: Vec<String>,
        /// Hex-encoded commitments for new output notes.
        output_commitments: Vec<String>,
        /// Hex-encoded public inputs (32-byte scalars).
        public_inputs: Vec<String>,
        /// Committee attestations: each is a hex-encoded signature over
        /// SHA-256(proof || public_inputs || merkle_root).
        attestations: Vec<ProofAttestation>,
        /// Chain domain for nullifier derivation.
        domain_chain_id: u32,
        /// App domain for nullifier derivation.
        domain_app_id: u32,
    },
    /// Withdraw funds from the shielded pool to a public address.
    Withdraw {
        /// Hex-encoded ZK proof bytes (Groth16 BLS12-381).
        proof: String,
        /// Hex-encoded expected Merkle root.
        merkle_root: String,
        /// Hex-encoded nullifiers for spent notes.
        nullifiers: Vec<String>,
        /// Hex-encoded commitments for change notes.
        change_commitments: Vec<String>,
        /// Hex-encoded public inputs (32-byte scalars).
        public_inputs: Vec<String>,
        /// Committee attestations over the proof.
        attestations: Vec<ProofAttestation>,
        /// Amount to withdraw (in smallest denomination).
        exit_amount: Uint128,
        /// Recipient bech32 address.
        recipient: String,
    },
    /// Admin-only: finalize the current epoch.
    FinalizeEpoch {},
    /// Publish the current epoch root to a remote chain via IBC.
    PublishEpochRootIbc {
        /// IBC channel ID (e.g., "channel-42").
        channel_id: String,
    },
    /// Receive an epoch root from a remote chain (called by IBC module).
    ReceiveEpochRoot {
        /// Source chain domain ID.
        source_chain_id: u32,
        /// Epoch number.
        epoch: u64,
        /// Hex-encoded nullifier Merkle root.
        nullifier_root: String,
    },
}

/// Query messages — read-only state queries.
#[cw_serde]
#[derive(cosmwasm_schema::QueryResponses)]
pub enum QueryMsg {
    /// Get pool status.
    #[returns(StatusResponse)]
    Status {},
    /// Get the Merkle root for a specific epoch.
    #[returns(EpochRootResponse)]
    EpochRoot { epoch: u64 },
    /// Check if a nullifier has been spent.
    #[returns(NullifierStatusResponse)]
    NullifierStatus { nullifier: String },
    /// Get pool configuration.
    #[returns(ConfigResponse)]
    Config {},
}

#[cw_serde]
pub struct StatusResponse {
    pub merkle_root: String,
    pub note_count: u64,
    pub pool_balance: Uint128,
    pub current_epoch: u64,
    pub nullifier_count: u64,
    pub chain_domain_id: u32,
}

#[cw_serde]
pub struct EpochRootResponse {
    pub epoch: u64,
    pub nullifier_root: Option<String>,
}

#[cw_serde]
pub struct NullifierStatusResponse {
    pub nullifier: String,
    pub spent: bool,
    pub epoch: Option<u64>,
}

#[cw_serde]
pub struct ConfigResponse {
    pub admin: String,
    pub chain_domain_id: u32,
    pub app_id: u32,
    pub epoch_duration_secs: u64,
    pub ibc_epoch_channel: Option<String>,
    pub denom: String,
}

/// Committee attestation over a proof hash.
/// Each committee member signs SHA-256(proof || concatenated_public_inputs || merkle_root)
/// using their ed25519 key registered at instantiation.
#[cw_serde]
pub struct ProofAttestation {
    /// Hex-encoded ed25519 public key of the attester.
    pub pubkey: String,
    /// Hex-encoded ed25519 signature (64 bytes).
    pub signature: String,
}
