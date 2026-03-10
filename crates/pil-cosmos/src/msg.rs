//! CosmWasm contract message types for the PIL privacy pool.
//!
//! These types define the API for the on-chain CosmWasm contract.
//! Generate the schema with `cargo schema` for client integration.

use serde::{Deserialize, Serialize};

/// Instantiation message: sets up the privacy pool on a Cosmos chain.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InstantiateMsg {
    /// Chain ID for domain-separated nullifiers.
    pub chain_domain_id: u32,
    /// Application ID for domain separation.
    pub app_id: u32,
    /// Admin address (for epoch finalization and governance).
    pub admin: String,
    /// Epoch duration in seconds (default: 3600).
    pub epoch_duration_secs: u64,
    /// IBC channel for cross-chain epoch sync (optional).
    pub ibc_epoch_channel: Option<String>,
}

/// Execute messages: operations on the privacy pool.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExecuteMsg {
    /// Deposit tokens into the shielded pool.
    Deposit {
        /// Note commitment (hex-encoded 32 bytes).
        commitment: String,
    },

    /// Private transfer within the shielded pool.
    Transfer {
        /// ZK proof bytes (hex-encoded).
        proof: String,
        /// Merkle root the proof was generated against.
        merkle_root: String,
        /// Nullifiers being spent (hex-encoded).
        nullifiers: Vec<String>,
        /// New note commitments (hex-encoded).
        output_commitments: Vec<String>,
        /// Domain chain ID for cross-chain nullifiers.
        domain_chain_id: u32,
        /// Domain app ID.
        domain_app_id: u32,
    },

    /// Withdraw tokens from the shielded pool to a public address.
    Withdraw {
        /// ZK proof bytes (hex-encoded).
        proof: String,
        /// Merkle root.
        merkle_root: String,
        /// Nullifiers being spent.
        nullifiers: Vec<String>,
        /// Change commitments (remaining value stays shielded).
        change_commitments: Vec<String>,
        /// Value to withdraw (in base denomination).
        exit_amount: u128,
        /// Recipient address (bech32).
        recipient: String,
    },

    /// Finalize the current epoch (admin only).
    FinalizeEpoch {},

    /// Publish epoch root to another chain via IBC.
    PublishEpochRootIBC {
        /// Target IBC channel.
        channel_id: String,
        /// Epoch number to publish.
        epoch: u64,
    },

    /// Receive epoch root from another chain via IBC.
    ReceiveEpochRoot {
        /// Source chain domain ID.
        source_chain_id: u32,
        /// Epoch number.
        epoch: u64,
        /// Nullifier Merkle root for the epoch.
        nullifier_root: String,
    },
}

/// Query messages: read-only operations on the privacy pool.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum QueryMsg {
    /// Get pool status.
    Status {},
    /// Get current Merkle root.
    MerkleRoot {},
    /// Check if a nullifier has been spent.
    NullifierSpent { nullifier: String },
    /// Get epoch roots (for cross-chain verification).
    EpochRoots { from_epoch: Option<u64>, limit: Option<u32> },
    /// Get remote epoch roots received via IBC.
    RemoteEpochRoots { chain_id: u32 },
    /// Get pool configuration.
    Config {},
}

/// Status response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StatusResponse {
    pub merkle_root: String,
    pub note_count: u64,
    pub pool_balance: u128,
    pub current_epoch: u64,
    pub nullifier_count: u64,
    pub chain_domain_id: u32,
}

/// Epoch roots response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EpochRootsResponse {
    pub epochs: Vec<EpochEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EpochEntry {
    pub epoch: u64,
    pub nullifier_root: String,
    pub finalized_at: u64, // block height
}
