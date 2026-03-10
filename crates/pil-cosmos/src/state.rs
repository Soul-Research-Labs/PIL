//! CosmWasm contract state storage.

use serde::{Deserialize, Serialize};

/// Privacy pool configuration (stored once at instantiation).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PoolConfig {
    pub chain_domain_id: u32,
    pub app_id: u32,
    pub admin: String,
    pub epoch_duration_secs: u64,
    pub ibc_epoch_channel: Option<String>,
}

/// Pool state (updated on every deposit/transfer/withdraw).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PoolState {
    /// Serialized Merkle root (32 bytes hex).
    pub merkle_root: String,
    /// Total note commitments.
    pub note_count: u64,
    /// Current epoch.
    pub current_epoch: u64,
    /// Pool balance in base denomination.
    pub pool_balance: u128,
    /// Total nullifiers spent.
    pub nullifier_count: u64,
}

impl Default for PoolState {
    fn default() -> Self {
        Self {
            merkle_root: "0".repeat(64),
            note_count: 0,
            current_epoch: 0,
            pool_balance: 0,
            nullifier_count: 0,
        }
    }
}

/// Epoch record (stored per finalized epoch).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EpochRecord {
    pub epoch: u64,
    pub nullifier_root: String,
    pub finalized_at_height: u64,
    pub nullifier_count: u64,
}

/// Remote epoch root received from another chain via IBC.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RemoteEpochRoot {
    pub source_chain_id: u32,
    pub epoch: u64,
    pub nullifier_root: String,
    pub received_at_height: u64,
}

// In a real CosmWasm contract, these would use cw-storage-plus:
// pub const CONFIG: Item<PoolConfig> = Item::new("config");
// pub const STATE: Item<PoolState> = Item::new("state");
// pub const NULLIFIERS: Map<&[u8], bool> = Map::new("nullifiers");
// pub const EPOCHS: Map<u64, EpochRecord> = Map::new("epochs");
// pub const REMOTE_EPOCHS: Map<(u32, u64), RemoteEpochRoot> = Map::new("remote_epochs");
// pub const COMMITMENTS: Map<u64, String> = Map::new("commitments");
