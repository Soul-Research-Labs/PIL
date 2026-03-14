use cosmwasm_schema::cw_serde;
use cosmwasm_std::{Addr, Uint128};
use cw_storage_plus::{Item, Map};

/// Pool configuration — set once at instantiation.
#[cw_serde]
pub struct Config {
    pub admin: Addr,
    pub chain_domain_id: u32,
    pub app_id: u32,
    pub epoch_duration_secs: u64,
    pub ibc_epoch_channel: Option<String>,
    pub denom: String,
    /// Hex-encoded ed25519 pubkeys of committee members that verify Groth16
    /// proofs off-chain and provide attestations on-chain.
    pub proof_verifier_committee: Vec<String>,
    /// Minimum number of valid attestations required per proof.
    pub committee_threshold: u32,
}

/// Pool runtime state — updated on every operation.
#[cw_serde]
pub struct PoolState {
    /// Hex-encoded current Merkle root.
    pub merkle_root: String,
    /// Total note commitments in the tree.
    pub note_count: u64,
    /// Current epoch number.
    pub current_epoch: u64,
    /// Total pool balance (all assets combined, in native denom).
    pub pool_balance: Uint128,
}

/// Nullifier entry — stored per nullifier hash.
#[cw_serde]
pub struct NullifierEntry {
    pub epoch: u64,
    pub timestamp: u64,
}

/// Finalized epoch root — stored per epoch.
#[cw_serde]
pub struct EpochRoot {
    pub nullifier_root: String,
    pub finalized_at: u64,
    pub note_count_at_finalization: u64,
}

/// Remote epoch root — received from another chain via IBC.
#[cw_serde]
pub struct RemoteEpochRoot {
    pub source_chain_id: u32,
    pub epoch: u64,
    pub nullifier_root: String,
    pub received_at: u64,
}

/// Note commitment — stored in order of insertion.
#[cw_serde]
pub struct NoteCommitment {
    pub commitment: String,
    pub epoch: u64,
}

// ─── Storage Keys ────────────────────────────────────────────────────

pub const CONFIG: Item<Config> = Item::new("config");
pub const POOL_STATE: Item<PoolState> = Item::new("pool_state");

/// Nullifier set: nullifier_hex → NullifierEntry
pub const NULLIFIERS: Map<&str, NullifierEntry> = Map::new("nullifiers");

/// Nullifier count (separate counter for efficient queries).
pub const NULLIFIER_COUNT: Item<u64> = Item::new("nullifier_count");

/// Note commitments: index → NoteCommitment
pub const COMMITMENTS: Map<u64, NoteCommitment> = Map::new("commitments");

/// Epoch roots: epoch_number → EpochRoot
pub const EPOCH_ROOTS: Map<u64, EpochRoot> = Map::new("epoch_roots");

/// Remote epoch roots: (source_chain_id, epoch) → RemoteEpochRoot
pub const REMOTE_EPOCH_ROOTS: Map<(u32, u64), RemoteEpochRoot> =
    Map::new("remote_epoch_roots");
