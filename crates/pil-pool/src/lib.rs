//! # pil-pool
//!
//! Privacy pool state machine: manages note commitments, nullifier registry,
//! epoch partitioning, and compliance hooks.
//!
//! This is the core on-chain logic that gets adapted for each target chain
//! (Cardano validators, CosmWasm contracts, etc.).

pub mod epoch;
pub mod nullifier_set;
pub mod pool;

pub use epoch::EpochManager;
pub use nullifier_set::NullifierSet;
pub use pool::PrivacyPool;
