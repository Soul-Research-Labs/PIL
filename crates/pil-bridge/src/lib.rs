//! # pil-bridge
//!
//! Cross-chain bridge adapter for PIL.
//!
//! Handles epoch root synchronization between Cardano and Cosmos chains.
//! Uses light client proofs for trustless verification:
//!
//! - **Cardano → Cosmos**: Mithril light client proofs verify Cardano state
//!   on Cosmos chains. Epoch roots from Cardano's privacy pool are submitted
//!   to Cosmos via IBC after Mithril verification.
//!
//! - **Cosmos → Cardano**: IBC light client state is relayed to Cardano
//!   via reference inputs. Cardano validators verify Tendermint/CometBFT
//!   consensus signatures for Cosmos epoch roots.
//!
//! ## Bridge Architecture
//!
//! ```text
//! ┌─────────────────┐         ┌──────────────────┐
//! │   Cardano L1     │         │   Cosmos Chain    │
//! │                  │         │                   │
//! │  PIL Pool        │         │  PIL Pool         │
//! │  (Aiken)         │         │  (CosmWasm)       │
//! │                  │         │                   │
//! │  Epoch Roots ──┐ │         │ ┌── Epoch Roots   │
//! └────────────────┼─┘         └─┼─────────────────┘
//!                  │             │
//!          ┌───────▼─────────────▼───────┐
//!          │     PIL Bridge Relayer       │
//!          │                              │
//!          │  • Mithril proof fetcher     │
//!          │  • IBC packet constructor    │
//!          │  • Cardano tx submitter      │
//!          │  • Cosmos tx submitter       │
//!          │  • Epoch root aggregator     │
//!          └─────────────────────────────┘
//! ```

pub mod relayer;

pub use relayer::BridgeRelayer;

use pil_primitives::domain::ChainDomain;
use serde::{Deserialize, Serialize};

/// A cross-chain epoch root attestation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EpochAttestation {
    /// Source chain where the epoch was finalized.
    pub source_chain: ChainDomain,
    /// Epoch number.
    pub epoch: u64,
    /// Nullifier Merkle root.
    pub nullifier_root: [u8; 32],
    /// Light client proof (chain-specific format).
    pub proof: Vec<u8>,
    /// Timestamp of attestation.
    pub timestamp: u64,
}

/// Bridge configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BridgeConfig {
    /// Cardano node endpoint.
    pub cardano_endpoint: String,
    /// Cosmos RPC endpoint.
    pub cosmos_endpoint: String,
    /// Mithril aggregator endpoint.
    pub mithril_endpoint: Option<String>,
    /// Polling interval for new epochs (seconds).
    pub poll_interval_secs: u64,
    /// Chains to relay between.
    pub relay_pairs: Vec<(ChainDomain, ChainDomain)>,
}
