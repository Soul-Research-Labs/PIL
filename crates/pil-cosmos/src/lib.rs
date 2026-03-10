//! # pil-cosmos
//!
//! Cosmos ecosystem adapter for the Privacy Interoperability Layer.
//!
//! ## Architecture
//!
//! The Cosmos adapter leverages CosmWasm smart contracts and IBC for cross-chain
//! privacy operations:
//!
//! ### On-chain (CosmWasm contracts)
//! - **PrivacyPoolContract**: Manages the shielded pool state (Merkle tree, nullifiers)
//! - **NullifierRegistryContract**: Tracks spent nullifiers with epoch partitioning
//! - **IBCRelayContract**: Handles cross-chain epoch root synchronization via IBC
//! - **ComplianceContract**: Optional compliance hooks for regulated environments
//!
//! ### Cross-chain via IBC
//! - Epoch nullifier roots are published to other Cosmos chains via IBC packets
//! - Chains can verify that a nullifier was spent on another chain by checking
//!   the epoch root against their local IBC light client
//! - Native IBC channels between Cosmos chains (no external bridges needed)
//!
//! ### Compatible Cosmos Chains
//! - **Osmosis**: DEX privacy (shielded swaps)
//! - **Neutron**: Cross-chain DeFi privacy via Interchain Queries + Accounts
//! - **Injective**: High-frequency shielded trading
//! - **Secret Network**: Complementary to Secret's native privacy (different approach)
//! - **Archway**: dApp-specific privacy pools with developer rewards
//! - **Sei**: Parallel execution for high-throughput privacy transfers
//! - **Celestia**: Data availability layer for proof publishing
//! - **Dymension**: RollApp privacy modules
//!
//! ### Cosmos-specific Advantages
//! 1. **Native IBC**: No bridges required between Cosmos chains — privacy pool
//!    epoch roots propagate natively via IBC packets
//! 2. **CosmWasm + Rust**: The privacy pool logic is written in Rust, same as
//!    the PIL core — minimal translation layer
//! 3. **Interchain Accounts**: Can control privacy pool contracts on remote
//!    chains from a single key
//! 4. **Interchain Queries**: Can read privacy pool state from other chains
//!    without trust assumptions

pub mod contract;
pub mod ibc;
pub mod msg;
pub mod state;

pub use contract::CosmosPrivacyPool;
pub use ibc::IBCEpochSync;
pub use msg::{ExecuteMsg, InstantiateMsg, QueryMsg};
