//! # pil-hydra
//!
//! Cardano Hydra L2 head management for PIL privacy pools.
//!
//! Hydra is Cardano's isomorphic Layer 2 scaling protocol. It enables
//! high-throughput private transfers by running a privacy pool inside
//! a Hydra head with sub-second finality, then committing periodic
//! state snapshots to L1.
//!
//! ## Architecture
//!
//! ```text
//! ┌──────────────────────────────────────┐
//! │           Hydra Head                 │
//! │  ┌──────────┐   ┌────────────────┐   │
//! │  │ Privacy  │   │  State Channel │   │
//! │  │ Pool     │──►│  Snapshots     │   │
//! │  │ (L2)     │   │  (every N txs) │   │
//! │  └──────────┘   └───────┬────────┘   │
//! │                         │            │
//! └─────────────────────────┼────────────┘
//!                           │ commit
//!                    ┌──────▼──────┐
//!                    │ Cardano L1  │
//!                    │ Privacy Pool│
//!                    │ (epoch root)│
//!                    └─────────────┘
//! ```
//!
//! ## Key Design Points
//!
//! - **Isomorphic**: Same eUTXO model in L2 as L1 — validators run unchanged
//! - **Snapshot frequency**: Configurable (every N transactions or T seconds)
//! - **Fanout**: On head close, all L2 UTXOs settle back to L1
//! - **Multi-party**: Heads support multiple participants jointly managing a pool

pub mod head;
pub mod snapshot;
pub mod state;
pub mod sync;

pub use head::{HydraHead, HydraHeadConfig, HydraHeadState};
pub use snapshot::{Snapshot, SnapshotPolicy};
pub use state::HydraPoolState;
pub use sync::L1SyncState;
