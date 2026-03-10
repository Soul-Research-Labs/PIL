//! # pil-node
//!
//! PIL prover daemon. Manages:
//! - Encrypted note storage
//! - Batch accumulator (collects transactions for batch proving)
//! - Async proof generation pipeline

use pil_pool::PrivacyPool;
use pil_prover::ProvingKeys;
use std::sync::Arc;
use tokio::sync::RwLock;

/// The PIL prover node.
pub struct PilNode {
    pub pool: Arc<RwLock<PrivacyPool>>,
    pub proving_keys: Arc<ProvingKeys>,
}

impl PilNode {
    /// Initialize the node (generates proving keys).
    pub fn init() -> Result<Self, NodeError> {
        tracing::info!("Initializing PIL node (generating proving keys)...");
        let keys = ProvingKeys::setup().map_err(|e| NodeError::Init(e.to_string()))?;
        tracing::info!("PIL node ready.");

        Ok(Self {
            pool: Arc::new(RwLock::new(PrivacyPool::new())),
            proving_keys: Arc::new(keys),
        })
    }
}

#[derive(Debug, thiserror::Error)]
pub enum NodeError {
    #[error("initialization failed: {0}")]
    Init(String),
    #[error("proof generation failed: {0}")]
    Prove(String),
}
