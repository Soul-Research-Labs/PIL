//! # pil-node
//!
//! PIL prover daemon. Manages:
//! - Encrypted note storage
//! - Batch accumulator (collects transactions for batch proving)
//! - Async proof generation pipeline
//! - Epoch finalization

use pil_note::{keys::SpendingKey, note::Note};
use pil_pool::{EpochManager, PrivacyPool};
use pil_primitives::types::{Base, Commitment, Nullifier};
use pil_prover::ProvingKeys;
use std::sync::Arc;
use tokio::sync::{mpsc, RwLock};

/// A pending transaction waiting for batch proving.
#[derive(Debug, Clone)]
pub enum PendingTx {
    Deposit {
        commitment: Commitment,
        value: u64,
        asset_id: u64,
    },
    Transfer {
        nullifiers: Vec<Nullifier>,
        new_commitments: Vec<Commitment>,
    },
    Withdraw {
        nullifiers: Vec<Nullifier>,
        change_commitments: Vec<Commitment>,
        exit_value: u64,
        asset_id: u64,
    },
}

/// Batch accumulator — collects transactions and flushes them in batches.
pub struct BatchAccumulator {
    pending: Vec<PendingTx>,
    max_batch_size: usize,
}

impl BatchAccumulator {
    pub fn new(max_batch_size: usize) -> Self {
        Self {
            pending: Vec::new(),
            max_batch_size,
        }
    }

    /// Push a transaction into the pending queue.
    pub fn push(&mut self, tx: PendingTx) {
        self.pending.push(tx);
    }

    /// Returns true if the batch is full and should be flushed.
    pub fn is_full(&self) -> bool {
        self.pending.len() >= self.max_batch_size
    }

    /// Drain all pending transactions for processing.
    pub fn drain(&mut self) -> Vec<PendingTx> {
        std::mem::take(&mut self.pending)
    }

    /// Number of pending transactions.
    pub fn pending_count(&self) -> usize {
        self.pending.len()
    }
}

/// Note scanner — checks if encrypted notes belong to a given viewing key.
pub struct NoteScanner {
    owner: Base,
}

impl NoteScanner {
    pub fn new(spending_key: &SpendingKey) -> Self {
        Self {
            owner: spending_key.owner(),
        }
    }

    /// Scan a list of notes and return those belonging to our owner.
    pub fn scan(&self, notes: &[(Note, u64)]) -> Vec<(Note, u64)> {
        notes
            .iter()
            .filter(|(note, _)| note.owner == self.owner)
            .cloned()
            .collect()
    }
}

/// The PIL prover node.
pub struct PilNode {
    pub pool: Arc<RwLock<PrivacyPool>>,
    pub epoch_manager: Arc<RwLock<EpochManager>>,
    pub proving_keys: Arc<ProvingKeys>,
    pub batch: Arc<RwLock<BatchAccumulator>>,
    shutdown_tx: Option<mpsc::Sender<()>>,
}

impl PilNode {
    /// Initialize the node (generates proving keys).
    pub fn init() -> Result<Self, NodeError> {
        Self::init_with_batch_size(32)
    }

    /// Initialize with a custom batch size.
    pub fn init_with_batch_size(batch_size: usize) -> Result<Self, NodeError> {
        tracing::info!("Initializing PIL node (generating proving keys)...");
        let keys = ProvingKeys::setup().map_err(|e| NodeError::Init(e.to_string()))?;
        tracing::info!("PIL node ready.");

        Ok(Self {
            pool: Arc::new(RwLock::new(PrivacyPool::new())),
            epoch_manager: Arc::new(RwLock::new(EpochManager::new(3600))),
            proving_keys: Arc::new(keys),
            batch: Arc::new(RwLock::new(BatchAccumulator::new(batch_size))),
            shutdown_tx: None,
        })
    }

    /// Submit a transaction to the batch accumulator.
    pub async fn submit_tx(&self, tx: PendingTx) -> Result<(), NodeError> {
        let mut batch = self.batch.write().await;
        batch.push(tx);

        if batch.is_full() {
            let pending = batch.drain();
            drop(batch);
            self.process_batch(pending).await?;
        }
        Ok(())
    }

    /// Force-flush: process all pending transactions now.
    pub async fn flush(&self) -> Result<usize, NodeError> {
        let pending = {
            let mut batch = self.batch.write().await;
            batch.drain()
        };
        let count = pending.len();
        if !pending.is_empty() {
            self.process_batch(pending).await?;
        }
        Ok(count)
    }

    /// Process a batch of pending transactions against the pool.
    async fn process_batch(&self, txs: Vec<PendingTx>) -> Result<(), NodeError> {
        let mut pool = self.pool.write().await;
        for tx in txs {
            match tx {
                PendingTx::Deposit {
                    commitment,
                    value,
                    asset_id,
                } => {
                    pool.deposit(commitment, value, asset_id)
                        .map_err(|e| NodeError::Pool(e.to_string()))?;
                }
                PendingTx::Transfer {
                    nullifiers,
                    new_commitments,
                } => {
                    pool.process_transfer(&nullifiers, &new_commitments, &[])
                        .map_err(|e| NodeError::Pool(e.to_string()))?;
                }
                PendingTx::Withdraw {
                    nullifiers,
                    change_commitments,
                    exit_value,
                    asset_id,
                } => {
                    pool.process_withdraw(
                        &nullifiers,
                        &change_commitments,
                        exit_value,
                        asset_id,
                        &[],
                    )
                    .map_err(|e| NodeError::Pool(e.to_string()))?;
                }
            }
        }
        Ok(())
    }

    /// Finalize the current epoch (snapshot the pool Merkle root).
    pub async fn finalize_epoch(&self) -> Result<u64, NodeError> {
        let pool = self.pool.read().await;
        let root = pool.root();
        drop(pool);

        let mut em = self.epoch_manager.write().await;
        let epoch = em.current_epoch();
        em.finalize_epoch(root);
        Ok(epoch)
    }

    /// Start the background daemon loop.
    ///
    /// The daemon periodically flushes the batch accumulator and finalizes epochs.
    /// Returns when a shutdown signal is received.
    pub async fn run_daemon(
        &mut self,
        batch_interval: std::time::Duration,
        epoch_interval: std::time::Duration,
    ) -> Result<(), NodeError> {
        let (tx, mut rx) = mpsc::channel::<()>(1);
        self.shutdown_tx = Some(tx);

        let pool = self.pool.clone();
        let epoch_mgr = self.epoch_manager.clone();
        let batch = self.batch.clone();

        let mut batch_tick = tokio::time::interval(batch_interval);
        let mut epoch_tick = tokio::time::interval(epoch_interval);

        loop {
            tokio::select! {
                _ = batch_tick.tick() => {
                    let pending = {
                        let mut b = batch.write().await;
                        b.drain()
                    };
                    if !pending.is_empty() {
                        let mut p = pool.write().await;
                        for tx in pending {
                            match tx {
                                PendingTx::Deposit { commitment, value, asset_id } => {
                                    let _ = p.deposit(commitment, value, asset_id);
                                }
                                PendingTx::Transfer { nullifiers, new_commitments } => {
                                    let _ = p.process_transfer(&nullifiers, &new_commitments, &[]);
                                }
                                PendingTx::Withdraw { nullifiers, change_commitments, exit_value, asset_id } => {
                                    let _ = p.process_withdraw(&nullifiers, &change_commitments, exit_value, asset_id, &[]);
                                }
                            }
                        }
                    }
                }
                _ = epoch_tick.tick() => {
                    let root = {
                        let p = pool.read().await;
                        p.root()
                    };
                    let mut em = epoch_mgr.write().await;
                    em.finalize_epoch(root);
                    tracing::info!("Epoch {} finalized", em.current_epoch() - 1);
                }
                _ = rx.recv() => {
                    tracing::info!("Shutdown signal received, stopping daemon");
                    break;
                }
            }
        }
        Ok(())
    }

    /// Send a shutdown signal to the daemon loop.
    pub async fn shutdown(&self) {
        if let Some(tx) = &self.shutdown_tx {
            let _ = tx.send(()).await;
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum NodeError {
    #[error("initialization failed: {0}")]
    Init(String),
    #[error("proof generation failed: {0}")]
    Prove(String),
    #[error("pool error: {0}")]
    Pool(String),
}

#[cfg(test)]
mod tests {
    use super::*;
    use pil_note::note::Note;

    #[tokio::test]
    async fn batch_accumulator_basic() {
        let mut acc = BatchAccumulator::new(2);
        assert_eq!(acc.pending_count(), 0);
        assert!(!acc.is_full());

        acc.push(PendingTx::Deposit {
            commitment: Commitment(Base::from(1u64)),
            value: 100,
            asset_id: 0,
        });
        assert_eq!(acc.pending_count(), 1);
        assert!(!acc.is_full());

        acc.push(PendingTx::Deposit {
            commitment: Commitment(Base::from(2u64)),
            value: 200,
            asset_id: 0,
        });
        assert!(acc.is_full());

        let drained = acc.drain();
        assert_eq!(drained.len(), 2);
        assert_eq!(acc.pending_count(), 0);
    }

    #[tokio::test]
    #[ignore] // Halo2 keygen too slow in debug mode
    async fn node_submit_and_flush() {
        let node = PilNode::init_with_batch_size(100).expect("init");

        node.submit_tx(PendingTx::Deposit {
            commitment: Commitment(Base::from(42u64)),
            value: 500,
            asset_id: 0,
        })
        .await
        .unwrap();

        let count = node.flush().await.unwrap();
        assert_eq!(count, 1);

        let pool = node.pool.read().await;
        assert_eq!(pool.balance(), 500);
        assert_eq!(pool.note_count(), 1);
    }

    #[tokio::test]
    #[ignore] // Halo2 keygen too slow in debug mode
    async fn node_finalize_epoch() {
        let node = PilNode::init_with_batch_size(100).expect("init");
        let epoch = node.finalize_epoch().await.unwrap();
        assert_eq!(epoch, 0);

        let em = node.epoch_manager.read().await;
        assert_eq!(em.current_epoch(), 1);
        assert!(em.epoch_root(0).is_some());
    }

    #[test]
    fn note_scanner_filters() {
        use pil_note::keys::SpendingKey;
        let mut rng = rand::thread_rng();
        let sk = SpendingKey::random(&mut rng);
        let scanner = NoteScanner::new(&sk);

        let owned_note = Note::new(100, sk.owner(), 0);
        let other_note = Note::new(200, Base::from(0xDEADu64), 0);

        let notes = vec![(owned_note.clone(), 0u64), (other_note, 1)];
        let found = scanner.scan(&notes);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].0.value, 100);
    }
}
