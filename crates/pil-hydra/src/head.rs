//! Hydra head lifecycle management.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use pil_primitives::domain::ChainDomain;
use pil_primitives::types::Base;

use super::snapshot::{Snapshot, SnapshotPolicy};
use super::state::HydraPoolState;

/// Configuration for a Hydra head.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HydraHeadConfig {
    /// Unique identifier for this head.
    pub head_id: String,
    /// Participating peers (public key hashes).
    pub participants: Vec<String>,
    /// Cardano chain domain (mainnet, preprod, preview).
    pub chain_domain: ChainDomain,
    /// When to take L2 → L1 snapshots.
    pub snapshot_policy: SnapshotPolicy,
    /// Maximum number of unconfirmed L2 transactions before forced snapshot.
    pub max_pending_txs: u32,
    /// Contestation period in seconds (for fanout/close).
    pub contestation_period_secs: u64,
}

/// Hydra head state machine.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum HydraHeadState {
    /// Head parameters defined, not yet initialized on-chain.
    Idle,
    /// Init transaction submitted, waiting for all participants to commit.
    Initializing,
    /// All parties committed, head is open for L2 transactions.
    Open,
    /// Close requested, in contestation period.
    Closing,
    /// Contestation period ended, fanout pending.
    Closed,
    /// Fanout complete, all UTXOs settled back to L1.
    FanoutComplete,
}

/// A Hydra head manages an L2 privacy pool with periodic L1 snapshots.
#[derive(Clone)]
pub struct HydraHead {
    config: HydraHeadConfig,
    state: HydraHeadState,
    /// L2 privacy pool state.
    pool_state: HydraPoolState,
    /// Snapshots taken so far (snapshot_number → snapshot).
    snapshots: HashMap<u64, Snapshot>,
    /// Current snapshot number.
    snapshot_number: u64,
    /// Number of L2 transactions since last snapshot.
    txs_since_snapshot: u32,
    /// L1 epoch at time of head opening.
    l1_epoch_at_open: u64,
}

impl HydraHead {
    /// Create a new Hydra head in Idle state.
    pub fn new(config: HydraHeadConfig) -> Self {
        Self {
            pool_state: HydraPoolState::new(config.chain_domain),
            config,
            state: HydraHeadState::Idle,
            snapshots: HashMap::new(),
            snapshot_number: 0,
            txs_since_snapshot: 0,
            l1_epoch_at_open: 0,
        }
    }

    /// Current head state.
    pub fn state(&self) -> HydraHeadState {
        self.state
    }

    /// Access the L2 pool state.
    pub fn pool_state(&self) -> &HydraPoolState {
        &self.pool_state
    }

    /// Mutable access to the L2 pool state.
    pub fn pool_state_mut(&mut self) -> &mut HydraPoolState {
        &mut self.pool_state
    }

    /// Number of participants.
    pub fn num_participants(&self) -> usize {
        self.config.participants.len()
    }

    /// Move head to Initializing (after init tx submitted on L1).
    pub fn begin_init(&mut self, l1_epoch: u64) -> Result<(), HydraError> {
        if self.state != HydraHeadState::Idle {
            return Err(HydraError::InvalidTransition {
                from: self.state,
                to: HydraHeadState::Initializing,
            });
        }
        self.l1_epoch_at_open = l1_epoch;
        self.state = HydraHeadState::Initializing;
        Ok(())
    }

    /// All participants committed — head is open.
    pub fn open(&mut self) -> Result<(), HydraError> {
        if self.state != HydraHeadState::Initializing {
            return Err(HydraError::InvalidTransition {
                from: self.state,
                to: HydraHeadState::Open,
            });
        }
        self.state = HydraHeadState::Open;
        Ok(())
    }

    /// Process an L2 transaction (deposit, transfer, or withdraw in the head).
    /// Returns whether a snapshot should be taken.
    pub fn process_l2_tx(&mut self) -> Result<bool, HydraError> {
        if self.state != HydraHeadState::Open {
            return Err(HydraError::HeadNotOpen);
        }
        self.txs_since_snapshot += 1;
        Ok(self.should_snapshot())
    }

    /// Check if a snapshot should be taken based on the policy.
    fn should_snapshot(&self) -> bool {
        match self.config.snapshot_policy {
            SnapshotPolicy::EveryNTransactions(n) => self.txs_since_snapshot >= n,
            SnapshotPolicy::Manual => false,
        }
    }

    /// Take a snapshot only if the configured policy says it's time.
    /// Returns `Ok(Some(snapshot))` when a snapshot was taken, `Ok(None)`
    /// when the policy says it's not time yet.
    pub fn try_auto_snapshot(&mut self) -> Result<Option<Snapshot>, HydraError> {
        if self.should_snapshot() {
            self.take_snapshot().map(Some)
        } else {
            Ok(None)
        }
    }

    /// Take a snapshot of the current L2 state for L1 commitment.
    pub fn take_snapshot(&mut self) -> Result<Snapshot, HydraError> {
        if self.state != HydraHeadState::Open {
            return Err(HydraError::HeadNotOpen);
        }

        let snapshot = Snapshot {
            snapshot_number: self.snapshot_number,
            pool_root: self.pool_state.pool_root(),
            nullifier_count: self.pool_state.nullifier_count() as u64,
            note_count: self.pool_state.note_count(),
            l2_tx_count: self.txs_since_snapshot,
        };

        self.snapshots
            .insert(self.snapshot_number, snapshot.clone());
        self.snapshot_number += 1;
        self.txs_since_snapshot = 0;

        Ok(snapshot)
    }

    /// Get a specific snapshot.
    pub fn snapshot(&self, number: u64) -> Option<&Snapshot> {
        self.snapshots.get(&number)
    }

    /// Latest snapshot number.
    pub fn latest_snapshot_number(&self) -> u64 {
        self.snapshot_number
    }

    /// Begin closing the head.
    pub fn begin_close(&mut self) -> Result<Snapshot, HydraError> {
        if self.state != HydraHeadState::Open {
            return Err(HydraError::HeadNotOpen);
        }
        // Take final snapshot before closing
        let final_snapshot = self.take_snapshot()?;
        self.state = HydraHeadState::Closing;
        Ok(final_snapshot)
    }

    /// Contestation period ended, head is closed.
    pub fn finalize_close(&mut self) -> Result<(), HydraError> {
        if self.state != HydraHeadState::Closing {
            return Err(HydraError::InvalidTransition {
                from: self.state,
                to: HydraHeadState::Closed,
            });
        }
        self.state = HydraHeadState::Closed;
        Ok(())
    }

    /// Fan out all L2 UTXOs back to L1.
    pub fn fanout(&mut self) -> Result<FanoutResult, HydraError> {
        if self.state != HydraHeadState::Closed {
            return Err(HydraError::InvalidTransition {
                from: self.state,
                to: HydraHeadState::FanoutComplete,
            });
        }
        let result = FanoutResult {
            final_pool_root: self.pool_state.pool_root(),
            total_notes: self.pool_state.note_count(),
            total_nullifiers: self.pool_state.nullifier_count() as u64,
            total_snapshots: self.snapshot_number,
        };
        self.state = HydraHeadState::FanoutComplete;
        Ok(result)
    }
}

/// Result of fanning out a Hydra head back to L1.
#[derive(Debug, Clone)]
pub struct FanoutResult {
    pub final_pool_root: Base,
    pub total_notes: u64,
    pub total_nullifiers: u64,
    pub total_snapshots: u64,
}

#[derive(Debug, thiserror::Error)]
pub enum HydraError {
    #[error("invalid state transition from {from:?} to {to:?}")]
    InvalidTransition {
        from: HydraHeadState,
        to: HydraHeadState,
    },
    #[error("head is not open")]
    HeadNotOpen,
    #[error("pool error: {0}")]
    Pool(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_config() -> HydraHeadConfig {
        HydraHeadConfig {
            head_id: "test-head-1".to_string(),
            participants: vec![
                "alice_pkh".to_string(),
                "bob_pkh".to_string(),
            ],
            chain_domain: ChainDomain::CardanoPreprod,
            snapshot_policy: SnapshotPolicy::EveryNTransactions(5),
            max_pending_txs: 100,
            contestation_period_secs: 300,
        }
    }

    #[test]
    fn hydra_head_lifecycle() {
        let mut head = HydraHead::new(test_config());
        assert_eq!(head.state(), HydraHeadState::Idle);

        // Init
        head.begin_init(0).unwrap();
        assert_eq!(head.state(), HydraHeadState::Initializing);

        // Open
        head.open().unwrap();
        assert_eq!(head.state(), HydraHeadState::Open);

        // Process L2 txs
        for _ in 0..4 {
            let needs_snapshot = head.process_l2_tx().unwrap();
            assert!(!needs_snapshot);
        }
        // 5th tx triggers snapshot
        let needs_snapshot = head.process_l2_tx().unwrap();
        assert!(needs_snapshot);

        let snap = head.take_snapshot().unwrap();
        assert_eq!(snap.snapshot_number, 0);
        assert_eq!(snap.l2_tx_count, 5);

        // Close
        let final_snap = head.begin_close().unwrap();
        assert_eq!(final_snap.snapshot_number, 1);
        assert_eq!(head.state(), HydraHeadState::Closing);

        head.finalize_close().unwrap();
        assert_eq!(head.state(), HydraHeadState::Closed);

        let fanout = head.fanout().unwrap();
        assert_eq!(fanout.total_snapshots, 2);
        assert_eq!(head.state(), HydraHeadState::FanoutComplete);
    }

    #[test]
    fn invalid_transitions_rejected() {
        let mut head = HydraHead::new(test_config());

        // Can't open without init
        assert!(head.open().is_err());

        // Can't process tx while idle
        assert!(head.process_l2_tx().is_err());

        head.begin_init(0).unwrap();

        // Can't init twice
        assert!(head.begin_init(1).is_err());

        // Can't close while initializing
        assert!(head.begin_close().is_err());
    }

    #[test]
    fn snapshot_counter_increments() {
        let mut head = HydraHead::new(test_config());
        head.begin_init(0).unwrap();
        head.open().unwrap();

        let s0 = head.take_snapshot().unwrap();
        let s1 = head.take_snapshot().unwrap();
        let s2 = head.take_snapshot().unwrap();

        assert_eq!(s0.snapshot_number, 0);
        assert_eq!(s1.snapshot_number, 1);
        assert_eq!(s2.snapshot_number, 2);
        assert_eq!(head.latest_snapshot_number(), 3);
    }
}
