//! Epoch root aggregator for multi-chain bridge operations.
//!
//! Collects epoch attestations from multiple source chains and produces
//! a summary digest that downstream consumers (relayers, verifiers) can use
//! to check cross-chain consistency.

use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

use pil_primitives::domain::ChainDomain;

use crate::EpochAttestation;

/// Aggregated epoch summary for a single epoch across multiple chains.
#[derive(Debug, Clone)]
pub struct EpochSummary {
    /// Epoch number.
    pub epoch: u64,
    /// Per-chain nullifier roots keyed by chain domain ID.
    pub chain_roots: BTreeMap<u32, [u8; 32]>,
    /// Combined digest: SHA-256 of all chain roots in deterministic order.
    pub digest: [u8; 32],
    /// Number of chains contributing to this epoch.
    pub chain_count: usize,
}

/// Multi-chain epoch root aggregator.
///
/// Accumulates attestations from different source chains and produces
/// a combined digest for each epoch. The digest is deterministic:
/// `SHA-256("PIL-AGG" || epoch_be || chain_a_id || root_a || chain_b_id || root_b || ...)`
/// where chains are sorted by their domain ID.
pub struct EpochAggregator {
    /// Collected attestations: epoch → (chain_id → nullifier_root).
    epochs: BTreeMap<u64, BTreeMap<u32, [u8; 32]>>,
    /// Expected number of chains before an epoch is considered complete.
    expected_chains: usize,
}

impl EpochAggregator {
    /// Create an aggregator expecting `expected_chains` attestations per epoch.
    pub fn new(expected_chains: usize) -> Self {
        Self {
            epochs: BTreeMap::new(),
            expected_chains,
        }
    }

    /// Ingest an epoch attestation from a source chain.
    /// Returns `true` if this epoch is now complete (all expected chains reported).
    pub fn ingest(&mut self, attestation: &EpochAttestation) -> bool {
        let chain_id = attestation.source_chain.as_u32();
        let entry = self.epochs.entry(attestation.epoch).or_default();
        entry.insert(chain_id, attestation.nullifier_root);
        entry.len() >= self.expected_chains
    }

    /// Check whether a specific epoch has complete attestations.
    pub fn is_complete(&self, epoch: u64) -> bool {
        self.epochs
            .get(&epoch)
            .is_some_and(|roots| roots.len() >= self.expected_chains)
    }

    /// Build the aggregated summary for a specific epoch.
    /// Returns `None` if the epoch is not yet complete.
    pub fn summarize(&self, epoch: u64) -> Option<EpochSummary> {
        let chain_roots = self.epochs.get(&epoch)?;
        if chain_roots.len() < self.expected_chains {
            return None;
        }

        let digest = Self::compute_digest(epoch, chain_roots);

        Some(EpochSummary {
            epoch,
            chain_roots: chain_roots.clone(),
            digest,
            chain_count: chain_roots.len(),
        })
    }

    /// Compute the deterministic digest for an epoch's chain roots.
    fn compute_digest(epoch: u64, chain_roots: &BTreeMap<u32, [u8; 32]>) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(b"PIL-AGG");
        hasher.update(epoch.to_be_bytes());
        // BTreeMap iterates in sorted key order → deterministic
        for (chain_id, root) in chain_roots {
            hasher.update(chain_id.to_be_bytes());
            hasher.update(root);
        }
        hasher.finalize().into()
    }

    /// Number of epochs tracked by the aggregator.
    pub fn epoch_count(&self) -> usize {
        self.epochs.len()
    }

    /// Number of attestations received for a specific epoch.
    pub fn attestation_count(&self, epoch: u64) -> usize {
        self.epochs.get(&epoch).map_or(0, |roots| roots.len())
    }

    /// Drain all complete epochs, returning their summaries.
    pub fn drain_complete(&mut self) -> Vec<EpochSummary> {
        let complete_epochs: Vec<u64> = self
            .epochs
            .iter()
            .filter(|(_, roots)| roots.len() >= self.expected_chains)
            .map(|(&epoch, _)| epoch)
            .collect();

        let mut summaries = Vec::new();
        for epoch in complete_epochs {
            if let Some(roots) = self.epochs.remove(&epoch) {
                let digest = Self::compute_digest(epoch, &roots);
                summaries.push(EpochSummary {
                    epoch,
                    chain_roots: roots.clone(),
                    digest,
                    chain_count: roots.len(),
                });
            }
        }
        summaries
    }
}

/// Relay health status for monitoring.
#[derive(Debug, Clone)]
pub struct RelayHealth {
    /// Source chain domain.
    pub source: ChainDomain,
    /// Destination chain domain.
    pub destination: ChainDomain,
    /// Latest successfully relayed epoch.
    pub latest_epoch: Option<u64>,
    /// Number of pending retries.
    pub pending_retries: usize,
    /// Whether the relay is healthy (no stuck epochs).
    pub healthy: bool,
    /// Lag: how many epochs behind the source chain.
    pub epoch_lag: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_attestation(chain: ChainDomain, epoch: u64, root_byte: u8) -> EpochAttestation {
        let mut root = [0u8; 32];
        root[0] = root_byte;
        EpochAttestation {
            source_chain: chain,
            epoch,
            nullifier_root: root,
            proof: vec![],
            timestamp: 1000,
        }
    }

    #[test]
    fn aggregator_single_chain() {
        let mut agg = EpochAggregator::new(1);

        let att = make_attestation(ChainDomain::CardanoMainnet, 0, 0xAA);
        assert!(agg.ingest(&att));
        assert!(agg.is_complete(0));

        let summary = agg.summarize(0).unwrap();
        assert_eq!(summary.epoch, 0);
        assert_eq!(summary.chain_count, 1);
        assert_ne!(summary.digest, [0u8; 32]);
    }

    #[test]
    fn aggregator_two_chains() {
        let mut agg = EpochAggregator::new(2);

        let att1 = make_attestation(ChainDomain::CardanoMainnet, 5, 0xAA);
        assert!(!agg.ingest(&att1));
        assert!(!agg.is_complete(5));

        let att2 = make_attestation(ChainDomain::CosmosHub, 5, 0xBB);
        assert!(agg.ingest(&att2));
        assert!(agg.is_complete(5));

        let summary = agg.summarize(5).unwrap();
        assert_eq!(summary.epoch, 5);
        assert_eq!(summary.chain_count, 2);
    }

    #[test]
    fn aggregator_digest_deterministic() {
        let mut agg1 = EpochAggregator::new(2);
        let mut agg2 = EpochAggregator::new(2);

        // Insert in different order → same digest
        let att_c = make_attestation(ChainDomain::CardanoMainnet, 0, 0xAA);
        let att_h = make_attestation(ChainDomain::CosmosHub, 0, 0xBB);

        agg1.ingest(&att_c);
        agg1.ingest(&att_h);

        agg2.ingest(&att_h); // different order
        agg2.ingest(&att_c);

        let s1 = agg1.summarize(0).unwrap();
        let s2 = agg2.summarize(0).unwrap();
        assert_eq!(s1.digest, s2.digest);
    }

    #[test]
    fn aggregator_drain_complete() {
        let mut agg = EpochAggregator::new(1);

        agg.ingest(&make_attestation(ChainDomain::CardanoMainnet, 0, 1));
        agg.ingest(&make_attestation(ChainDomain::CardanoMainnet, 1, 2));
        agg.ingest(&make_attestation(ChainDomain::CardanoMainnet, 2, 3));

        assert_eq!(agg.epoch_count(), 3);

        let summaries = agg.drain_complete();
        assert_eq!(summaries.len(), 3);
        assert_eq!(summaries[0].epoch, 0);
        assert_eq!(summaries[1].epoch, 1);
        assert_eq!(summaries[2].epoch, 2);

        // All drained
        assert_eq!(agg.epoch_count(), 0);
    }

    #[test]
    fn aggregator_incomplete_not_drained() {
        let mut agg = EpochAggregator::new(2);

        agg.ingest(&make_attestation(ChainDomain::CardanoMainnet, 0, 1));
        // Only 1 of 2 expected chains

        assert!(!agg.is_complete(0));
        assert!(agg.summarize(0).is_none());

        let summaries = agg.drain_complete();
        assert_eq!(summaries.len(), 0);
        assert_eq!(agg.epoch_count(), 1); // still there
    }

    #[test]
    fn aggregator_attestation_count() {
        let mut agg = EpochAggregator::new(3);

        assert_eq!(agg.attestation_count(0), 0);

        agg.ingest(&make_attestation(ChainDomain::CardanoMainnet, 0, 1));
        assert_eq!(agg.attestation_count(0), 1);

        agg.ingest(&make_attestation(ChainDomain::CosmosHub, 0, 2));
        assert_eq!(agg.attestation_count(0), 2);

        agg.ingest(&make_attestation(ChainDomain::Osmosis, 0, 3));
        assert_eq!(agg.attestation_count(0), 3);
    }
}
