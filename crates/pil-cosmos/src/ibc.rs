//! IBC integration for cross-chain epoch synchronization.
//!
//! This module implements IBC packet handling for publishing and receiving
//! epoch nullifier roots between Cosmos chains.
//!
//! ## Protocol
//!
//! 1. At epoch finalization, the privacy pool computes a nullifier Merkle root
//! 2. The root is published to connected chains via IBC packets
//! 3. Remote chains store the root and can verify cross-chain nullifier membership
//! 4. This prevents double-spending across Cosmos chains without a central coordinator
//!
//! ## IBC Channel Setup
//!
//! Each pair of PIL-enabled Cosmos chains establishes a dedicated IBC channel
//! using a custom port: `pil-epoch-sync`. The channel is ORDERED to ensure
//! epoch roots arrive in sequence.

use serde::{Deserialize, Serialize};

/// IBC packet data for epoch root synchronization.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EpochSyncPacket {
    /// Source chain domain ID.
    pub source_chain_id: u32,
    /// Source app ID.
    pub source_app_id: u32,
    /// Epoch number.
    pub epoch: u64,
    /// Nullifier Merkle root for this epoch (hex-encoded 32 bytes).
    pub nullifier_root: String,
    /// Number of nullifiers in this epoch.
    pub nullifier_count: u64,
    /// Summary root over all epochs up to this one.
    pub cumulative_root: String,
}

/// IBC epoch synchronization handler.
pub struct IBCEpochSync {
    /// Local chain domain ID.
    pub local_chain_id: u32,
    /// Connected channels: channel_id → remote chain domain ID.
    pub channels: Vec<(String, u32)>,
    /// Received remote epoch roots: (chain_id, epoch) → root.
    pub remote_roots: Vec<(u32, u64, String)>,
}

impl IBCEpochSync {
    pub fn new(local_chain_id: u32) -> Self {
        Self {
            local_chain_id,
            channels: Vec::new(),
            remote_roots: Vec::new(),
        }
    }

    /// Register an IBC channel for epoch sync with a remote chain.
    pub fn register_channel(&mut self, channel_id: String, remote_chain_id: u32) {
        self.channels.push((channel_id, remote_chain_id));
    }

    /// Create an IBC packet for publishing the local epoch root.
    pub fn create_epoch_packet(
        &self,
        epoch: u64,
        nullifier_root: String,
        nullifier_count: u64,
        cumulative_root: String,
    ) -> EpochSyncPacket {
        EpochSyncPacket {
            source_chain_id: self.local_chain_id,
            source_app_id: 0,
            epoch,
            nullifier_root,
            nullifier_count,
            cumulative_root,
        }
    }

    /// Handle a received epoch root from a remote chain.
    pub fn receive_epoch_root(
        &mut self,
        packet: EpochSyncPacket,
    ) -> Result<(), IBCSyncError> {
        // Verify source chain is a known peer
        let is_known = self
            .channels
            .iter()
            .any(|(_, chain_id)| *chain_id == packet.source_chain_id);

        if !is_known {
            return Err(IBCSyncError::UnknownSourceChain(packet.source_chain_id));
        }

        // Store the remote epoch root
        self.remote_roots.push((
            packet.source_chain_id,
            packet.epoch,
            packet.nullifier_root,
        ));

        Ok(())
    }

    /// Check if a nullifier was spent on a remote chain during a specific epoch.
    /// Returns the nullifier root for verification.
    pub fn get_remote_epoch_root(
        &self,
        chain_id: u32,
        epoch: u64,
    ) -> Option<&str> {
        self.remote_roots
            .iter()
            .find(|(c, e, _)| *c == chain_id && *e == epoch)
            .map(|(_, _, root)| root.as_str())
    }
}

#[derive(Debug, thiserror::Error)]
pub enum IBCSyncError {
    #[error("unknown source chain: {0}")]
    UnknownSourceChain(u32),
    #[error("epoch already received")]
    DuplicateEpoch,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ibc_epoch_sync_roundtrip() {
        let mut local = IBCEpochSync::new(10); // Cosmos Hub
        local.register_channel("channel-42".to_string(), 11); // Osmosis

        // Osmosis sends an epoch root
        let packet = EpochSyncPacket {
            source_chain_id: 11,
            source_app_id: 0,
            epoch: 5,
            nullifier_root: "abcdef".to_string(),
            nullifier_count: 100,
            cumulative_root: "123456".to_string(),
        };

        local.receive_epoch_root(packet).unwrap();

        let root = local.get_remote_epoch_root(11, 5);
        assert_eq!(root, Some("abcdef"));
    }

    #[test]
    fn ibc_rejects_unknown_chain() {
        let mut sync = IBCEpochSync::new(10);
        let packet = EpochSyncPacket {
            source_chain_id: 99, // Unknown chain
            source_app_id: 0,
            epoch: 0,
            nullifier_root: "".to_string(),
            nullifier_count: 0,
            cumulative_root: "".to_string(),
        };
        assert!(sync.receive_epoch_root(packet).is_err());
    }
}
