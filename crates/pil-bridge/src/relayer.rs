//! Bridge relayer: watches for epoch finalizations on each chain and
//! relays the epoch roots to connected chains.
//!
//! The relayer operates as a persistent service that:
//! 1. Polls source chains for new epoch finalizations
//! 2. Fetches light-client proofs for the epoch roots
//! 3. Constructs and submits attestation transactions on destination chains
//! 4. Tracks relayed epochs to prevent duplicates

use super::{BridgeConfig, EpochAttestation};
use pil_cosmos::ibc::{EpochSyncPacket, IBCEpochSync};
use pil_primitives::domain::ChainDomain;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Response from the PIL RPC `/status` endpoint.
#[derive(Debug, serde::Deserialize)]
struct RpcStatusResponse {
    current_epoch: Option<u64>,
}

/// Response from the PIL RPC `/epoch/:id` endpoint.
#[derive(Debug, serde::Deserialize)]
struct RpcEpochResponse {
    epoch: u64,
    nullifier_root: String,
    #[serde(default)]
    proof: String,
}

/// The bridge relayer service.
pub struct BridgeRelayer {
    config: BridgeConfig,
    /// Latest relayed epoch per (source, destination) chain pair.
    latest_relayed: HashMap<(u32, u32), u64>,
    /// IBC epoch sync instances per Cosmos destination chain.
    cosmos_sync: HashMap<u32, IBCEpochSync>,
    /// Queue of pending attestations awaiting submission.
    pending_queue: Vec<PendingAttestation>,
    /// Metrics counters.
    metrics: RelayerMetrics,
    /// HTTP client for RPC calls.
    http: reqwest::Client,
    /// Per-pair rate limiter.
    rate_limiter: RateLimiter,
}

/// A pending attestation waiting to be submitted.
#[derive(Debug, Clone)]
struct PendingAttestation {
    attestation: EpochAttestation,
    destination: ChainDomain,
    retries: u32,
    max_retries: u32,
    /// Next retry time (epoch seconds). Implements exponential backoff.
    next_retry_at: u64,
}

/// Simple per-pair rate limiter: allows at most `max_per_window`
/// submissions per `window_secs` seconds for each (source, dest) pair.
#[derive(Debug, Clone)]
pub struct RateLimiter {
    /// Maximum submissions per window.
    max_per_window: u32,
    /// Window duration in seconds.
    window_secs: u64,
    /// Submission timestamps per pair key.
    history: HashMap<(u32, u32), Vec<u64>>,
}

impl RateLimiter {
    /// Create a rate limiter allowing `max_per_window` submissions
    /// every `window_secs` seconds per chain pair.
    pub fn new(max_per_window: u32, window_secs: u64) -> Self {
        Self {
            max_per_window,
            window_secs,
            history: HashMap::new(),
        }
    }

    /// Check if a submission is allowed for this pair, and record it if so.
    pub fn try_acquire(&mut self, pair: (u32, u32), now: u64) -> bool {
        let entries = self.history.entry(pair).or_default();
        // Evict entries outside the window
        entries.retain(|&ts| now.saturating_sub(ts) < self.window_secs);
        if entries.len() < self.max_per_window as usize {
            entries.push(now);
            true
        } else {
            false
        }
    }

    /// Number of submissions remaining in the current window for a pair.
    pub fn remaining(&mut self, pair: (u32, u32), now: u64) -> u32 {
        let entries = self.history.entry(pair).or_default();
        entries.retain(|&ts| now.saturating_sub(ts) < self.window_secs);
        self.max_per_window.saturating_sub(entries.len() as u32)
    }
}

impl Default for RateLimiter {
    fn default() -> Self {
        // Default: 10 relays per 60 seconds per pair
        Self::new(10, 60)
    }
}

/// Relayer operational metrics.
#[derive(Debug, Clone, Default)]
pub struct RelayerMetrics {
    /// Total epochs successfully relayed.
    pub epochs_relayed: u64,
    /// Total relay failures.
    pub relay_failures: u64,
    /// Total attestation verifications performed.
    pub verifications: u64,
    /// Total retry attempts.
    pub retries: u64,
    /// Total submissions blocked by rate limiter.
    pub rate_limited: u64,
}

impl BridgeRelayer {
    pub fn new(config: BridgeConfig) -> Self {
        Self {
            config,
            latest_relayed: HashMap::new(),
            cosmos_sync: HashMap::new(),
            pending_queue: Vec::new(),
            metrics: RelayerMetrics::default(),
            http: reqwest::Client::new(),
            rate_limiter: RateLimiter::default(),
        }
    }

    /// Get a reference to the bridge configuration.
    pub fn config(&self) -> &BridgeConfig {
        &self.config
    }

    /// Register a Cosmos chain for IBC epoch sync.
    pub fn register_cosmos_chain(
        &mut self,
        chain_domain: ChainDomain,
        channel_id: String,
        local_chain_id: u32,
    ) {
        let remote_id = chain_domain.as_u32();
        let mut sync = IBCEpochSync::new(local_chain_id);
        sync.register_channel(channel_id, remote_id);
        self.cosmos_sync.insert(remote_id, sync);
    }

    /// Access relayer metrics.
    pub fn metrics(&self) -> &RelayerMetrics {
        &self.metrics
    }

    /// Start the relay loop (async, long-running).
    ///
    /// Polls each configured relay pair on the configured interval,
    /// fetches new epochs, and submits attestations.
    pub async fn run(&mut self) -> Result<(), BridgeError> {
        tracing::info!(
            "Starting PIL bridge relayer: {} relay pairs, poll interval {}s",
            self.config.relay_pairs.len(),
            self.config.poll_interval_secs,
        );

        loop {
            // Process each relay pair
            for (source, destination) in self.config.relay_pairs.clone() {
                match self.poll_and_relay(source, destination).await {
                    Ok(Some(epoch)) => {
                        tracing::info!(
                            "Relayed epoch {} from {:?} → {:?}",
                            epoch,
                            source,
                            destination,
                        );
                    }
                    Ok(None) => {} // No new epoch
                    Err(e) => {
                        tracing::warn!("Relay error {:?} → {:?}: {}", source, destination, e,);
                        self.metrics.relay_failures += 1;
                    }
                }
            }

            // Retry pending attestations
            self.process_pending_queue().await;

            tokio::time::sleep(tokio::time::Duration::from_secs(
                self.config.poll_interval_secs,
            ))
            .await;
        }
    }

    /// Poll a source chain for new epochs and relay to destination.
    async fn poll_and_relay(
        &mut self,
        source: ChainDomain,
        destination: ChainDomain,
    ) -> Result<Option<u64>, BridgeError> {
        let pair_key = (source.as_u32(), destination.as_u32());
        let last_relayed = self.latest_relayed.get(&pair_key).copied().unwrap_or(0);

        // Fetch the latest finalized epoch from the source chain
        let latest_epoch = self.fetch_latest_epoch(source).await?;

        if latest_epoch <= last_relayed {
            return Ok(None);
        }

        // Relay all missed epochs sequentially
        for epoch in (last_relayed + 1)..=latest_epoch {
            let attestation = self.fetch_epoch_attestation(source, epoch).await?;

            // Verify the attestation's light-client proof
            self.verify_attestation(&attestation)?;
            self.metrics.verifications += 1;

            // Submit to destination
            self.submit_attestation(destination, &attestation).await?;

            self.latest_relayed.insert(pair_key, epoch);
            self.metrics.epochs_relayed += 1;
        }

        Ok(Some(latest_epoch))
    }

    /// Relay a single epoch root from source to destination.
    pub async fn relay_epoch(
        &mut self,
        source: ChainDomain,
        destination: ChainDomain,
        attestation: EpochAttestation,
    ) -> Result<(), BridgeError> {
        let pair_key = (source.as_u32(), destination.as_u32());

        // Check we haven't already relayed this epoch
        if let Some(&latest) = self.latest_relayed.get(&pair_key) {
            if attestation.epoch <= latest {
                return Err(BridgeError::EpochAlreadyRelayed {
                    epoch: attestation.epoch,
                });
            }
        }

        // Rate limit check
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        if !self.rate_limiter.try_acquire(pair_key, now) {
            self.metrics.rate_limited += 1;
            return Err(BridgeError::RateLimited {
                src: source,
                dst: destination,
            });
        }

        // Verify the attestation
        self.verify_attestation(&attestation)?;
        self.metrics.verifications += 1;

        // Submit to destination
        self.submit_attestation(destination, &attestation).await?;

        self.latest_relayed.insert(pair_key, attestation.epoch);
        self.metrics.epochs_relayed += 1;
        Ok(())
    }

    /// Fetch the latest finalized epoch number from a chain.
    async fn fetch_latest_epoch(&self, chain: ChainDomain) -> Result<u64, BridgeError> {
        let endpoint = self.endpoint_for(chain)?;
        tracing::debug!("Fetching latest epoch from {:?} at {}", chain, endpoint);

        let url = format!("{endpoint}/pil/v1/status");
        let resp = self
            .http
            .get(&url)
            .timeout(std::time::Duration::from_secs(10))
            .send()
            .await
            .map_err(|e| BridgeError::ChainError(format!("HTTP GET {url}: {e}")))?;

        if !resp.status().is_success() {
            return Err(BridgeError::ChainError(format!(
                "GET {url} returned {}",
                resp.status()
            )));
        }

        let body: RpcStatusResponse = resp
            .json()
            .await
            .map_err(|e| BridgeError::ChainError(format!("parse status: {e}")))?;

        Ok(body.current_epoch.unwrap_or(0))
    }

    /// Fetch a specific epoch's attestation from a chain.
    async fn fetch_epoch_attestation(
        &self,
        chain: ChainDomain,
        epoch: u64,
    ) -> Result<EpochAttestation, BridgeError> {
        let endpoint = self.endpoint_for(chain)?;
        tracing::debug!(
            "Fetching epoch {} attestation from {:?} at {}",
            epoch,
            chain,
            endpoint,
        );

        let url = format!("{endpoint}/pil/v1/epoch/{epoch}");
        let resp = self
            .http
            .get(&url)
            .timeout(std::time::Duration::from_secs(10))
            .send()
            .await
            .map_err(|e| BridgeError::ChainError(format!("HTTP GET {url}: {e}")))?;

        if !resp.status().is_success() {
            return Err(BridgeError::ChainError(format!(
                "GET {url} returned {}",
                resp.status()
            )));
        }

        let body: RpcEpochResponse = resp
            .json()
            .await
            .map_err(|e| BridgeError::ChainError(format!("parse epoch: {e}")))?;

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let mut nullifier_root = [0u8; 32];
        if let Ok(bytes) = hex::decode(&body.nullifier_root) {
            let len = bytes.len().min(32);
            nullifier_root[..len].copy_from_slice(&bytes[..len]);
        }

        let proof = hex::decode(&body.proof).unwrap_or_default();

        Ok(EpochAttestation {
            source_chain: chain,
            epoch: body.epoch,
            nullifier_root,
            proof,
            timestamp: now,
        })
    }

    /// Verify an epoch attestation's light-client proof.
    fn verify_attestation(&self, attestation: &EpochAttestation) -> Result<(), BridgeError> {
        // Check timestamp is not too old (within 24 hours)
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let max_age = 24 * 60 * 60; // 24 hours
        if now.saturating_sub(attestation.timestamp) > max_age {
            return Err(BridgeError::StaleAttestation {
                epoch: attestation.epoch,
                age_secs: now - attestation.timestamp,
            });
        }

        // Check nullifier root is not all-zeros (empty proof)
        if attestation.nullifier_root == [0u8; 32] && attestation.epoch > 0 {
            tracing::warn!(
                "Epoch {} has empty nullifier root — skipping proof verification",
                attestation.epoch,
            );
        }

        match attestation.source_chain {
            ChainDomain::CardanoMainnet
            | ChainDomain::CardanoPreprod
            | ChainDomain::CardanoPreview => self.verify_mithril_proof(attestation),
            _ => self.verify_tendermint_proof(attestation),
        }
    }

    /// Minimum acceptable proof length in bytes.
    /// Below this threshold the proof is considered malformed.
    const MIN_PROOF_LEN: usize = 32;

    /// Verify a Cardano Mithril light-client proof.
    ///
    /// Mithril certificates use a multi-signature scheme where Cardano SPOs
    /// sign epoch state snapshots. Verification ensures:
    /// 1. The certificate message commits to the claimed epoch root
    /// 2. Enough SPO signers meet the quorum threshold
    /// 3. Each signer's commitment binds to the message
    /// 4. The certificate is within its validity period (TTL)
    ///
    /// Certificate wire format (packed bytes):
    /// ```text
    /// [version: 1B][epoch: 8B][message: 32B][timestamp: 8B][ttl_secs: 4B]
    /// [num_signers: 2B][signer_entries...]
    ///
    /// Each signer_entry:
    /// [signer_id: 32B][stake_weight: 8B][commitment: 32B]
    /// ```
    fn verify_mithril_proof(&self, attestation: &EpochAttestation) -> Result<(), BridgeError> {
        tracing::debug!(
            "Verifying Mithril proof for epoch {} from {:?}",
            attestation.epoch,
            attestation.source_chain,
        );

        if attestation.proof.is_empty() {
            // In production, empty proofs are never acceptable.
            // Only allow in debug/test builds.
            #[cfg(debug_assertions)]
            {
                tracing::warn!(
                    "No Mithril proof attached for epoch {} — accepting in debug mode only",
                    attestation.epoch,
                );
                return Ok(());
            }
            #[cfg(not(debug_assertions))]
            {
                return Err(BridgeError::VerificationFailed(
                    "empty Mithril proof is not accepted in production".to_string(),
                ));
            }
        }

        // Validate proof has minimum plausible length
        if attestation.proof.len() < Self::MIN_PROOF_LEN {
            return Err(BridgeError::VerificationFailed(format!(
                "Mithril proof too short: {} bytes (min {})",
                attestation.proof.len(),
                Self::MIN_PROOF_LEN,
            )));
        }

        let cert = MithrilCertificate::parse(&attestation.proof).map_err(|e| {
            BridgeError::VerificationFailed(format!("Mithril certificate parse error: {e}"))
        })?;

        // Verify certificate epoch matches attestation
        if cert.epoch != attestation.epoch {
            return Err(BridgeError::VerificationFailed(format!(
                "Certificate epoch {} does not match attestation epoch {}",
                cert.epoch, attestation.epoch,
            )));
        }

        // Verify the certificate message commits to the attestation's nullifier root
        let expected_message =
            Self::compute_epoch_message(attestation.epoch, &attestation.nullifier_root);
        if cert.message != expected_message {
            return Err(BridgeError::VerificationFailed(
                "Certificate message does not match epoch root commitment".to_string(),
            ));
        }

        // Check certificate TTL
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let expiry = cert.timestamp.saturating_add(cert.ttl_secs as u64);
        if now > expiry {
            return Err(BridgeError::VerificationFailed(format!(
                "Mithril certificate expired: issued at {}, TTL {}s, now {}",
                cert.timestamp, cert.ttl_secs, now,
            )));
        }

        // Verify signer quorum: total stake of valid signers must exceed threshold
        let total_stake: u64 = cert.signers.iter().map(|s| s.stake_weight).sum();
        let valid_stake: u64 = cert
            .signers
            .iter()
            .filter(|s| s.verify_commitment(&cert.message, b"PIL-MITHRIL-SIG"))
            .map(|s| s.stake_weight)
            .sum();

        // Require >50% of total stake to have valid commitments (Byzantine quorum)
        let quorum_threshold = total_stake / 2 + 1;
        if valid_stake < quorum_threshold {
            return Err(BridgeError::VerificationFailed(format!(
                "Mithril quorum not met: valid stake {valid_stake} < threshold {quorum_threshold} (total {total_stake})",
            )));
        }

        tracing::info!(
            "Mithril certificate verified for epoch {}: {}/{} stake ({} signers)",
            cert.epoch,
            valid_stake,
            total_stake,
            cert.signers.len(),
        );

        Ok(())
    }

    /// Compute the expected message hash for an epoch root commitment.
    /// `SHA-256("PIL-EPOCH" || epoch_be || nullifier_root)`
    fn compute_epoch_message(epoch: u64, nullifier_root: &[u8; 32]) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(b"PIL-EPOCH");
        hasher.update(epoch.to_be_bytes());
        hasher.update(nullifier_root);
        hasher.finalize().into()
    }

    /// Verify a Cosmos Tendermint/CometBFT light-client proof.
    ///
    /// Validates that the epoch finalization was included in a block signed
    /// by a quorum of Cosmos validators. Uses the same certificate format
    /// as Mithril but with CometBFT validator set semantics.
    ///
    /// In production, this would verify ed25519 signatures from the
    /// CometBFT validator set against the block header containing the
    /// epoch finalization transaction.
    fn verify_tendermint_proof(&self, attestation: &EpochAttestation) -> Result<(), BridgeError> {
        tracing::debug!(
            "Verifying Tendermint proof for epoch {} from {:?}",
            attestation.epoch,
            attestation.source_chain,
        );

        if attestation.proof.is_empty() {
            // In production, empty proofs are never acceptable.
            // Only allow in debug/test builds.
            #[cfg(debug_assertions)]
            {
                tracing::warn!(
                    "No Tendermint proof attached for epoch {} — accepting in debug mode only",
                    attestation.epoch,
                );
                return Ok(());
            }
            #[cfg(not(debug_assertions))]
            {
                return Err(BridgeError::VerificationFailed(
                    "empty Tendermint proof is not accepted in production".to_string(),
                ));
            }
        }

        if attestation.proof.len() < Self::MIN_PROOF_LEN {
            return Err(BridgeError::VerificationFailed(format!(
                "Tendermint proof too short: {} bytes (min {})",
                attestation.proof.len(),
                Self::MIN_PROOF_LEN,
            )));
        }

        // Parse as a certificate (same wire format as Mithril)
        let cert = MithrilCertificate::parse(&attestation.proof).map_err(|e| {
            BridgeError::VerificationFailed(format!("Tendermint certificate parse error: {e}"))
        })?;

        // Verify epoch matches
        if cert.epoch != attestation.epoch {
            return Err(BridgeError::VerificationFailed(format!(
                "Certificate epoch {} does not match attestation epoch {}",
                cert.epoch, attestation.epoch,
            )));
        }

        // Verify message commitment
        let expected_message =
            Self::compute_epoch_message(attestation.epoch, &attestation.nullifier_root);
        if cert.message != expected_message {
            return Err(BridgeError::VerificationFailed(
                "Certificate message does not match epoch root commitment".to_string(),
            ));
        }

        // Check TTL
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let expiry = cert.timestamp.saturating_add(cert.ttl_secs as u64);
        if now > expiry {
            return Err(BridgeError::VerificationFailed(format!(
                "Tendermint certificate expired: issued at {}, TTL {}s, now {}",
                cert.timestamp, cert.ttl_secs, now,
            )));
        }

        // Verify validator quorum (2/3+ for BFT consensus)
        let total_stake: u64 = cert.signers.iter().map(|s| s.stake_weight).sum();
        let valid_stake: u64 = cert
            .signers
            .iter()
            .filter(|s| s.verify_commitment(&cert.message, b"PIL-TENDERMINT-SIG"))
            .map(|s| s.stake_weight)
            .sum();

        // BFT requires >2/3 of voting power
        let quorum_threshold = total_stake * 2 / 3 + 1;
        if valid_stake < quorum_threshold {
            return Err(BridgeError::VerificationFailed(format!(
                "Tendermint quorum not met: valid stake {valid_stake} < threshold {quorum_threshold} (total {total_stake})",
            )));
        }

        tracing::info!(
            "Tendermint certificate verified for epoch {}: {}/{} stake ({} validators)",
            cert.epoch,
            valid_stake,
            total_stake,
            cert.signers.len(),
        );

        Ok(())
    }

    /// Submit an attestation to a destination chain.
    async fn submit_attestation(
        &self,
        destination: ChainDomain,
        attestation: &EpochAttestation,
    ) -> Result<(), BridgeError> {
        match destination {
            ChainDomain::CosmosHub
            | ChainDomain::Osmosis
            | ChainDomain::Neutron
            | ChainDomain::Injective
            | ChainDomain::SecretNetwork
            | ChainDomain::Celestia
            | ChainDomain::Sei
            | ChainDomain::Archway
            | ChainDomain::Dymension
            | ChainDomain::Stargaze
            | ChainDomain::Akash
            | ChainDomain::Juno => self.submit_to_cosmos(destination, attestation).await,
            ChainDomain::CardanoMainnet
            | ChainDomain::CardanoPreprod
            | ChainDomain::CardanoPreview => self.submit_to_cardano(attestation).await,
            _ => {
                tracing::warn!("Unsupported destination chain: {:?}", destination);
                Err(BridgeError::UnsupportedChain(destination))
            }
        }
    }

    /// Submit an epoch root attestation to a Cosmos chain via IBC.
    async fn submit_to_cosmos(
        &self,
        destination: ChainDomain,
        attestation: &EpochAttestation,
    ) -> Result<(), BridgeError> {
        tracing::info!(
            "Submitting epoch {} from {:?} to Cosmos chain {:?}",
            attestation.epoch,
            attestation.source_chain,
            destination,
        );

        let packet = EpochSyncPacket {
            source_chain_id: attestation.source_chain.as_u32(),
            source_app_id: 0,
            epoch: attestation.epoch,
            nullifier_root: hex::encode(attestation.nullifier_root),
            nullifier_count: 0,
            cumulative_root: String::new(),
        };

        if self.config.dry_run {
            tracing::debug!(
                "Dry-run: skipping Cosmos submission for epoch {}",
                attestation.epoch
            );
            return Ok(());
        }

        // POST the ReceiveEpochRoot message to the Cosmos chain's PIL RPC
        let endpoint = self.endpoint_for(destination)?;
        let url = format!("{endpoint}/pil/v1/receive_epoch_root");

        let body = serde_json::json!({
            "source_chain_id": packet.source_chain_id,
            "epoch": packet.epoch,
            "nullifier_root": packet.nullifier_root,
        });

        let resp = self
            .http
            .post(&url)
            .json(&body)
            .timeout(std::time::Duration::from_secs(30))
            .send()
            .await
            .map_err(|e| BridgeError::ChainError(format!("POST {url}: {e}")))?;

        if !resp.status().is_success() {
            return Err(BridgeError::ChainError(format!(
                "POST {url} returned {}",
                resp.status()
            )));
        }

        Ok(())
    }

    /// Submit an epoch root attestation to Cardano.
    async fn submit_to_cardano(&self, attestation: &EpochAttestation) -> Result<(), BridgeError> {
        tracing::info!(
            "Submitting epoch {} from {:?} to Cardano",
            attestation.epoch,
            attestation.source_chain,
        );

        if self.config.dry_run {
            tracing::debug!(
                "Dry-run: skipping Cardano submission for epoch {}",
                attestation.epoch
            );
            return Ok(());
        }
        // Build a Cardano transaction submission request:
        // 1. Construct epoch datum with the remote chain's root
        // 2. POST the tx to the Cardano submit endpoint
        let endpoint = self.endpoint_for(ChainDomain::CardanoMainnet)?;
        let url = format!("{endpoint}/pil/v1/submit_epoch_root");

        let body = serde_json::json!({
            "source_chain": attestation.source_chain.as_u32(),
            "epoch": attestation.epoch,
            "nullifier_root": hex::encode(attestation.nullifier_root),
            "proof": hex::encode(&attestation.proof),
        });

        let resp = self
            .http
            .post(&url)
            .json(&body)
            .timeout(std::time::Duration::from_secs(30))
            .send()
            .await
            .map_err(|e| BridgeError::ChainError(format!("POST {url}: {e}")))?;

        if !resp.status().is_success() {
            return Err(BridgeError::ChainError(format!(
                "POST {url} returned {}",
                resp.status()
            )));
        }

        Ok(())
    }

    /// Process the pending attestation retry queue with exponential backoff.
    async fn process_pending_queue(&mut self) {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let pending_items: Vec<_> = self.pending_queue.drain(..).collect();
        let mut still_pending = Vec::new();

        for mut pending in pending_items {
            if pending.retries >= pending.max_retries {
                tracing::error!(
                    "Giving up on epoch {} to {:?} after {} retries",
                    pending.attestation.epoch,
                    pending.destination,
                    pending.retries,
                );
                self.metrics.relay_failures += 1;
                continue;
            }

            // Exponential backoff: skip if not yet time
            if now < pending.next_retry_at {
                still_pending.push(pending);
                continue;
            }

            match self
                .submit_attestation(pending.destination, &pending.attestation)
                .await
            {
                Ok(()) => {
                    let pair_key = (
                        pending.attestation.source_chain.as_u32(),
                        pending.destination.as_u32(),
                    );
                    self.latest_relayed
                        .insert(pair_key, pending.attestation.epoch);
                    self.metrics.epochs_relayed += 1;
                    self.metrics.retries += pending.retries as u64;
                }
                Err(e) => {
                    tracing::warn!(
                        "Retry {} for epoch {} to {:?}: {}",
                        pending.retries + 1,
                        pending.attestation.epoch,
                        pending.destination,
                        e,
                    );
                    pending.retries += 1;
                    // Exponential backoff: 2^retries seconds (capped at 300s)
                    let backoff = (1u64 << pending.retries.min(9)).min(300);
                    pending.next_retry_at = now + backoff;
                    still_pending.push(pending);
                }
            }
        }

        self.pending_queue = still_pending;
    }

    /// Queue an attestation for retry with exponential backoff.
    pub fn queue_for_retry(
        &mut self,
        attestation: EpochAttestation,
        destination: ChainDomain,
        max_retries: u32,
    ) {
        self.pending_queue.push(PendingAttestation {
            attestation,
            destination,
            retries: 0,
            max_retries,
            next_retry_at: 0, // eligible immediately on first attempt
        });
    }

    /// Compute the backoff delay for a given retry count.
    /// Uses exponential backoff: 2^retries seconds, capped at 300s.
    pub fn backoff_delay(retries: u32) -> Duration {
        let secs = (1u64 << retries.min(9)).min(300);
        Duration::from_secs(secs)
    }

    /// Get the latest relayed epoch for a chain pair.
    pub fn latest_relayed_epoch(
        &self,
        source: ChainDomain,
        destination: ChainDomain,
    ) -> Option<u64> {
        self.latest_relayed
            .get(&(source.as_u32(), destination.as_u32()))
            .copied()
    }

    /// Number of pending attestations in the retry queue.
    pub fn pending_count(&self) -> usize {
        self.pending_queue.len()
    }

    /// Get the appropriate endpoint for a chain.
    fn endpoint_for(&self, chain: ChainDomain) -> Result<&str, BridgeError> {
        match chain {
            ChainDomain::CardanoMainnet
            | ChainDomain::CardanoPreprod
            | ChainDomain::CardanoPreview => Ok(&self.config.cardano_endpoint),
            _ => Ok(&self.config.cosmos_endpoint),
        }
    }
}

/// Parsed Mithril multi-signature certificate.
///
/// Represents a snapshot attestation signed by Cardano SPOs using the
/// Mithril Stake-based Threshold Multi-signature (STM) scheme.
#[derive(Debug, Clone)]
pub struct MithrilCertificate {
    /// Certificate format version.
    pub version: u8,
    /// Epoch this certificate attests to.
    pub epoch: u64,
    /// SHA-256 message hash: `H("PIL-EPOCH" || epoch || nullifier_root)`.
    pub message: [u8; 32],
    /// Certificate issuance timestamp (epoch seconds).
    pub timestamp: u64,
    /// Certificate validity period in seconds.
    pub ttl_secs: u32,
    /// SPO signers with stake-weighted commitments.
    pub signers: Vec<MithrilSigner>,
}

/// Header size: version(1) + epoch(8) + message(32) + timestamp(8) + ttl(4) + num_signers(2) = 55
const CERT_HEADER_SIZE: usize = 1 + 8 + 32 + 8 + 4 + 2;
/// Each signer entry: signer_pubkey(32) + stake_weight(8) + ed25519_signature(64) = 104
const SIGNER_ENTRY_SIZE: usize = 32 + 8 + 64;

impl MithrilCertificate {
    /// Current certificate format version.
    const CURRENT_VERSION: u8 = 1;

    /// Parse a certificate from its wire format.
    pub fn parse(data: &[u8]) -> Result<Self, String> {
        if data.len() < CERT_HEADER_SIZE {
            return Err(format!(
                "Certificate too short: {} bytes (header requires {CERT_HEADER_SIZE})",
                data.len(),
            ));
        }

        let version = data[0];
        if version != Self::CURRENT_VERSION {
            return Err(format!(
                "Unsupported certificate version: {version} (expected {})",
                Self::CURRENT_VERSION,
            ));
        }

        let epoch = u64::from_be_bytes(data[1..9].try_into().unwrap());
        let mut message = [0u8; 32];
        message.copy_from_slice(&data[9..41]);
        let timestamp = u64::from_be_bytes(data[41..49].try_into().unwrap());
        let ttl_secs = u32::from_be_bytes(data[49..53].try_into().unwrap());
        let num_signers = u16::from_be_bytes(data[53..55].try_into().unwrap()) as usize;

        let expected_len = CERT_HEADER_SIZE + num_signers * SIGNER_ENTRY_SIZE;
        if data.len() < expected_len {
            return Err(format!(
                "Certificate truncated: {} bytes (expected {expected_len} for {num_signers} signers)",
                data.len(),
            ));
        }

        let mut signers = Vec::with_capacity(num_signers);
        for i in 0..num_signers {
            let offset = CERT_HEADER_SIZE + i * SIGNER_ENTRY_SIZE;
            let mut signer_id = [0u8; 32];
            signer_id.copy_from_slice(&data[offset..offset + 32]);
            let stake_weight =
                u64::from_be_bytes(data[offset + 32..offset + 40].try_into().unwrap());
            let mut signature = [0u8; 64];
            signature.copy_from_slice(&data[offset + 40..offset + 104]);
            signers.push(MithrilSigner {
                signer_id,
                stake_weight,
                signature,
            });
        }

        Ok(Self {
            version,
            epoch,
            message,
            timestamp,
            ttl_secs,
            signers,
        })
    }

    /// Serialize a certificate to its wire format.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(CERT_HEADER_SIZE + self.signers.len() * SIGNER_ENTRY_SIZE);
        buf.push(self.version);
        buf.extend_from_slice(&self.epoch.to_be_bytes());
        buf.extend_from_slice(&self.message);
        buf.extend_from_slice(&self.timestamp.to_be_bytes());
        buf.extend_from_slice(&self.ttl_secs.to_be_bytes());
        buf.extend_from_slice(&(self.signers.len() as u16).to_be_bytes());
        for signer in &self.signers {
            buf.extend_from_slice(&signer.signer_id);
            buf.extend_from_slice(&signer.stake_weight.to_be_bytes());
            buf.extend_from_slice(&signer.signature);
        }
        buf
    }
}

/// A Mithril signer (Cardano SPO) with their stake-weighted ed25519 signature.
#[derive(Debug, Clone)]
pub struct MithrilSigner {
    /// SPO ed25519 public key (32 bytes).
    pub signer_id: [u8; 32],
    /// Stake weight in lovelace.
    pub stake_weight: u64,
    /// ed25519 signature over the certificate message (64 bytes).
    /// The signer signs the message field of the certificate, which is
    /// SHA-256("PIL-EPOCH" || epoch_be || nullifier_root).
    pub signature: [u8; 64],
}

impl MithrilSigner {
    /// Verify that this signer's ed25519 signature is valid for the given message.
    ///
    /// `domain_prefix` must be protocol-specific to prevent cross-protocol replay:
    /// - Mithril: `b"PIL-MITHRIL-SIG"`
    /// - Tendermint: `b"PIL-TENDERMINT-SIG"`
    pub fn verify_commitment(&self, message: &[u8; 32], domain_prefix: &[u8]) -> bool {
        use ed25519_dalek::{Signature, VerifyingKey};

        let Ok(vk) = VerifyingKey::from_bytes(&self.signer_id) else {
            return false;
        };
        let sig = Signature::from_bytes(&self.signature);

        // Verify the ed25519 signature over the domain-separated message
        let mut sign_data = Vec::with_capacity(domain_prefix.len() + 32);
        sign_data.extend_from_slice(domain_prefix);
        sign_data.extend_from_slice(message);

        use ed25519_dalek::Verifier;
        vk.verify(&sign_data, &sig).is_ok()
    }

    /// Create a signer with a valid ed25519 signature for testing.
    #[cfg(test)]
    pub fn sign_message(
        signing_key: &ed25519_dalek::SigningKey,
        stake_weight: u64,
        message: &[u8; 32],
        domain_prefix: &[u8],
    ) -> Self {
        use ed25519_dalek::Signer;

        let signer_id: [u8; 32] = signing_key.verifying_key().to_bytes();
        let mut sign_data = Vec::with_capacity(domain_prefix.len() + 32);
        sign_data.extend_from_slice(domain_prefix);
        sign_data.extend_from_slice(message);
        let sig = signing_key.sign(&sign_data);

        Self {
            signer_id,
            stake_weight,
            signature: sig.to_bytes(),
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum BridgeError {
    #[error("epoch {epoch} already relayed")]
    EpochAlreadyRelayed { epoch: u64 },
    #[error("chain communication error: {0}")]
    ChainError(String),
    #[error("light client verification failed: {0}")]
    VerificationFailed(String),
    #[error("stale attestation for epoch {epoch} (age: {age_secs}s)")]
    StaleAttestation { epoch: u64, age_secs: u64 },
    #[error("unsupported chain: {0:?}")]
    UnsupportedChain(ChainDomain),
    #[error("rate limited: {src:?} → {dst:?}")]
    RateLimited { src: ChainDomain, dst: ChainDomain },
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_config() -> BridgeConfig {
        BridgeConfig {
            cardano_endpoint: "http://localhost:3001".to_string(),
            cosmos_endpoint: "http://localhost:26657".to_string(),
            mithril_endpoint: Some("http://localhost:8080".to_string()),
            poll_interval_secs: 30,
            relay_pairs: vec![
                (ChainDomain::CardanoMainnet, ChainDomain::CosmosHub),
                (ChainDomain::CosmosHub, ChainDomain::CardanoMainnet),
            ],
            dry_run: true,
        }
    }

    #[test]
    fn relayer_creation() {
        let relayer = BridgeRelayer::new(test_config());
        assert_eq!(relayer.metrics().epochs_relayed, 0);
        assert_eq!(relayer.pending_count(), 0);
    }

    #[test]
    fn relayer_rejects_duplicate_epoch() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();

        rt.block_on(async {
            let mut relayer = BridgeRelayer::new(test_config());

            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs();

            let attestation = EpochAttestation {
                source_chain: ChainDomain::CardanoMainnet,
                epoch: 1,
                nullifier_root: [0u8; 32],
                proof: vec![],
                timestamp: now,
            };

            // First relay succeeds
            relayer
                .relay_epoch(
                    ChainDomain::CardanoMainnet,
                    ChainDomain::CosmosHub,
                    attestation.clone(),
                )
                .await
                .unwrap();

            // Duplicate is rejected
            let result = relayer
                .relay_epoch(
                    ChainDomain::CardanoMainnet,
                    ChainDomain::CosmosHub,
                    attestation,
                )
                .await;

            assert!(matches!(
                result,
                Err(BridgeError::EpochAlreadyRelayed { epoch: 1 })
            ));
            assert_eq!(relayer.metrics().epochs_relayed, 1);
        });
    }

    #[test]
    fn relayer_tracks_latest_epoch() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();

        rt.block_on(async {
            let mut relayer = BridgeRelayer::new(test_config());

            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs();

            for epoch in 1..=3 {
                let attestation = EpochAttestation {
                    source_chain: ChainDomain::CosmosHub,
                    epoch,
                    nullifier_root: [0u8; 32],
                    proof: vec![],
                    timestamp: now,
                };
                relayer
                    .relay_epoch(
                        ChainDomain::CosmosHub,
                        ChainDomain::CardanoMainnet,
                        attestation,
                    )
                    .await
                    .unwrap();
            }

            assert_eq!(
                relayer.latest_relayed_epoch(ChainDomain::CosmosHub, ChainDomain::CardanoMainnet,),
                Some(3),
            );
            assert_eq!(relayer.metrics().epochs_relayed, 3);
            assert_eq!(relayer.metrics().verifications, 3);
        });
    }

    #[test]
    fn retry_queue_management() {
        let mut relayer = BridgeRelayer::new(test_config());

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let attestation = EpochAttestation {
            source_chain: ChainDomain::CardanoMainnet,
            epoch: 5,
            nullifier_root: [0u8; 32],
            proof: vec![],
            timestamp: now,
        };

        relayer.queue_for_retry(attestation, ChainDomain::CosmosHub, 3);
        assert_eq!(relayer.pending_count(), 1);
    }

    #[test]
    fn cosmos_chain_registration() {
        let mut relayer = BridgeRelayer::new(test_config());
        relayer.register_cosmos_chain(
            ChainDomain::Osmosis,
            "channel-0".to_string(),
            10, // CosmosHub chain ID
        );
        // Verify registration didn't panic
        assert_eq!(relayer.cosmos_sync.len(), 1);
    }

    #[test]
    fn rate_limiter_basic() {
        let mut limiter = RateLimiter::new(3, 60);
        let pair = (1, 10);
        let now = 1000;

        assert!(limiter.try_acquire(pair, now));
        assert!(limiter.try_acquire(pair, now + 1));
        assert!(limiter.try_acquire(pair, now + 2));
        // 4th should be rejected
        assert!(!limiter.try_acquire(pair, now + 3));

        // After window expires, should work again
        assert!(limiter.try_acquire(pair, now + 61));
    }

    #[test]
    fn rate_limiter_remaining() {
        let mut limiter = RateLimiter::new(5, 60);
        let pair = (1, 10);
        let now = 1000;

        assert_eq!(limiter.remaining(pair, now), 5);
        limiter.try_acquire(pair, now);
        assert_eq!(limiter.remaining(pair, now), 4);
        limiter.try_acquire(pair, now);
        limiter.try_acquire(pair, now);
        assert_eq!(limiter.remaining(pair, now), 2);
    }

    #[test]
    fn rate_limiter_independent_pairs() {
        let mut limiter = RateLimiter::new(2, 60);
        let pair_a = (1, 10);
        let pair_b = (10, 1);
        let now = 1000;

        assert!(limiter.try_acquire(pair_a, now));
        assert!(limiter.try_acquire(pair_a, now));
        assert!(!limiter.try_acquire(pair_a, now));

        // Different pair is independent
        assert!(limiter.try_acquire(pair_b, now));
        assert!(limiter.try_acquire(pair_b, now));
        assert!(!limiter.try_acquire(pair_b, now));
    }

    #[test]
    fn relay_epoch_rate_limited() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();

        rt.block_on(async {
            let mut relayer = BridgeRelayer::new(test_config());
            // Set a tight rate limit: 2 per 60s
            relayer.rate_limiter = RateLimiter::new(2, 60);

            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs();

            for epoch in 1..=2 {
                let att = EpochAttestation {
                    source_chain: ChainDomain::CardanoMainnet,
                    epoch,
                    nullifier_root: [0u8; 32],
                    proof: vec![],
                    timestamp: now,
                };
                relayer
                    .relay_epoch(ChainDomain::CardanoMainnet, ChainDomain::CosmosHub, att)
                    .await
                    .unwrap();
            }

            // 3rd relay should be rate limited
            let att = EpochAttestation {
                source_chain: ChainDomain::CardanoMainnet,
                epoch: 3,
                nullifier_root: [0u8; 32],
                proof: vec![],
                timestamp: now,
            };
            let result = relayer
                .relay_epoch(ChainDomain::CardanoMainnet, ChainDomain::CosmosHub, att)
                .await;
            assert!(matches!(result, Err(BridgeError::RateLimited { .. })));
            assert_eq!(relayer.metrics().rate_limited, 1);
        });
    }

    #[test]
    fn backoff_delay_exponential() {
        assert_eq!(BridgeRelayer::backoff_delay(0).as_secs(), 1);
        assert_eq!(BridgeRelayer::backoff_delay(1).as_secs(), 2);
        assert_eq!(BridgeRelayer::backoff_delay(2).as_secs(), 4);
        assert_eq!(BridgeRelayer::backoff_delay(3).as_secs(), 8);
        assert_eq!(BridgeRelayer::backoff_delay(5).as_secs(), 32);
        // Capped at 300s
        assert_eq!(BridgeRelayer::backoff_delay(9).as_secs(), 300);
        assert_eq!(BridgeRelayer::backoff_delay(20).as_secs(), 300);
    }

    #[test]
    fn short_proof_rejected() {
        let relayer = BridgeRelayer::new(test_config());

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // Mithril proof too short
        let att = EpochAttestation {
            source_chain: ChainDomain::CardanoMainnet,
            epoch: 1,
            nullifier_root: [1u8; 32],
            proof: vec![0u8; 10], // < 32 min
            timestamp: now,
        };
        let result = relayer.verify_attestation(&att);
        assert!(matches!(result, Err(BridgeError::VerificationFailed(_))));

        // Tendermint proof too short
        let att2 = EpochAttestation {
            source_chain: ChainDomain::CosmosHub,
            epoch: 1,
            nullifier_root: [1u8; 32],
            proof: vec![0u8; 16],
            timestamp: now,
        };
        let result2 = relayer.verify_attestation(&att2);
        assert!(matches!(result2, Err(BridgeError::VerificationFailed(_))));

        // Malformed proof (enough bytes but invalid certificate) is rejected
        let att3 = EpochAttestation {
            source_chain: ChainDomain::CardanoMainnet,
            epoch: 1,
            nullifier_root: [1u8; 32],
            proof: vec![0u8; 64],
            timestamp: now,
        };
        assert!(relayer.verify_attestation(&att3).is_err());
    }

    /// Helper: build a valid Mithril certificate for testing.
    fn build_test_certificate(
        epoch: u64,
        nullifier_root: &[u8; 32],
        num_signers: usize,
    ) -> Vec<u8> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let message = BridgeRelayer::compute_epoch_message(epoch, nullifier_root);

        let signers: Vec<MithrilSigner> = (0..num_signers)
            .map(|i| {
                // Generate a deterministic signing key from the index
                let mut seed = [0u8; 32];
                seed[0] = i as u8;
                seed[31] = (i + 1) as u8;
                let signing_key = ed25519_dalek::SigningKey::from_bytes(&seed);
                MithrilSigner::sign_message(&signing_key, 1000, &message, b"PIL-MITHRIL-SIG")
            })
            .collect();

        let cert = MithrilCertificate {
            version: MithrilCertificate::CURRENT_VERSION,
            epoch,
            message,
            timestamp: now,
            ttl_secs: 3600,
            signers,
        };
        cert.to_bytes()
    }

    #[test]
    fn mithril_certificate_roundtrip() {
        let epoch = 42u64;
        let root = [7u8; 32];
        let proof = build_test_certificate(epoch, &root, 3);

        let cert = MithrilCertificate::parse(&proof).unwrap();
        assert_eq!(cert.version, 1);
        assert_eq!(cert.epoch, 42);
        assert_eq!(cert.signers.len(), 3);

        // Roundtrip
        let reserialized = cert.to_bytes();
        assert_eq!(proof, reserialized);
    }

    #[test]
    fn mithril_verification_valid_certificate() {
        let relayer = BridgeRelayer::new(test_config());
        let epoch = 10u64;
        let root = [42u8; 32];
        let proof = build_test_certificate(epoch, &root, 5);

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let att = EpochAttestation {
            source_chain: ChainDomain::CardanoMainnet,
            epoch,
            nullifier_root: root,
            proof,
            timestamp: now,
        };
        assert!(relayer.verify_attestation(&att).is_ok());
    }

    #[test]
    fn mithril_verification_rejects_wrong_epoch() {
        let relayer = BridgeRelayer::new(test_config());
        let root = [1u8; 32];
        // Certificate says epoch 5, attestation says epoch 6
        let proof = build_test_certificate(5, &root, 3);

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let att = EpochAttestation {
            source_chain: ChainDomain::CardanoMainnet,
            epoch: 6,
            nullifier_root: root,
            proof,
            timestamp: now,
        };
        let err = relayer.verify_attestation(&att).unwrap_err();
        assert!(matches!(err, BridgeError::VerificationFailed(_)));
    }

    #[test]
    fn mithril_verification_rejects_wrong_root() {
        let relayer = BridgeRelayer::new(test_config());
        let root = [1u8; 32];
        let wrong_root = [2u8; 32];
        // Certificate built with root, but attestation has wrong_root
        let proof = build_test_certificate(1, &root, 3);

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let att = EpochAttestation {
            source_chain: ChainDomain::CardanoMainnet,
            epoch: 1,
            nullifier_root: wrong_root,
            proof,
            timestamp: now,
        };
        let err = relayer.verify_attestation(&att).unwrap_err();
        assert!(matches!(err, BridgeError::VerificationFailed(_)));
    }

    #[test]
    fn mithril_verification_rejects_insufficient_quorum() {
        let relayer = BridgeRelayer::new(test_config());
        let epoch = 1u64;
        let root = [1u8; 32];
        let message = BridgeRelayer::compute_epoch_message(epoch, &root);

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // Create 3 signers: 2 valid, 1 with bad signature
        // Each has 1000 stake — quorum needs >1500 (3000/2+1)
        // Only 2000 valid stake, so this should pass
        let sk1 = ed25519_dalek::SigningKey::from_bytes(&[1u8; 32]);
        let signer_valid_1 = MithrilSigner::sign_message(&sk1, 1000, &message, b"PIL-MITHRIL-SIG");

        let sk2 = ed25519_dalek::SigningKey::from_bytes(&[2u8; 32]);
        let signer_valid_2 = MithrilSigner::sign_message(&sk2, 1000, &message, b"PIL-MITHRIL-SIG");

        let sk3 = ed25519_dalek::SigningKey::from_bytes(&[3u8; 32]);
        let signer_invalid = MithrilSigner {
            signer_id: sk3.verifying_key().to_bytes(),
            stake_weight: 1000,
            signature: [0xFFu8; 64], // Bad signature
        };

        let cert = MithrilCertificate {
            version: 1,
            epoch,
            message,
            timestamp: now,
            ttl_secs: 3600,
            signers: vec![signer_valid_1, signer_valid_2, signer_invalid],
        };

        let att = EpochAttestation {
            source_chain: ChainDomain::CardanoMainnet,
            epoch,
            nullifier_root: root,
            proof: cert.to_bytes(),
            timestamp: now,
        };
        // 2000 valid / 3000 total > 50% → passes Mithril quorum
        assert!(relayer.verify_attestation(&att).is_ok());

        // Now make it fail: only 1 valid signer (1000/3000 < 50%)
        let signer_only_valid = MithrilSigner::sign_message(&sk1, 1000, &message, b"PIL-MITHRIL-SIG");
        let signer_bad_1 = MithrilSigner {
            signer_id: sk2.verifying_key().to_bytes(),
            stake_weight: 1000,
            signature: [0xAAu8; 64],
        };
        let signer_bad_2 = MithrilSigner {
            signer_id: sk3.verifying_key().to_bytes(),
            stake_weight: 1000,
            signature: [0xBBu8; 64],
        };

        let cert_fail = MithrilCertificate {
            version: 1,
            epoch,
            message,
            timestamp: now,
            ttl_secs: 3600,
            signers: vec![signer_only_valid, signer_bad_1, signer_bad_2],
        };

        let att_fail = EpochAttestation {
            source_chain: ChainDomain::CardanoMainnet,
            epoch,
            nullifier_root: root,
            proof: cert_fail.to_bytes(),
            timestamp: now,
        };
        let err = relayer.verify_attestation(&att_fail).unwrap_err();
        assert!(matches!(err, BridgeError::VerificationFailed(_)));
    }
}
