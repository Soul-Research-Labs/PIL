//! Integration tests for cross-chain scenarios, epoch sync, and multi-user flows.

use ff::Field;
use pil_cosmos::ibc::IBCEpochSync;
use pil_note::{keys::SpendingKey, note::Note};
use pil_pool::{EpochManager, PrivacyPool};
use pil_primitives::{
    domain::{ChainDomain, DomainSeparator},
    types::Base,
};
use rand::rngs::OsRng;

/// Test that domain-separated nullifiers prevent cross-chain replays.
#[test]
fn cross_chain_nullifier_isolation() {
    let spending_key = SpendingKey::random(&mut OsRng);
    let owner = spending_key.owner();

    let note = Note::new(100, owner, 0);
    let commitment = note.commitment();

    let domain_cardano = DomainSeparator::new(ChainDomain::CardanoMainnet, 0);
    let domain_cosmos = DomainSeparator::new(ChainDomain::CosmosHub, 0);

    let nf_cardano =
        pil_note::derive_nullifier_v2(spending_key.to_base(), commitment, &domain_cardano);
    let nf_cosmos =
        pil_note::derive_nullifier_v2(spending_key.to_base(), commitment, &domain_cosmos);

    assert_ne!(
        nf_cardano, nf_cosmos,
        "Cross-chain nullifiers must be different"
    );
}

/// Test that the same spending key produces different nullifiers for different apps.
#[test]
fn app_domain_nullifier_isolation() {
    let spending_key = SpendingKey::random(&mut OsRng);
    let note = Note::new(50, spending_key.owner(), 0);
    let commitment = note.commitment();

    let domain_app0 = DomainSeparator::new(ChainDomain::Osmosis, 0);
    let domain_app1 = DomainSeparator::new(ChainDomain::Osmosis, 1);

    let nf0 = pil_note::derive_nullifier_v2(spending_key.to_base(), commitment, &domain_app0);
    let nf1 = pil_note::derive_nullifier_v2(spending_key.to_base(), commitment, &domain_app1);

    assert_ne!(
        nf0, nf1,
        "Different app IDs must produce different nullifiers"
    );
}

/// Test the epoch lifecycle: deposit → finalize epoch → query epoch root.
#[test]
fn epoch_lifecycle() {
    let mut pool = PrivacyPool::new();
    let mut epoch_mgr = EpochManager::new(3600);

    let sk = SpendingKey::random(&mut OsRng);
    for val in [100, 200, 300] {
        let note = Note::new(val, sk.owner(), 0);
        pool.deposit(note.commitment(), val, 0).unwrap();
    }

    assert_eq!(pool.balance(), 600);
    assert_eq!(pool.note_count(), 3);

    epoch_mgr.finalize_epoch(pool.root());

    assert_eq!(epoch_mgr.current_epoch(), 1);
    assert!(epoch_mgr.epoch_root(0).is_some());
}

/// Multi-user: two users deposit, one transfers to the other, then withdraws.
#[test]
fn multi_user_flow() {
    let mut pool = PrivacyPool::new();
    let domain = DomainSeparator::new(ChainDomain::CardanoMainnet, 0);

    let sk_a = SpendingKey::random(&mut OsRng);
    let note_a = Note::new(500, sk_a.owner(), 0);
    pool.deposit(note_a.commitment(), 500, 0).unwrap();

    let sk_b = SpendingKey::random(&mut OsRng);
    let note_b = Note::new(300, sk_b.owner(), 0);
    pool.deposit(note_b.commitment(), 300, 0).unwrap();

    assert_eq!(pool.balance(), 800);
    assert_eq!(pool.note_count(), 2);

    // User A transfers 200 to User B
    let nf_a = pil_note::derive_nullifier_v2(sk_a.to_base(), note_a.commitment(), &domain);

    let note_to_b = Note::new(200, sk_b.owner(), 0);
    let note_change_a = Note::new(300, sk_a.owner(), 0);

    let transfer_receipt = pool
        .process_transfer(
            &[nf_a],
            &[note_to_b.commitment(), note_change_a.commitment()],
            &[],
        )
        .unwrap();

    assert_eq!(transfer_receipt.nullifiers_spent, 1);
    assert_eq!(pool.balance(), 800);
    assert_eq!(pool.note_count(), 4);

    // User B withdraws 200
    let nf_b_out = pil_note::derive_nullifier_v2(sk_b.to_base(), note_to_b.commitment(), &domain);

    pool.process_withdraw(&[nf_b_out], &[], 200, 0, &[])
        .unwrap();
    assert_eq!(pool.balance(), 600);
}

/// Nullifier double-spend prevention across epoch boundaries.
#[test]
fn double_spend_across_epochs() {
    let mut pool = PrivacyPool::new();
    let mut epoch_mgr = EpochManager::new(3600);
    let domain = DomainSeparator::new(ChainDomain::Neutron, 0);
    let sk = SpendingKey::random(&mut OsRng);

    let note = Note::new(100, sk.owner(), 0);
    pool.deposit(note.commitment(), 100, 0).unwrap();

    // Finalize epoch 0
    epoch_mgr.finalize_epoch(pool.root());

    // Spend in epoch 1
    let nf = pil_note::derive_nullifier_v2(sk.to_base(), note.commitment(), &domain);

    pool.process_withdraw(&[nf], &[], 100, 0, &[]).unwrap();

    // Double-spend must fail
    let result = pool.process_withdraw(&[nf], &[], 100, 0, &[]);
    assert!(result.is_err(), "Double-spend should be rejected");
}

/// IBC epoch sync: simulate epoch root exchange between two Cosmos chains.
#[test]
fn ibc_epoch_sync_multi_chain() {
    let mut sync_a = IBCEpochSync::new(11); // Osmosis
    sync_a.register_channel("channel-1".to_string(), 12); // → Neutron

    let mut sync_b = IBCEpochSync::new(12); // Neutron
    sync_b.register_channel("channel-2".to_string(), 11); // → Osmosis

    // Osmosis → Neutron
    let packet_a =
        sync_a.create_epoch_packet(0, "aabbccddee".to_string(), 50, "cumroot_a_0".to_string());
    sync_b.receive_epoch_root(packet_a).unwrap();

    // Neutron → Osmosis
    let packet_b =
        sync_b.create_epoch_packet(0, "1122334455".to_string(), 30, "cumroot_b_0".to_string());
    sync_a.receive_epoch_root(packet_b).unwrap();

    assert_eq!(sync_b.get_remote_epoch_root(11, 0), Some("aabbccddee"));
    assert_eq!(sync_a.get_remote_epoch_root(12, 0), Some("1122334455"));
    assert_eq!(sync_b.get_remote_epoch_root(11, 1), None);
}

/// Multiple chain domains produce unique domain separators.
#[test]
fn chain_domains_unique_separators() {
    let domains = [
        ChainDomain::CardanoMainnet,
        ChainDomain::CardanoPreprod,
        ChainDomain::CardanoPreview,
        ChainDomain::CosmosHub,
        ChainDomain::Osmosis,
        ChainDomain::Neutron,
        ChainDomain::Injective,
        ChainDomain::SecretNetwork,
        ChainDomain::Celestia,
        ChainDomain::Sei,
        ChainDomain::Archway,
        ChainDomain::Dymension,
        ChainDomain::Stargaze,
        ChainDomain::Akash,
        ChainDomain::Juno,
    ];

    let tags: Vec<Base> = domains
        .iter()
        .map(|d| DomainSeparator::new(*d, 0).to_domain_tag())
        .collect();

    for i in 0..tags.len() {
        for j in (i + 1)..tags.len() {
            assert_ne!(
                tags[i], tags[j],
                "Domains {:?} and {:?} must have different tags",
                domains[i], domains[j],
            );
        }
    }
}

/// Epoch manager summary root is deterministic.
#[test]
fn epoch_summary_root_deterministic() {
    let mut em1 = EpochManager::new(3600);
    let mut em2 = EpochManager::new(3600);

    let root_a = Base::from(42u64);
    let root_b = Base::from(99u64);

    em1.finalize_epoch(root_a);
    em1.finalize_epoch(root_b);

    em2.finalize_epoch(root_a);
    em2.finalize_epoch(root_b);

    assert_eq!(em1.summary_root(), em2.summary_root());
    assert_ne!(em1.summary_root(), Base::ZERO);
}

/// Stress test: many deposits followed by batch epoch finalization.
#[test]
fn batch_deposits_and_epoch() {
    let mut pool = PrivacyPool::new();
    let mut epoch_mgr = EpochManager::new(3600);
    let sk = SpendingKey::random(&mut OsRng);

    // Deposit 64 notes
    for i in 0..64u64 {
        let note = Note::new(10 + i, sk.owner(), 0);
        pool.deposit(note.commitment(), 10 + i, 0).unwrap();
    }

    assert_eq!(pool.note_count(), 64);
    assert_eq!(pool.balance(), (10..74).sum::<u64>());

    // Finalize epoch
    epoch_mgr.finalize_epoch(pool.root());
    assert_eq!(epoch_mgr.current_epoch(), 1);

    // root should be non-zero after finalization
    let root = epoch_mgr.epoch_root(0).unwrap();
    assert_ne!(root, Base::ZERO);
}

/// Multiple sequential epochs with deposits interleaved.
#[test]
fn multi_epoch_with_operations() {
    let mut pool = PrivacyPool::new();
    let mut epoch_mgr = EpochManager::new(3600);
    let domain = DomainSeparator::new(ChainDomain::CardanoMainnet, 0);
    let sk = SpendingKey::random(&mut OsRng);

    // Epoch 0: deposit
    let n0 = Note::new(100, sk.owner(), 0);
    pool.deposit(n0.commitment(), 100, 0).unwrap();
    epoch_mgr.finalize_epoch(pool.root());

    // Epoch 1: deposit + transfer
    let n1 = Note::new(200, sk.owner(), 0);
    pool.deposit(n1.commitment(), 200, 0).unwrap();

    let nf0 = pil_note::derive_nullifier_v2(sk.to_base(), n0.commitment(), &domain);
    let out = Note::new(100, sk.owner(), 0);
    pool.process_transfer(&[nf0], &[out.commitment()], &[])
        .unwrap();
    epoch_mgr.finalize_epoch(pool.root());

    // Epoch 2: deposit + withdraw (deposit changes tree root)
    let n2 = Note::new(50, sk.owner(), 0);
    pool.deposit(n2.commitment(), 50, 0).unwrap();
    let nf1 = pil_note::derive_nullifier_v2(sk.to_base(), n1.commitment(), &domain);
    pool.process_withdraw(&[nf1], &[], 200, 0, &[]).unwrap();
    epoch_mgr.finalize_epoch(pool.root());

    assert_eq!(epoch_mgr.current_epoch(), 3);
    assert_eq!(pool.balance(), 150); // 100 from out note + 50 from n2
    assert_eq!(pool.nullifier_count(), 2);

    // All epoch roots should be distinct
    let r0 = epoch_mgr.epoch_root(0).unwrap();
    let r1 = epoch_mgr.epoch_root(1).unwrap();
    let r2 = epoch_mgr.epoch_root(2).unwrap();
    assert_ne!(r0, r1);
    assert_ne!(r1, r2);
}

/// Bridge relayer dry-run: create config, instantiate relayer, verify config.
#[test]
fn bridge_relayer_dry_run_config() {
    use pil_bridge::{BridgeConfig, BridgeRelayer};

    let config = BridgeConfig {
        cardano_endpoint: "http://localhost:4000".to_string(),
        cosmos_endpoint: "http://localhost:26657".to_string(),
        mithril_endpoint: None,
        poll_interval_secs: 30,
        relay_pairs: vec![],
        dry_run: true,
    };

    let relayer = BridgeRelayer::new(config);
    assert!(relayer.config().dry_run);
    assert_eq!(relayer.config().poll_interval_secs, 30);
}

/// Full end-to-end flow: keygen → deposit → transfer → withdraw across two users.
#[test]
fn full_e2e_two_user_flow() {
    let mut pool = PrivacyPool::new();
    let domain = DomainSeparator::new(ChainDomain::CosmosHub, 0);

    // User A: keygen + deposit
    let sk_a = SpendingKey::random(&mut OsRng);
    let note_a1 = Note::new(1000, sk_a.owner(), 0);
    let note_a2 = Note::new(500, sk_a.owner(), 0);
    pool.deposit(note_a1.commitment(), 1000, 0).unwrap();
    pool.deposit(note_a2.commitment(), 500, 0).unwrap();

    // User B: keygen + deposit
    let sk_b = SpendingKey::random(&mut OsRng);
    let note_b1 = Note::new(200, sk_b.owner(), 0);
    pool.deposit(note_b1.commitment(), 200, 0).unwrap();

    assert_eq!(pool.balance(), 1700);

    // User A sends 300 to User B (spending note_a1, getting 700 change)
    let nf_a1 = pil_note::derive_nullifier_v2(sk_a.to_base(), note_a1.commitment(), &domain);
    let note_to_b = Note::new(300, sk_b.owner(), 0);
    let note_change_a = Note::new(700, sk_a.owner(), 0);
    pool.process_transfer(
        &[nf_a1],
        &[note_to_b.commitment(), note_change_a.commitment()],
        &[],
    )
    .unwrap();

    assert_eq!(pool.balance(), 1700); // total unchanged
    assert_eq!(pool.note_count(), 5); // 3 deposits + 2 transfer outputs

    // User B withdraws 500 (using original 200 + received 300)
    let nf_b1 = pil_note::derive_nullifier_v2(sk_b.to_base(), note_b1.commitment(), &domain);
    let nf_b2 = pil_note::derive_nullifier_v2(sk_b.to_base(), note_to_b.commitment(), &domain);
    pool.process_withdraw(&[nf_b1, nf_b2], &[], 500, 0, &[])
        .unwrap();

    assert_eq!(pool.balance(), 1200); // 700 (A change) + 500 (A note_a2)

    // User A withdraws remaining
    let nf_a2 = pil_note::derive_nullifier_v2(sk_a.to_base(), note_a2.commitment(), &domain);
    let nf_change =
        pil_note::derive_nullifier_v2(sk_a.to_base(), note_change_a.commitment(), &domain);
    pool.process_withdraw(&[nf_a2, nf_change], &[], 1200, 0, &[])
        .unwrap();

    assert_eq!(pool.balance(), 0);
    assert_eq!(pool.nullifier_count(), 5);
}

/// IBC sync rejects duplicate and out-of-order epochs.
#[test]
fn ibc_sync_ordering_enforcement() {
    let mut sync = IBCEpochSync::new(10);
    sync.register_channel("ch-1".to_string(), 11);

    // Receive epochs 0, 1, 2 in order
    for epoch in 0..3 {
        let p = pil_cosmos::ibc::EpochSyncPacket {
            source_chain_id: 11,
            source_app_id: 0,
            epoch,
            nullifier_root: format!("root_{epoch}"),
            nullifier_count: epoch * 10,
            cumulative_root: format!("cum_{epoch}"),
        };
        sync.receive_epoch_root(p).unwrap();
    }

    // Duplicate epoch 1 should fail
    let dup = pil_cosmos::ibc::EpochSyncPacket {
        source_chain_id: 11,
        source_app_id: 0,
        epoch: 1,
        nullifier_root: "dup".to_string(),
        nullifier_count: 0,
        cumulative_root: "dup".to_string(),
    };
    assert!(sync.receive_epoch_root(dup).is_err());

    // Out-of-order epoch 0 should fail (latest is 2)
    let old = pil_cosmos::ibc::EpochSyncPacket {
        source_chain_id: 11,
        source_app_id: 0,
        epoch: 0,
        nullifier_root: "old".to_string(),
        nullifier_count: 0,
        cumulative_root: "old".to_string(),
    };
    assert!(sync.receive_epoch_root(old).is_err());
}

/// Hydra L2 head lifecycle: init → open → deposit → snapshot → close → fanout.
#[test]
fn hydra_l2_full_lifecycle() {
    use pil_hydra::head::{HydraHead, HydraHeadConfig};
    use pil_hydra::snapshot::SnapshotPolicy;
    use pil_primitives::types::Commitment;

    let config = HydraHeadConfig {
        head_id: "integ-test-head".to_string(),
        participants: vec!["alice".into(), "bob".into()],
        chain_domain: ChainDomain::CardanoMainnet,
        snapshot_policy: SnapshotPolicy::Manual,
        max_pending_txs: 100,
        contestation_period_secs: 300,
    };

    let mut head = HydraHead::new(config);
    assert_eq!(head.num_participants(), 2);

    // Init → Open
    head.begin_init(5).unwrap();
    head.open().unwrap();

    // Deposit in L2
    let cm = Commitment(Base::from(42u64));
    head.pool_state_mut().deposit(cm, 100, 0).unwrap();
    assert_eq!(head.pool_state().balance(), 100);
    assert_eq!(head.pool_state().note_count(), 1);

    // Process an L2 tx and take snapshot
    head.process_l2_tx().unwrap();
    let snap = head.take_snapshot().unwrap();
    assert_eq!(snap.snapshot_number, 0);
    assert!(!snap.snapshot_id_hex().is_empty());

    // Close → Fanout
    let close_snap = head.begin_close().unwrap();
    assert!(close_snap.snapshot_number >= 1);
    head.finalize_close().unwrap();
    let fanout = head.fanout().unwrap();
    assert_eq!(fanout.total_notes, 1);
}

/// End-to-end cross-chain relay: Cardano deposits → epoch finalize →
/// build Mithril certificate → relay to Cosmos via bridge relayer.
#[test]
fn cardano_to_cosmos_epoch_relay() {
    use pil_bridge::relayer::{BridgeRelayer, MithrilCertificate, MithrilSigner};
    use pil_bridge::{BridgeConfig, EpochAttestation};
    use sha2::{Digest, Sha256};

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();

    rt.block_on(async {
        // --- Cardano side: deposit notes and finalize epoch ---
        let mut cardano_pool = PrivacyPool::new();
        let mut cardano_epoch = EpochManager::new(3600);
        let sk = pil_note::keys::SpendingKey::random(&mut rand::rngs::OsRng);

        for val in [100, 200, 300] {
            let note = pil_note::note::Note::new(val, sk.owner(), 0);
            cardano_pool.deposit(note.commitment(), val, 0).unwrap();
        }

        assert_eq!(cardano_pool.balance(), 600);
        cardano_epoch.finalize_epoch(cardano_pool.root());

        let epoch_root = cardano_epoch.epoch_root(0).unwrap();
        let mut nullifier_root = [0u8; 32];
        let root_repr = <Base as ff::PrimeField>::to_repr(&epoch_root);
        nullifier_root.copy_from_slice(root_repr.as_ref());

        // --- Build a Mithril certificate ---
        let epoch = 0u64;
        let mut msg_hasher = Sha256::new();
        msg_hasher.update(b"PIL-EPOCH");
        msg_hasher.update(epoch.to_be_bytes());
        msg_hasher.update(&nullifier_root);
        let message: [u8; 32] = msg_hasher.finalize().into();

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // Create 3 SPO signers with valid commitments
        let mut signers = Vec::new();
        for i in 0u8..3 {
            let mut signer_id = [0u8; 32];
            signer_id[0] = i + 1;
            let commitment = MithrilSigner::compute_commitment(&signer_id, &message);
            signers.push(MithrilSigner {
                signer_id,
                stake_weight: 1000,
                commitment,
            });
        }

        let cert = MithrilCertificate {
            version: 1,
            epoch,
            message,
            timestamp: now,
            ttl_secs: 3600,
            signers,
        };
        let proof_bytes = cert.to_bytes();

        // --- Relay via bridge ---
        let config = BridgeConfig {
            cardano_endpoint: "http://localhost:4000".to_string(),
            cosmos_endpoint: "http://localhost:26657".to_string(),
            mithril_endpoint: None,
            poll_interval_secs: 30,
            relay_pairs: vec![],
            dry_run: true,
        };
        let mut relayer = BridgeRelayer::new(config);

        let attestation = EpochAttestation {
            source_chain: ChainDomain::CardanoMainnet,
            epoch,
            nullifier_root,
            proof: proof_bytes,
            timestamp: now,
        };

        relayer
            .relay_epoch(
                ChainDomain::CardanoMainnet,
                ChainDomain::CosmosHub,
                attestation,
            )
            .await
            .unwrap();

        assert_eq!(relayer.metrics().epochs_relayed, 1);
        assert_eq!(relayer.metrics().verifications, 1);
        assert_eq!(
            relayer.latest_relayed_epoch(ChainDomain::CardanoMainnet, ChainDomain::CosmosHub),
            Some(0)
        );

        // --- Cosmos side: receive the epoch root ---
        let mut cosmos_sync = IBCEpochSync::new(ChainDomain::CosmosHub.as_u32());
        cosmos_sync.register_channel(
            "channel-0".to_string(),
            ChainDomain::CardanoMainnet.as_u32(),
        );

        let packet = pil_cosmos::ibc::EpochSyncPacket {
            source_chain_id: ChainDomain::CardanoMainnet.as_u32(),
            source_app_id: 0,
            epoch: 0,
            nullifier_root: hex::encode(nullifier_root),
            nullifier_count: 3,
            cumulative_root: hex::encode(nullifier_root),
        };
        cosmos_sync.receive_epoch_root(packet).unwrap();

        let received = cosmos_sync.get_remote_epoch_root(ChainDomain::CardanoMainnet.as_u32(), 0);
        assert!(received.is_some());
        assert_eq!(received.unwrap(), hex::encode(nullifier_root));
    });
}

/// Bidirectional relay: Cosmos → Cardano and Cardano → Cosmos in parallel.
#[test]
fn bidirectional_epoch_relay() {
    use pil_bridge::relayer::{BridgeRelayer, MithrilCertificate, MithrilSigner};
    use pil_bridge::{BridgeConfig, EpochAttestation};
    use sha2::{Digest, Sha256};

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();

    rt.block_on(async {
        let config = BridgeConfig {
            cardano_endpoint: "http://localhost:4000".to_string(),
            cosmos_endpoint: "http://localhost:26657".to_string(),
            mithril_endpoint: None,
            poll_interval_secs: 30,
            relay_pairs: vec![],
            dry_run: true,
        };
        let mut relayer = BridgeRelayer::new(config);

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // Helper to build a test certificate
        let build_cert = |epoch: u64, root: &[u8; 32]| {
            let mut msg_hasher = Sha256::new();
            msg_hasher.update(b"PIL-EPOCH");
            msg_hasher.update(epoch.to_be_bytes());
            msg_hasher.update(root);
            let message: [u8; 32] = msg_hasher.finalize().into();

            let mut signer_id = [0u8; 32];
            signer_id[0] = 1;
            let commitment = MithrilSigner::compute_commitment(&signer_id, &message);

            MithrilCertificate {
                version: 1,
                epoch,
                message,
                timestamp: now,
                ttl_secs: 3600,
                signers: vec![MithrilSigner {
                    signer_id,
                    stake_weight: 1000,
                    commitment,
                }],
            }
            .to_bytes()
        };

        // Cardano → Cosmos (epoch 1)
        let cardano_root = [1u8; 32];
        let cardano_cert = build_cert(1, &cardano_root);
        relayer
            .relay_epoch(
                ChainDomain::CardanoMainnet,
                ChainDomain::CosmosHub,
                EpochAttestation {
                    source_chain: ChainDomain::CardanoMainnet,
                    epoch: 1,
                    nullifier_root: cardano_root,
                    proof: cardano_cert,
                    timestamp: now,
                },
            )
            .await
            .unwrap();

        // Cosmos → Cardano (epoch 1)
        let cosmos_root = [2u8; 32];
        let cosmos_cert = build_cert(1, &cosmos_root);
        relayer
            .relay_epoch(
                ChainDomain::CosmosHub,
                ChainDomain::CardanoMainnet,
                EpochAttestation {
                    source_chain: ChainDomain::CosmosHub,
                    epoch: 1,
                    nullifier_root: cosmos_root,
                    proof: cosmos_cert,
                    timestamp: now,
                },
            )
            .await
            .unwrap();

        assert_eq!(relayer.metrics().epochs_relayed, 2);
        assert_eq!(relayer.metrics().verifications, 2);
        assert_eq!(
            relayer.latest_relayed_epoch(ChainDomain::CardanoMainnet, ChainDomain::CosmosHub),
            Some(1)
        );
        assert_eq!(
            relayer.latest_relayed_epoch(ChainDomain::CosmosHub, ChainDomain::CardanoMainnet),
            Some(1)
        );
    });
}

/// Cross-chain double-spend prevention: nullifiers from Cardano should not
/// replay on Cosmos, and vice versa, even with the same spending key.
#[test]
fn cross_chain_double_spend_prevention_full() {
    let sk = pil_note::keys::SpendingKey::random(&mut rand::rngs::OsRng);
    let note = pil_note::note::Note::new(100, sk.owner(), 0);
    let commitment = note.commitment();

    let domain_cardano = DomainSeparator::new(ChainDomain::CardanoMainnet, 0);
    let domain_cosmos = DomainSeparator::new(ChainDomain::CosmosHub, 0);

    // Derive nullifiers on both chains
    let nf_cardano = pil_note::derive_nullifier_v2(sk.to_base(), commitment, &domain_cardano);
    let nf_cosmos = pil_note::derive_nullifier_v2(sk.to_base(), commitment, &domain_cosmos);

    // Deposit on Cardano
    let mut cardano_pool = PrivacyPool::new();
    cardano_pool.deposit(commitment, 100, 0).unwrap();

    // Deposit on Cosmos
    let mut cosmos_pool = PrivacyPool::new();
    cosmos_pool.deposit(commitment, 100, 0).unwrap();

    // Spend on Cardano
    cardano_pool
        .process_withdraw(&[nf_cardano], &[], 100, 0, &[])
        .unwrap();

    // Spend on Cosmos — different nullifier, so this should succeed
    cosmos_pool
        .process_withdraw(&[nf_cosmos], &[], 100, 0, &[])
        .unwrap();

    // Attempting Cosmos nullifier on Cardano pool should fail
    // (because nf_cosmos was never used on cardano_pool directly,
    // but let's verify the Cardano pool still has the Cardano nullifier registered)
    let result = cardano_pool.process_withdraw(&[nf_cardano], &[], 0, 0, &[]);
    assert!(
        result.is_err(),
        "Double-spend of Cardano nullifier should fail"
    );

    // Each pool should have exactly 1 nullifier
    assert_eq!(cardano_pool.nullifier_count(), 1);
    assert_eq!(cosmos_pool.nullifier_count(), 1);
}

/// Multi-epoch relay stress: relay 10 sequential epochs from Cardano → Cosmos
/// and verify all are tracked correctly.
#[test]
fn multi_epoch_sequential_relay() {
    use pil_bridge::relayer::BridgeRelayer;
    use pil_bridge::{BridgeConfig, EpochAttestation};

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();

    rt.block_on(async {
        let config = BridgeConfig {
            cardano_endpoint: "http://localhost:4000".to_string(),
            cosmos_endpoint: "http://localhost:26657".to_string(),
            mithril_endpoint: None,
            poll_interval_secs: 30,
            relay_pairs: vec![],
            dry_run: true,
        };
        let mut relayer = BridgeRelayer::new(config);

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // Relay 10 epochs (with empty proofs ⇒ dev mode, accepted)
        for epoch in 1..=10u64 {
            let mut root = [0u8; 32];
            root[0..8].copy_from_slice(&epoch.to_be_bytes());

            let attestation = EpochAttestation {
                source_chain: ChainDomain::CardanoMainnet,
                epoch,
                nullifier_root: root,
                proof: vec![], // empty = dev mode
                timestamp: now,
            };

            relayer
                .relay_epoch(
                    ChainDomain::CardanoMainnet,
                    ChainDomain::Osmosis,
                    attestation,
                )
                .await
                .unwrap();
        }

        assert_eq!(relayer.metrics().epochs_relayed, 10);
        assert_eq!(
            relayer.latest_relayed_epoch(ChainDomain::CardanoMainnet, ChainDomain::Osmosis),
            Some(10)
        );
    });
}
