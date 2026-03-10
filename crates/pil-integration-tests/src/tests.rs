//! Integration tests for cross-chain scenarios, epoch sync, and multi-user flows.

use pil_primitives::{
    domain::{ChainDomain, DomainSeparator},
    types::Base,
};
use pil_pool::{PrivacyPool, EpochManager};
use pil_note::{keys::SpendingKey, note::Note};
use pil_cosmos::ibc::IBCEpochSync;
use ff::Field;
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

    let nf_cardano = pil_note::derive_nullifier_v2(
        spending_key.to_base(),
        commitment,
        &domain_cardano,
    );
    let nf_cosmos = pil_note::derive_nullifier_v2(
        spending_key.to_base(),
        commitment,
        &domain_cosmos,
    );

    assert_ne!(nf_cardano, nf_cosmos, "Cross-chain nullifiers must be different");
}

/// Test that the same spending key produces different nullifiers for different apps.
#[test]
fn app_domain_nullifier_isolation() {
    let spending_key = SpendingKey::random(&mut OsRng);
    let note = Note::new(50, spending_key.owner(), 0);
    let commitment = note.commitment();

    let domain_app0 = DomainSeparator::new(ChainDomain::Osmosis, 0);
    let domain_app1 = DomainSeparator::new(ChainDomain::Osmosis, 1);

    let nf0 = pil_note::derive_nullifier_v2(
        spending_key.to_base(),
        commitment,
        &domain_app0,
    );
    let nf1 = pil_note::derive_nullifier_v2(
        spending_key.to_base(),
        commitment,
        &domain_app1,
    );

    assert_ne!(nf0, nf1, "Different app IDs must produce different nullifiers");
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
    let nf_a = pil_note::derive_nullifier_v2(
        sk_a.to_base(),
        note_a.commitment(),
        &domain,
    );

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
    let nf_b_out = pil_note::derive_nullifier_v2(
        sk_b.to_base(),
        note_to_b.commitment(),
        &domain,
    );

    pool.process_withdraw(&[nf_b_out], &[], 200, 0, &[]).unwrap();
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
    let nf = pil_note::derive_nullifier_v2(
        sk.to_base(),
        note.commitment(),
        &domain,
    );

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
    let packet_a = sync_a.create_epoch_packet(
        0,
        "aabbccddee".to_string(),
        50,
        "cumroot_a_0".to_string(),
    );
    sync_b.receive_epoch_root(packet_a).unwrap();

    // Neutron → Osmosis
    let packet_b = sync_b.create_epoch_packet(
        0,
        "1122334455".to_string(),
        30,
        "cumroot_b_0".to_string(),
    );
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
                tags[i],
                tags[j],
                "Domains {:?} and {:?} must have different tags",
                domains[i],
                domains[j],
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
