//! Core performance benchmarks for PIL operations.
//!
//! Run with: `cargo bench --package pil-benchmarks`

use criterion::{criterion_group, criterion_main, BatchSize, Criterion};
use ff::Field;
use pasta_curves::pallas;
use rand::rngs::OsRng;

use pil_note::keys::SpendingKey;
use pil_note::note::Note;
use pil_note::{derive_nullifier_v1, derive_nullifier_v2};
use pil_pool::{EpochManager, PrivacyPool};
use pil_primitives::commitment::pedersen_commit;
use pil_primitives::domain::{ChainDomain, DomainSeparator};
use pil_primitives::hash::poseidon_hash;
use pil_tree::IncrementalMerkleTree;

fn bench_poseidon_hash(c: &mut Criterion) {
    let a = pallas::Base::random(OsRng);

    c.bench_function("poseidon_hash", |bench| bench.iter(|| poseidon_hash(a)));
}

fn bench_pedersen_commit(c: &mut Criterion) {
    let value = pallas::Scalar::random(OsRng);
    let blinding = pallas::Scalar::random(OsRng);

    c.bench_function("pedersen_commit", |bench| {
        bench.iter(|| pedersen_commit(value, blinding))
    });
}

fn bench_note_commitment(c: &mut Criterion) {
    let sk = SpendingKey::random(&mut OsRng);
    let note = Note::new(500, sk.owner(), 0);

    c.bench_function("note_commitment", |bench| bench.iter(|| note.commitment()));
}

fn bench_nullifier_v1(c: &mut Criterion) {
    let sk = SpendingKey::random(&mut OsRng);
    let note = Note::new(100, sk.owner(), 0);
    let commitment = note.commitment();

    c.bench_function("derive_nullifier_v1", |bench| {
        bench.iter(|| derive_nullifier_v1(sk.to_base(), commitment))
    });
}

fn bench_nullifier_v2(c: &mut Criterion) {
    let sk = SpendingKey::random(&mut OsRng);
    let note = Note::new(100, sk.owner(), 0);
    let commitment = note.commitment();
    let domain = DomainSeparator::new(ChainDomain::CardanoMainnet, 0);

    c.bench_function("derive_nullifier_v2_domain_separated", |bench| {
        bench.iter(|| derive_nullifier_v2(sk.to_base(), commitment, &domain))
    });
}

fn bench_merkle_tree_append(c: &mut Criterion) {
    c.bench_function("merkle_tree_append_1", |bench| {
        bench.iter_batched(
            || {
                let tree = IncrementalMerkleTree::new();
                let leaf = pallas::Base::random(OsRng);
                (tree, leaf)
            },
            |(mut tree, leaf)| tree.append(leaf).unwrap(),
            BatchSize::SmallInput,
        )
    });
}

fn bench_merkle_tree_100_appends(c: &mut Criterion) {
    c.bench_function("merkle_tree_100_appends", |bench| {
        bench.iter(|| {
            let mut tree = IncrementalMerkleTree::new();
            for _ in 0..100 {
                tree.append(pallas::Base::random(OsRng)).unwrap();
            }
            tree.root()
        })
    });
}

fn bench_merkle_auth_path(c: &mut Criterion) {
    let mut tree = IncrementalMerkleTree::new();
    for _ in 0..100 {
        tree.append(pallas::Base::random(OsRng)).unwrap();
    }

    c.bench_function("merkle_auth_path_100_leaves", |bench| {
        bench.iter(|| tree.authentication_path(50).unwrap())
    });
}

fn bench_merkle_path_verify(c: &mut Criterion) {
    let mut tree = IncrementalMerkleTree::new();
    let leaf = pallas::Base::random(OsRng);
    tree.append(leaf).unwrap();
    for _ in 0..99 {
        tree.append(pallas::Base::random(OsRng)).unwrap();
    }
    let path = tree.authentication_path(0).unwrap();
    let root = tree.root();

    c.bench_function("merkle_path_verify", |bench| {
        bench.iter(|| path.verify(leaf, root))
    });
}

fn bench_pool_deposit(c: &mut Criterion) {
    c.bench_function("pool_deposit", |bench| {
        bench.iter_batched(
            || {
                let pool = PrivacyPool::new();
                let sk = SpendingKey::random(&mut OsRng);
                let note = Note::new(100, sk.owner(), 0);
                (pool, note.commitment())
            },
            |(mut pool, commitment)| pool.deposit(commitment, 100, 0).unwrap(),
            BatchSize::SmallInput,
        )
    });
}

fn bench_epoch_finalize(c: &mut Criterion) {
    c.bench_function("epoch_finalize", |bench| {
        bench.iter_batched(
            || {
                let em = EpochManager::new(3600);
                let root = pallas::Base::random(OsRng);
                (em, root)
            },
            |(mut em, root)| em.finalize_epoch(root),
            BatchSize::SmallInput,
        )
    });
}

fn bench_domain_separator(c: &mut Criterion) {
    c.bench_function("domain_separator_to_tag", |bench| {
        let sep = DomainSeparator::new(ChainDomain::CardanoMainnet, 42);
        bench.iter(|| sep.to_domain_tag())
    });
}

criterion_group!(
    benches,
    bench_poseidon_hash,
    bench_pedersen_commit,
    bench_note_commitment,
    bench_nullifier_v1,
    bench_nullifier_v2,
    bench_merkle_tree_append,
    bench_merkle_tree_100_appends,
    bench_merkle_auth_path,
    bench_merkle_path_verify,
    bench_pool_deposit,
    bench_epoch_finalize,
    bench_domain_separator,
);

criterion_main!(benches);
