//! # pil-primitives
//!
//! Core cryptographic primitives for the Privacy Interoperability Layer.
//!
//! Provides Poseidon hashing, Pedersen commitments, field type aliases,
//! fixed-size proof envelopes, and domain separation utilities used
//! across all PIL crates.

pub mod commitment;
pub mod domain;
pub mod envelope;
pub mod hash;
pub mod types;

pub use commitment::{pedersen_commit, PedersenCommitment};
pub use domain::{ChainDomain, DomainSeparator};
pub use envelope::ProofEnvelope;
pub use hash::{poseidon_hash, poseidon_hash2, poseidon_hash3};
pub use types::{Base, Commitment, Nullifier, Scalar};
