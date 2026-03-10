//! # pil-note
//!
//! Note model, keys, encryption, stealth addresses, and nullifier derivation.
//!
//! A **Note** represents a private UTXO in the PIL privacy pool. Each note
//! contains a value, an owner, an asset ID, and randomness used for hiding.
//! Notes are committed to the Merkle tree and spent by revealing nullifiers.

pub mod encryption;
pub mod keys;
pub mod note;
pub mod nullifier;
pub mod stealth;

pub use keys::{SpendingKey, ViewingKey};
pub use note::Note;
pub use nullifier::{derive_nullifier_v1, derive_nullifier_v2};
pub use stealth::{StealthAddress, StealthMeta};
