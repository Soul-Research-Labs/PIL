use ff::Field;
use pasta_curves::pallas;
use pil_primitives::{
    hash::{poseidon_hash2, poseidon_hash3},
    types::{Base, Commitment},
};

/// A private note in the PIL privacy pool.
///
/// Notes are the fundamental unit of value in the shielded pool. Each note
/// commits to a value, owner, asset ID, and randomness. The commitment is
/// stored in the on-chain Merkle tree; the preimage is known only to the owner.
#[derive(Debug, Clone)]
pub struct Note {
    /// The value stored in this note.
    pub value: u64,
    /// The owner's identity (derived from their spending key).
    pub owner: Base,
    /// Asset identifier (0 = native token, others = wrapped assets).
    pub asset_id: u64,
    /// Random blinding factor for the commitment.
    pub randomness: Base,
}

impl Note {
    /// Create a new note.
    pub fn new(value: u64, owner: Base, asset_id: u64) -> Self {
        let mut rng = rand::thread_rng();
        Self {
            value,
            owner,
            asset_id,
            randomness: Base::random(&mut rng),
        }
    }

    /// Create a note with a specific randomness (for deterministic testing).
    pub fn with_randomness(value: u64, owner: Base, asset_id: u64, randomness: Base) -> Self {
        Self {
            value,
            owner,
            asset_id,
            randomness,
        }
    }

    /// Compute the note commitment: Poseidon(value, owner, H(asset_id, randomness)).
    pub fn commitment(&self) -> Commitment {
        let inner = poseidon_hash2(Base::from(self.asset_id), self.randomness);
        let cm = poseidon_hash3(Base::from(self.value), self.owner, inner);
        Commitment(cm)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn note_commitment_deterministic() {
        let owner = Base::from(0xDEADu64);
        let randomness = Base::from(42u64);
        let note = Note::with_randomness(100, owner, 0, randomness);
        let cm1 = note.commitment();
        let cm2 = note.commitment();
        assert_eq!(cm1, cm2);
    }

    #[test]
    fn different_values_different_commitments() {
        let owner = Base::from(0xBEEFu64);
        let randomness = Base::from(99u64);
        let n1 = Note::with_randomness(100, owner, 0, randomness);
        let n2 = Note::with_randomness(200, owner, 0, randomness);
        assert_ne!(n1.commitment(), n2.commitment());
    }
}
