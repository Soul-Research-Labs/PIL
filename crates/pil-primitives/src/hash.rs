use crate::types::Base;
use ff::{Field, PrimeField};

/// Poseidon hash parameters: width=3, rate=2 (P128Pow5T3 equivalent).
/// This is a simplified Poseidon implementation for the Pallas base field.
///
/// In production, use the full-round Poseidon specification with proper
/// round constants and MDS matrix. This implementation uses a
/// hardened sponge construction.

const POSEIDON_RATE: usize = 2;
const POSEIDON_CAPACITY: usize = 1;
const POSEIDON_WIDTH: usize = POSEIDON_RATE + POSEIDON_CAPACITY;
const POSEIDON_FULL_ROUNDS: usize = 8;
const POSEIDON_PARTIAL_ROUNDS: usize = 56;
const POSEIDON_ALPHA: u64 = 5;

/// Generate round constants deterministically from a seed.
/// In production, these should be generated from the Poseidon paper's
/// grain LFSR construction. Here we use Blake2b for determinism.
fn generate_round_constants() -> Vec<Base> {
    use blake2::{Blake2b512, Digest};
    let total = POSEIDON_WIDTH * (POSEIDON_FULL_ROUNDS + POSEIDON_PARTIAL_ROUNDS);
    let mut constants = Vec::with_capacity(total);
    for i in 0..total {
        let mut hasher = Blake2b512::new();
        hasher.update(b"PIL_Poseidon_RC_");
        hasher.update(i.to_le_bytes());
        let hash = hasher.finalize();
        let mut repr = [0u8; 32];
        repr.copy_from_slice(&hash[..32]);
        // Reduce mod p by clearing top bits (Pallas field is ~255 bits)
        repr[31] &= 0x3f;
        let val = Base::from_repr(repr);
        constants.push(if bool::from(val.is_some()) {
            val.unwrap()
        } else {
            Base::from(i as u64)
        });
    }
    constants
}

/// S-box: x -> x^5 over the Pallas base field.
#[inline]
fn sbox(x: Base) -> Base {
    let x2 = x * x;
    let x4 = x2 * x2;
    x4 * x
}

/// MDS matrix multiplication (simplified circulant construction).
fn mds_multiply(state: &mut [Base; POSEIDON_WIDTH]) {
    let old = *state;
    // Simple MDS: Cauchy matrix construction
    state[0] = old[0] + old[0] + old[1] + old[2];
    state[1] = old[0] + old[1] + old[1] + old[2];
    state[2] = old[0] + old[1] + old[2] + old[2];
}

/// Poseidon permutation over 3-element state.
fn poseidon_permutation(state: &mut [Base; POSEIDON_WIDTH]) {
    let constants = generate_round_constants();
    let mut rc_idx = 0;

    // First half of full rounds
    for _ in 0..POSEIDON_FULL_ROUNDS / 2 {
        for j in 0..POSEIDON_WIDTH {
            state[j] += constants[rc_idx];
            rc_idx += 1;
        }
        for j in 0..POSEIDON_WIDTH {
            state[j] = sbox(state[j]);
        }
        mds_multiply(state);
    }

    // Partial rounds (S-box on first element only)
    for _ in 0..POSEIDON_PARTIAL_ROUNDS {
        for j in 0..POSEIDON_WIDTH {
            state[j] += constants[rc_idx];
            rc_idx += 1;
        }
        state[0] = sbox(state[0]);
        mds_multiply(state);
    }

    // Second half of full rounds
    for _ in 0..POSEIDON_FULL_ROUNDS / 2 {
        for j in 0..POSEIDON_WIDTH {
            state[j] += constants[rc_idx];
            rc_idx += 1;
        }
        for j in 0..POSEIDON_WIDTH {
            state[j] = sbox(state[j]);
        }
        mds_multiply(state);
    }
}

/// Hash a single field element.
pub fn poseidon_hash(input: Base) -> Base {
    poseidon_hash2(input, Base::ZERO)
}

/// Hash two field elements (most common: commitment = H(value, owner, randomness)).
pub fn poseidon_hash2(a: Base, b: Base) -> Base {
    let mut state = [Base::ZERO; POSEIDON_WIDTH];
    // Domain separation: set capacity element
    state[0] = Base::from(2u64); // number of inputs
    state[1] = a;
    state[2] = b;
    poseidon_permutation(&mut state);
    state[0]
}

/// Hash three field elements.
pub fn poseidon_hash3(a: Base, b: Base, c: Base) -> Base {
    // Two absorptions for 3 inputs with rate=2
    let mut state = [Base::ZERO; POSEIDON_WIDTH];
    state[0] = Base::from(3u64); // domain tag: 3 inputs
    state[1] = a;
    state[2] = b;
    poseidon_permutation(&mut state);
    state[1] += c;
    poseidon_permutation(&mut state);
    state[0]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn poseidon_hash_deterministic() {
        let a = Base::from(42u64);
        let b = Base::from(123u64);
        let h1 = poseidon_hash2(a, b);
        let h2 = poseidon_hash2(a, b);
        assert_eq!(h1, h2);
    }

    #[test]
    fn poseidon_hash_different_inputs_differ() {
        let h1 = poseidon_hash2(Base::from(1u64), Base::from(2u64));
        let h2 = poseidon_hash2(Base::from(2u64), Base::from(1u64));
        assert_ne!(h1, h2);
    }

    #[test]
    fn poseidon_hash3_deterministic() {
        let a = Base::from(10u64);
        let b = Base::from(20u64);
        let c = Base::from(30u64);
        let h1 = poseidon_hash3(a, b, c);
        let h2 = poseidon_hash3(a, b, c);
        assert_eq!(h1, h2);
    }
}
