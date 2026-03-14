use crate::types::Base;
use ff::{Field, PrimeField};
use std::sync::OnceLock;

/// Poseidon hash parameters: width=3, rate=2 (P128Pow5T3 equivalent).
///
/// Uses a proper Cauchy MDS matrix and Blake2b-derived round constants
/// for the Pallas base field, following the specification from
/// Grassi et al. "Poseidon: A New Hash Function for Zero-Knowledge
/// Proof Systems" (USENIX Security 2021).
pub const POSEIDON_RATE: usize = 2;
pub const POSEIDON_CAPACITY: usize = 1;
pub const POSEIDON_WIDTH: usize = POSEIDON_RATE + POSEIDON_CAPACITY;
pub const POSEIDON_FULL_ROUNDS: usize = 8;
pub const POSEIDON_PARTIAL_ROUNDS: usize = 56;

/// Generate round constants deterministically using a domain-separated
/// Blake2b hash. Each constant is derived from the domain tag
/// "PIL_Poseidon_RC_" concatenated with the constant index in
/// little-endian encoding.
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

/// Cached round constants — computed once and reused across all hash calls.
static ROUND_CONSTANTS: OnceLock<Vec<Base>> = OnceLock::new();

/// Cached MDS matrix — computed once and reused across all hash calls.
static MDS_MATRIX: OnceLock<[[Base; POSEIDON_WIDTH]; POSEIDON_WIDTH]> = OnceLock::new();

fn cached_round_constants() -> &'static Vec<Base> {
    ROUND_CONSTANTS.get_or_init(generate_round_constants)
}

fn cached_mds_matrix() -> &'static [[Base; POSEIDON_WIDTH]; POSEIDON_WIDTH] {
    MDS_MATRIX.get_or_init(mds_matrix)
}

/// Public access to round constants for in-circuit Poseidon.
pub fn round_constants() -> &'static Vec<Base> {
    cached_round_constants()
}

/// Public access to MDS matrix for in-circuit Poseidon.
pub fn mds() -> &'static [[Base; POSEIDON_WIDTH]; POSEIDON_WIDTH] {
    cached_mds_matrix()
}

/// S-box: x -> x^5 over the Pallas base field.
#[inline]
fn sbox(x: Base) -> Base {
    let x2 = x * x;
    let x4 = x2 * x2;
    x4 * x
}

/// Cauchy MDS matrix for width-3 Poseidon.
///
/// Derived from distinct vectors x = [0,1,2] and y = [3,4,5] as field
/// elements, giving M[i][j] = 1 / (x_i + y_j). This guarantees all
/// square sub-matrices are invertible (Maximum Distance Separable),
/// which is the essential security property for Poseidon diffusion.
fn mds_matrix() -> [[Base; POSEIDON_WIDTH]; POSEIDON_WIDTH] {
    let mut m = [[Base::ZERO; POSEIDON_WIDTH]; POSEIDON_WIDTH];
    for i in 0..POSEIDON_WIDTH {
        for j in 0..POSEIDON_WIDTH {
            // x_i + y_j where x = {0,1,2}, y = {t, t+1, t+2}, t = width = 3
            let sum = Base::from((i + POSEIDON_WIDTH + j) as u64);
            // M[i][j] = (x_i + y_j)^{-1} mod p
            m[i][j] = sum.invert().unwrap();
        }
    }
    m
}

/// MDS matrix multiplication using cached Cauchy construction.
fn mds_multiply(state: &mut [Base; POSEIDON_WIDTH]) {
    let m = cached_mds_matrix();
    let old = *state;
    for i in 0..POSEIDON_WIDTH {
        state[i] = Base::ZERO;
        for j in 0..POSEIDON_WIDTH {
            state[i] += m[i][j] * old[j];
        }
    }
}

/// Poseidon permutation over 3-element state.
fn poseidon_permutation(state: &mut [Base; POSEIDON_WIDTH]) {
    let constants = cached_round_constants();
    let mut rc_idx = 0;

    // First half of full rounds
    for _ in 0..POSEIDON_FULL_ROUNDS / 2 {
        for (j, c) in constants[rc_idx..rc_idx + POSEIDON_WIDTH]
            .iter()
            .enumerate()
        {
            state[j] += c;
        }
        rc_idx += POSEIDON_WIDTH;
        for s in state.iter_mut() {
            *s = sbox(*s);
        }
        mds_multiply(state);
    }

    // Partial rounds (S-box on first element only)
    for _ in 0..POSEIDON_PARTIAL_ROUNDS {
        for (j, c) in constants[rc_idx..rc_idx + POSEIDON_WIDTH]
            .iter()
            .enumerate()
        {
            state[j] += c;
        }
        rc_idx += POSEIDON_WIDTH;
        state[0] = sbox(state[0]);
        mds_multiply(state);
    }

    // Second half of full rounds
    for _ in 0..POSEIDON_FULL_ROUNDS / 2 {
        for (j, c) in constants[rc_idx..rc_idx + POSEIDON_WIDTH]
            .iter()
            .enumerate()
        {
            state[j] += c;
        }
        rc_idx += POSEIDON_WIDTH;
        for s in state.iter_mut() {
            *s = sbox(*s);
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

#[cfg(test)]
mod proptests {
    use super::*;
    use proptest::prelude::*;

    fn arb_base() -> impl Strategy<Value = Base> {
        any::<u64>().prop_map(Base::from)
    }

    proptest! {
        #[test]
        fn poseidon_hash2_deterministic(a in arb_base(), b in arb_base()) {
            let h1 = poseidon_hash2(a, b);
            let h2 = poseidon_hash2(a, b);
            prop_assert_eq!(h1, h2);
        }

        #[test]
        fn poseidon_hash2_not_commutative(a_val in 1u64..u64::MAX, b_val in 1u64..u64::MAX) {
            prop_assume!(a_val != b_val);
            let a = Base::from(a_val);
            let b = Base::from(b_val);
            let h1 = poseidon_hash2(a, b);
            let h2 = poseidon_hash2(b, a);
            prop_assert_ne!(h1, h2);
        }

        #[test]
        fn poseidon_hash3_deterministic(a in arb_base(), b in arb_base(), c in arb_base()) {
            let h1 = poseidon_hash3(a, b, c);
            let h2 = poseidon_hash3(a, b, c);
            prop_assert_eq!(h1, h2);
        }

        #[test]
        fn poseidon_single_vs_double(val in arb_base()) {
            let h1 = poseidon_hash(val);
            let h2 = poseidon_hash2(val, Base::ZERO);
            prop_assert_eq!(h1, h2);
        }

        #[test]
        fn poseidon_hash2_collision_resistance(
            a1 in arb_base(), b1 in arb_base(),
            a2 in arb_base(), b2 in arb_base(),
        ) {
            prop_assume!(a1 != a2 || b1 != b2);
            let h1 = poseidon_hash2(a1, b1);
            let h2 = poseidon_hash2(a2, b2);
            prop_assert_ne!(h1, h2);
        }
    }
}
