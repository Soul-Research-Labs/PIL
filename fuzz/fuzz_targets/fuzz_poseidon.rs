#![no_main]
use libfuzzer_sys::fuzz_target;

use ff::Field;
use pasta_curves::pallas;
use pil_primitives::{
    hash::{poseidon_hash, poseidon_hash2, poseidon_hash3},
    types::Base,
};

fuzz_target!(|data: &[u8]| {
    if data.len() < 24 {
        return;
    }

    // Extract three u64 values from fuzz input
    let a_val = u64::from_le_bytes(data[0..8].try_into().unwrap());
    let b_val = u64::from_le_bytes(data[8..16].try_into().unwrap());
    let c_val = u64::from_le_bytes(data[16..24].try_into().unwrap());

    let a = Base::from(a_val);
    let b = Base::from(b_val);
    let c = Base::from(c_val);

    // Property: determinism
    let h1 = poseidon_hash2(a, b);
    let h2 = poseidon_hash2(a, b);
    assert_eq!(h1, h2, "poseidon_hash2 must be deterministic");

    // Property: poseidon_hash(x) == poseidon_hash2(x, 0)
    let h_single = poseidon_hash(a);
    let h_double = poseidon_hash2(a, Base::ZERO);
    assert_eq!(h_single, h_double, "poseidon_hash must equal poseidon_hash2(x, 0)");

    // Property: poseidon_hash3 determinism
    let h3a = poseidon_hash3(a, b, c);
    let h3b = poseidon_hash3(a, b, c);
    assert_eq!(h3a, h3b, "poseidon_hash3 must be deterministic");

    // Property: non-trivial output (not zero for non-zero inputs)
    if a_val > 0 && b_val > 0 {
        assert_ne!(h1, Base::ZERO, "hash of non-zero inputs should not be zero");
    }
});
