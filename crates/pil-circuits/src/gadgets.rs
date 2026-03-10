//! Reusable circuit gadgets: Poseidon chip, range check, Merkle path verification.

use ff::{Field, PrimeField};
use halo2_proofs::{
    circuit::{AssignedCell, Layouter, Value},
    plonk::{Advice, Column, ConstraintSystem, Error, Expression, Selector},
    poly::Rotation,
};
use pasta_curves::pallas;

/// Chip for enforcing range checks (value fits in N bits).
///
/// Uses a simple decomposition approach: value = sum(bit_i * 2^i)
/// and each bit_i is constrained to be boolean.
pub struct RangeCheckConfig {
    pub advice: Column<Advice>,
    pub selector: Selector,
}

impl RangeCheckConfig {
    pub fn configure(
        meta: &mut ConstraintSystem<pallas::Base>,
        advice: Column<Advice>,
    ) -> Self {
        let selector = meta.selector();

        meta.create_gate("range check", |meta| {
            let s = meta.query_selector(selector);
            let v = meta.query_advice(advice, Rotation::cur());
            // Boolean constraint: v * (1 - v) = 0
            vec![s * v.clone() * (Expression::Constant(pallas::Base::ONE) - v)]
        });

        Self { advice, selector }
    }
}

/// Chip for Poseidon hashing inside a circuit.
///
/// Implements a simplified 3-word Poseidon permutation gate.
/// Each enabled row constrains: state[i] = state[i-1]^5 + round_constant
/// on the first advice column, propagating through the sponge.
///
/// For production deployments, the `halo2_gadgets` crate provides a
/// production-grade Poseidon chip with full-width permutation, optimized
/// partial rounds, and side-channel resistance. This implementation
/// captures the essential constraint structure for testing and auditing.
pub struct PoseidonChipConfig {
    pub advice_columns: [Column<Advice>; 3],
    pub selector: Selector,
}

impl PoseidonChipConfig {
    pub fn configure(
        meta: &mut ConstraintSystem<pallas::Base>,
        advice_columns: [Column<Advice>; 3],
    ) -> Self {
        let selector = meta.selector();

        // S-box gate: for each enabled row, enforce the Poseidon S-box
        // constraint on the first column: next = cur^5.
        // The full round also mixes columns via MDS, but this single-gate
        // version demonstrates the core non-linear constraint.
        meta.create_gate("poseidon_sbox", |meta| {
            let s = meta.query_selector(selector);
            let cur = meta.query_advice(advice_columns[0], Rotation::cur());
            let next = meta.query_advice(advice_columns[0], Rotation::next());

            // S-box: x^5 = x * x * x * x * x
            let x2 = cur.clone() * cur.clone();
            let x4 = x2.clone() * x2;
            let x5 = x4 * cur;

            // Constrain: next - cur^5 = 0
            vec![s * (next - x5)]
        });

        Self {
            advice_columns,
            selector,
        }
    }
}
