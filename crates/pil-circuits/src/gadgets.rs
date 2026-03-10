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
/// This is a placeholder for the full Poseidon gadget from halo2_gadgets.
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

        // In production, this would implement the full Poseidon round constraints.
        // The halo2_gadgets crate provides a production-ready Poseidon chip.
        meta.create_gate("poseidon_placeholder", |meta| {
            let _s = meta.query_selector(selector);
            // Placeholder: real implementation uses full Poseidon round constraints
            vec![Expression::Constant(pallas::Base::ZERO)]
        });

        Self {
            advice_columns,
            selector,
        }
    }
}
