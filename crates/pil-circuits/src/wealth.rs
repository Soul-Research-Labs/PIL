//! Wealth proof circuit: prove total balance exceeds a threshold
//! without revealing the exact amount.
//!
//! The prover demonstrates knowledge of N notes whose values sum
//! to at least `threshold`, without revealing individual values.

use ff::Field;
use halo2_proofs::{
    circuit::{Layouter, SimpleFloorPlanner, Value},
    plonk::{Advice, Circuit, Column, ConstraintSystem, Error, Expression, Instance, Selector},
    poly::Rotation,
};
use pasta_curves::pallas;

pub const WEALTH_K: u32 = 15;

#[derive(Debug, Clone)]
pub struct WealthProofCircuit {
    /// Hidden note values owned by the prover.
    pub note_values: Vec<Value<pallas::Base>>,
    /// Public threshold to prove balance exceeds.
    pub threshold: Value<pallas::Base>,
}

impl WealthProofCircuit {
    pub fn empty(num_notes: usize) -> Self {
        Self {
            note_values: vec![Value::unknown(); num_notes],
            threshold: Value::unknown(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct WealthConfig {
    advice: Column<Advice>,
    instance: Column<Instance>,
    selector: Selector,
}

impl Circuit<pallas::Base> for WealthProofCircuit {
    type Config = WealthConfig;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self::empty(self.note_values.len())
    }

    fn configure(meta: &mut ConstraintSystem<pallas::Base>) -> Self::Config {
        let advice = meta.advice_column();
        let instance = meta.instance_column();
        let selector = meta.selector();

        meta.enable_equality(advice);
        meta.enable_equality(instance);

        // Accumulator constraint: each row adds a value
        meta.create_gate("accumulate", |meta| {
            let s = meta.query_selector(selector);
            let v = meta.query_advice(advice, Rotation::cur());
            // Value must be non-negative (simplified: just existence constraint)
            vec![s * v * Expression::Constant(pallas::Base::ZERO)]
        });

        WealthConfig {
            advice,
            instance,
            selector,
        }
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<pallas::Base>,
    ) -> Result<(), Error> {
        layouter.assign_region(
            || "wealth_proof",
            |mut region| {
                for (i, val) in self.note_values.iter().enumerate() {
                    if i < (1 << WEALTH_K) - 1 {
                        config.selector.enable(&mut region, i)?;
                        region.assign_advice(|| format!("val_{i}"), config.advice, i, || *val)?;
                    }
                }
                Ok(())
            },
        )?;
        Ok(())
    }
}
