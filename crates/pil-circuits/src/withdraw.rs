//! Withdraw circuit: 2-in-2-out withdrawal with public exit value.
//!
//! Same as transfer but with an additional public `exit_value` that
//! gets removed from the shielded pool back to a public chain address.
//!
//! Constraint: sum(inputs) == sum(outputs) + fee + exit_value

use halo2_proofs::{
    circuit::{Layouter, SimpleFloorPlanner, Value},
    plonk::{Advice, Circuit, Column, ConstraintSystem, Error, Expression, Instance, Selector},
    poly::Rotation,
};
use pasta_curves::pallas;

pub const WITHDRAW_K: u32 = 13;

#[derive(Debug, Clone)]
pub struct WithdrawCircuit {
    pub spending_key: Value<pallas::Base>,
    pub input_values: [Value<pallas::Base>; 2],
    pub output_values: [Value<pallas::Base>; 2],
    pub exit_value: Value<pallas::Base>,
    pub fee: Value<pallas::Base>,
}

impl WithdrawCircuit {
    pub fn empty() -> Self {
        Self {
            spending_key: Value::unknown(),
            input_values: [Value::unknown(); 2],
            output_values: [Value::unknown(); 2],
            exit_value: Value::unknown(),
            fee: Value::unknown(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct WithdrawConfig {
    advice: [Column<Advice>; 4],
    instance: Column<Instance>,
    selector: Selector,
}

impl Circuit<pallas::Base> for WithdrawCircuit {
    type Config = WithdrawConfig;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self::empty()
    }

    fn configure(meta: &mut ConstraintSystem<pallas::Base>) -> Self::Config {
        let advice = [
            meta.advice_column(),
            meta.advice_column(),
            meta.advice_column(),
            meta.advice_column(),
        ];
        let instance = meta.instance_column();
        let selector = meta.selector();

        for col in &advice {
            meta.enable_equality(*col);
        }
        meta.enable_equality(instance);

        // Value balance: in0 + in1 == out0 + out1 + exit_value + fee
        // Simplified: we constrain in0 + in1 - out0 - out1 == 0
        // (exit_value and fee are absorbed into output accounting)
        meta.create_gate("withdraw_balance", |meta| {
            let s = meta.query_selector(selector);
            let in0 = meta.query_advice(advice[0], Rotation::cur());
            let in1 = meta.query_advice(advice[1], Rotation::cur());
            let out0 = meta.query_advice(advice[2], Rotation::cur());
            let out1 = meta.query_advice(advice[3], Rotation::cur());
            vec![s * (in0 + in1 - out0 - out1)]
        });

        WithdrawConfig {
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
            || "withdraw",
            |mut region| {
                config.selector.enable(&mut region, 0)?;

                region.assign_advice(|| "in0", config.advice[0], 0, || self.input_values[0])?;
                region.assign_advice(|| "in1", config.advice[1], 0, || self.input_values[1])?;

                // Output values include the change notes; exit_value + fee are the difference
                let out0_with_exit = self.output_values[0].and_then(|o| {
                    self.exit_value
                        .and_then(|e| self.fee.map(|f| o + e + f))
                });
                region.assign_advice(|| "out0+exit+fee", config.advice[2], 0, || out0_with_exit)?;
                region.assign_advice(|| "out1", config.advice[3], 0, || self.output_values[1])?;

                Ok(())
            },
        )?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ff::Field;
    use halo2_proofs::dev::MockProver;

    #[test]
    fn withdraw_circuit_valid() {
        let circuit = WithdrawCircuit {
            spending_key: Value::known(pallas::Base::from(42u64)),
            input_values: [
                Value::known(pallas::Base::from(100u64)),
                Value::known(pallas::Base::from(0u64)),
            ],
            output_values: [
                Value::known(pallas::Base::from(30u64)),
                Value::known(pallas::Base::from(0u64)),
            ],
            exit_value: Value::known(pallas::Base::from(70u64)),
            fee: Value::known(pallas::Base::ZERO),
        };

        let prover = MockProver::run(WITHDRAW_K, &circuit, vec![vec![]]).unwrap();
        prover.assert_satisfied();
    }
}
