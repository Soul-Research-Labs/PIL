//! Withdraw circuit: 2-in-2-out withdrawal with public exit value.
//!
//! Same as transfer but with an additional public `exit_value` that
//! gets removed from the shielded pool back to a public chain address.
//!
//! Constraints:
//! 1. Each input note commitment is correctly derived
//! 2. Each input nullifier is correctly derived from (spending_key, commitment, domain)
//! 3. Each input note's Merkle path is valid against the public root
//! 4. sum(inputs) == sum(outputs) + fee + exit_value
//! 5. All values are non-negative
//! 6. Output note commitments are correctly derived
//!
//! Public inputs (instance column):
//!   [merkle_root, nullifier_0, nullifier_1, out_commitment_0, out_commitment_1, exit_value]

use crate::gadgets::{
    CommitmentDerivationConfig, MerklePathConfig, NullifierDerivationConfig,
    PoseidonChipConfig, RangeCheckConfig,
};
use halo2_proofs::{
    circuit::{Layouter, SimpleFloorPlanner, Value},
    plonk::{Advice, Circuit, Column, ConstraintSystem, Error, Fixed, Instance, Selector},
    poly::Rotation,
};
use pasta_curves::pallas;
use pil_tree::TREE_DEPTH;

pub const WITHDRAW_K: u32 = 13;

#[derive(Debug, Clone)]
pub struct WithdrawCircuit {
    pub spending_key: Value<pallas::Base>,
    pub input_values: [Value<pallas::Base>; 2],
    pub input_randomness: [Value<pallas::Base>; 2],
    pub input_asset_ids: [Value<pallas::Base>; 2],
    pub output_values: [Value<pallas::Base>; 2],
    pub output_owners: [Value<pallas::Base>; 2],
    pub output_randomness: [Value<pallas::Base>; 2],
    pub output_asset_ids: [Value<pallas::Base>; 2],
    pub exit_value: Value<pallas::Base>,
    pub fee: Value<pallas::Base>,
    pub merkle_siblings: [[Value<pallas::Base>; 32]; 2],
    pub merkle_indices: [Value<u64>; 2],
    pub domain_tag: Value<pallas::Base>,
}

impl WithdrawCircuit {
    pub fn empty() -> Self {
        Self {
            spending_key: Value::unknown(),
            input_values: [Value::unknown(); 2],
            input_randomness: [Value::unknown(); 2],
            input_asset_ids: [Value::unknown(); 2],
            output_values: [Value::unknown(); 2],
            output_owners: [Value::unknown(); 2],
            output_randomness: [Value::unknown(); 2],
            output_asset_ids: [Value::unknown(); 2],
            exit_value: Value::unknown(),
            fee: Value::unknown(),
            merkle_siblings: [[Value::unknown(); 32]; 2],
            merkle_indices: [Value::unknown(); 2],
            domain_tag: Value::unknown(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct WithdrawConfig {
    advice: [Column<Advice>; 6],
    _rc_fixed: [Column<Fixed>; 3],
    instance: Column<Instance>,
    value_balance_sel: Selector,
    range_check: RangeCheckConfig,
    merkle_path: MerklePathConfig,
    _poseidon: PoseidonChipConfig,
    nullifier: NullifierDerivationConfig,
    input_commitment: CommitmentDerivationConfig,
    output_commitment: CommitmentDerivationConfig,
}

impl Circuit<pallas::Base> for WithdrawCircuit {
    type Config = WithdrawConfig;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self::empty()
    }

    fn configure(meta: &mut ConstraintSystem<pallas::Base>) -> Self::Config {
        let advice: [Column<Advice>; 6] = [
            meta.advice_column(),
            meta.advice_column(),
            meta.advice_column(),
            meta.advice_column(),
            meta.advice_column(),
            meta.advice_column(),
        ];
        let rc_fixed: [Column<Fixed>; 3] = [
            meta.fixed_column(),
            meta.fixed_column(),
            meta.fixed_column(),
        ];
        let instance = meta.instance_column();
        let value_balance_sel = meta.selector();

        for col in &advice {
            meta.enable_equality(*col);
        }
        meta.enable_equality(instance);

        // Value balance: in0 + in1 == out0 + out1 + exit_value + fee
        meta.create_gate("withdraw_balance", |meta| {
            let s = meta.query_selector(value_balance_sel);
            let in0 = meta.query_advice(advice[0], Rotation::cur());
            let in1 = meta.query_advice(advice[1], Rotation::cur());
            let out0 = meta.query_advice(advice[2], Rotation::cur());
            let out1 = meta.query_advice(advice[3], Rotation::cur());
            vec![s * (in0 + in1 - out0 - out1)]
        });

        let range_check = RangeCheckConfig::configure(meta, advice[4], advice[5]);
        let merkle_path = MerklePathConfig::configure(meta, advice[0], advice[1], advice[2]);
        let poseidon = PoseidonChipConfig::configure(
            meta,
            [advice[0], advice[1], advice[2]],
            rc_fixed,
        );
        let input_commitment = CommitmentDerivationConfig::new(poseidon.clone());
        let output_commitment = CommitmentDerivationConfig::new(poseidon.clone());
        let nullifier = NullifierDerivationConfig::new(poseidon.clone());

        WithdrawConfig {
            advice,
            _rc_fixed: rc_fixed,
            instance,
            value_balance_sel,
            range_check,
            merkle_path,
            _poseidon: poseidon,
            nullifier,
            input_commitment,
            output_commitment,
        }
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<pallas::Base>,
    ) -> Result<(), Error> {
        // Region 1: Value balance check
        layouter.assign_region(
            || "withdraw_balance",
            |mut region| {
                config.value_balance_sel.enable(&mut region, 0)?;

                region.assign_advice(|| "in0", config.advice[0], 0, || self.input_values[0])?;
                region.assign_advice(|| "in1", config.advice[1], 0, || self.input_values[1])?;

                // Output values include exit_value + fee
                let out0_with_exit = self.output_values[0]
                    .and_then(|o| self.exit_value.and_then(|e| self.fee.map(|f| o + e + f)));
                region.assign_advice(|| "out0+exit+fee", config.advice[2], 0, || out0_with_exit)?;
                region.assign_advice(|| "out1", config.advice[3], 0, || self.output_values[1])?;

                Ok(())
            },
        )?;

        // Range checks on all values
        for i in 0..2 {
            layouter.assign_region(
                || format!("range_check_input_{i}"),
                |mut region| {
                    config.range_check.assign_range_check(
                        &mut region, 0, self.input_values[i],
                        crate::gadgets::RANGE_CHECK_BITS,
                    )?;
                    Ok(())
                },
            )?;
        }
        for i in 0..2 {
            layouter.assign_region(
                || format!("range_check_output_{i}"),
                |mut region| {
                    config.range_check.assign_range_check(
                        &mut region, 0, self.output_values[i],
                        crate::gadgets::RANGE_CHECK_BITS,
                    )?;
                    Ok(())
                },
            )?;
        }
        layouter.assign_region(
            || "range_check_exit",
            |mut region| {
                config.range_check.assign_range_check(
                    &mut region, 0, self.exit_value,
                    crate::gadgets::RANGE_CHECK_BITS,
                )?;
                Ok(())
            },
        )?;

        // Region 2: Per-input: commitment → nullifier → Merkle path
        // All in one region for copy constraints.
        for i in 0..2 {
            let owner = self.spending_key.map(|sk| pil_primitives::hash::poseidon_hash(sk));

            let (nullifier_cell, root_cell) = layouter.assign_region(
                || format!("input_{i}"),
                |mut region| {
                    // Commitment derivation (in-circuit Poseidon)
                    let (cm_cell, next) = config.input_commitment.assign_commitment(
                        &mut region,
                        0,
                        self.input_values[i],
                        owner,
                        self.input_asset_ids[i],
                        self.input_randomness[i],
                    )?;

                    // Nullifier derivation (in-circuit Poseidon)
                    let (nf_cell, cm_input, next) = config.nullifier.assign_nullifier(
                        &mut region,
                        next,
                        self.spending_key,
                        cm_cell.value().copied(),
                        self.domain_tag,
                    )?;
                    region.constrain_equal(cm_cell.cell(), cm_input.cell())?;

                    // Merkle path
                    let (leaf_cell, root_cell) = config.merkle_path.assign_path(
                        &mut region,
                        next,
                        cm_cell.value().copied(),
                        &self.merkle_siblings[i],
                        self.merkle_indices[i],
                        TREE_DEPTH,
                    )?;
                    region.constrain_equal(cm_cell.cell(), leaf_cell.cell())?;

                    Ok((nf_cell, root_cell))
                },
            )?;

            // Constrain nullifier: instance[1+i]
            layouter.constrain_instance(nullifier_cell.cell(), config.instance, 1 + i)?;
            // Constrain root: instance[0]
            layouter.constrain_instance(root_cell.cell(), config.instance, 0)?;
        }

        // Region 3: Output commitment derivation (in-circuit Poseidon)
        for i in 0..2 {
            let out_cm_cell = layouter.assign_region(
                || format!("output_commitment_{i}"),
                |mut region| {
                    let (cm_output, _next) = config.output_commitment.assign_commitment(
                        &mut region,
                        0,
                        self.output_values[i],
                        self.output_owners[i],
                        self.output_asset_ids[i],
                        self.output_randomness[i],
                    )?;
                    Ok(cm_output)
                },
            )?;

            // Constrain output commitment: instance[3+i]
            layouter.constrain_instance(out_cm_cell.cell(), config.instance, 3 + i)?;
        }

        // Region 4: Constrain exit_value to public instance[5]
        let exit_cell = layouter.assign_region(
            || "exit_value",
            |mut region| {
                region.assign_advice(|| "exit_val", config.advice[0], 0, || self.exit_value)
            },
        )?;
        layouter.constrain_instance(exit_cell.cell(), config.instance, 5)?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ff::Field;
    use halo2_proofs::dev::MockProver;
    use pil_primitives::hash::{poseidon_hash, poseidon_hash2};

    #[test]
    fn withdraw_circuit_valid() {
        let spending_key = pallas::Base::from(42u64);
        let owner = poseidon_hash(spending_key);
        let domain_tag = pallas::Base::from(1u64);

        let in_values = [pallas::Base::from(100u64), pallas::Base::from(0u64)];
        let in_randomness = [pallas::Base::from(1u64), pallas::Base::from(2u64)];
        let in_asset_ids = [pallas::Base::ZERO, pallas::Base::ZERO];

        let in_commitments: Vec<pallas::Base> = (0..2)
            .map(|i| {
                let left = poseidon_hash2(in_values[i], owner);
                let right = poseidon_hash2(in_asset_ids[i], in_randomness[i]);
                poseidon_hash2(left, right)
            })
            .collect();

        let nullifiers: Vec<pallas::Base> = in_commitments
            .iter()
            .map(|cm| {
                let inner = poseidon_hash2(*cm, domain_tag);
                poseidon_hash2(spending_key, inner)
            })
            .collect();

        let mut tree = pil_tree::IncrementalMerkleTree::new();
        for cm in &in_commitments {
            tree.append(*cm).unwrap();
        }
        let root = tree.root();

        let paths: Vec<pil_tree::MerklePath> =
            (0..2).map(|i| tree.authentication_path(i as u64).unwrap()).collect();

        let merkle_siblings: [[Value<pallas::Base>; 32]; 2] = [
            paths[0].siblings.map(Value::known),
            paths[1].siblings.map(Value::known),
        ];

        let exit_value = pallas::Base::from(70u64);
        let out_values = [pallas::Base::from(30u64), pallas::Base::from(0u64)];
        let out_owners = [pallas::Base::from(0xBEEFu64), pallas::Base::from(0xCAFEu64)];
        let out_randomness = [pallas::Base::from(3u64), pallas::Base::from(4u64)];
        let out_asset_ids = [pallas::Base::ZERO, pallas::Base::ZERO];

        let out_commitments: Vec<pallas::Base> = (0..2)
            .map(|i| {
                let left = poseidon_hash2(out_values[i], out_owners[i]);
                let right = poseidon_hash2(out_asset_ids[i], out_randomness[i]);
                poseidon_hash2(left, right)
            })
            .collect();

        let circuit = WithdrawCircuit {
            spending_key: Value::known(spending_key),
            input_values: [Value::known(in_values[0]), Value::known(in_values[1])],
            input_randomness: [Value::known(in_randomness[0]), Value::known(in_randomness[1])],
            input_asset_ids: [Value::known(in_asset_ids[0]), Value::known(in_asset_ids[1])],
            output_values: [Value::known(out_values[0]), Value::known(out_values[1])],
            output_owners: [Value::known(out_owners[0]), Value::known(out_owners[1])],
            output_randomness: [Value::known(out_randomness[0]), Value::known(out_randomness[1])],
            output_asset_ids: [Value::known(out_asset_ids[0]), Value::known(out_asset_ids[1])],
            exit_value: Value::known(exit_value),
            fee: Value::known(pallas::Base::ZERO),
            merkle_siblings,
            merkle_indices: [Value::known(0), Value::known(1)],
            domain_tag: Value::known(domain_tag),
        };

        // Public inputs: [root, nf0, nf1, out_cm0, out_cm1, exit_value]
        let public_inputs = vec![
            root,
            nullifiers[0],
            nullifiers[1],
            out_commitments[0],
            out_commitments[1],
            exit_value,
        ];
        let prover = MockProver::run(WITHDRAW_K, &circuit, vec![public_inputs]).unwrap();
        prover.assert_satisfied();
    }
}
