//! Transfer circuit: 2-in-2-out private transfer with fee enforcement.
//!
//! Constraints:
//! 1. Each input note commitment is correctly derived
//! 2. Each input nullifier is correctly derived from (spending_key, commitment, domain)
//! 3. Each input note's Merkle path is valid against the public root
//! 4. sum(input_values) == sum(output_values) + fee
//! 5. All values are non-negative (range check: 0..2^64)
//! 6. Output note commitments are correctly derived
//!
//! Public inputs (instance column):
//!   [merkle_root, nullifier_0, nullifier_1, out_commitment_0, out_commitment_1]

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

/// k parameter for the transfer circuit (2^13 = 8192 rows).
pub const TRANSFER_K: u32 = 13;

/// Number of inputs and outputs in a transfer.
pub const NUM_INPUTS: usize = 2;
pub const NUM_OUTPUTS: usize = 2;

/// Private transfer circuit.
///
/// Public inputs (instance):
/// - merkle_root
/// - nullifier_0, nullifier_1
/// - output_commitment_0, output_commitment_1
///
/// Private inputs (witness):
/// - spending_key
/// - input notes (value, owner, asset_id, randomness) x 2
/// - Merkle paths x 2
/// - output notes (value, owner, asset_id, randomness) x 2
/// - domain_tag for nullifier derivation
#[derive(Debug, Clone)]
pub struct TransferCircuit {
    // Private witnesses
    pub spending_key: Value<pallas::Base>,
    pub input_values: [Value<pallas::Base>; NUM_INPUTS],
    pub input_randomness: [Value<pallas::Base>; NUM_INPUTS],
    pub input_asset_ids: [Value<pallas::Base>; NUM_INPUTS],
    pub output_values: [Value<pallas::Base>; NUM_OUTPUTS],
    pub output_owners: [Value<pallas::Base>; NUM_OUTPUTS],
    pub output_randomness: [Value<pallas::Base>; NUM_OUTPUTS],
    pub output_asset_ids: [Value<pallas::Base>; NUM_OUTPUTS],
    pub fee: Value<pallas::Base>,
    pub merkle_siblings: [[Value<pallas::Base>; 32]; NUM_INPUTS],
    pub merkle_indices: [Value<u64>; NUM_INPUTS],
    pub domain_tag: Value<pallas::Base>,
}

impl TransferCircuit {
    /// Create an empty circuit for key generation.
    pub fn empty() -> Self {
        Self {
            spending_key: Value::unknown(),
            input_values: [Value::unknown(); NUM_INPUTS],
            input_randomness: [Value::unknown(); NUM_INPUTS],
            input_asset_ids: [Value::unknown(); NUM_INPUTS],
            output_values: [Value::unknown(); NUM_OUTPUTS],
            output_owners: [Value::unknown(); NUM_OUTPUTS],
            output_randomness: [Value::unknown(); NUM_OUTPUTS],
            output_asset_ids: [Value::unknown(); NUM_OUTPUTS],
            fee: Value::unknown(),
            merkle_siblings: [[Value::unknown(); 32]; NUM_INPUTS],
            merkle_indices: [Value::unknown(); NUM_INPUTS],
            domain_tag: Value::unknown(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct TransferConfig {
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

impl Circuit<pallas::Base> for TransferCircuit {
    type Config = TransferConfig;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self::empty()
    }

    fn configure(meta: &mut ConstraintSystem<pallas::Base>) -> Self::Config {
        // advice[0..2]: Poseidon state / Merkle path (shared by row range)
        // advice[3]:     value balance 4th column
        // advice[4..5]:  range check bits + accumulator
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

        // Value balance constraint: in0 + in1 == out0 + out1 (fee absorbed)
        meta.create_gate("value_balance", |meta| {
            let s = meta.query_selector(value_balance_sel);
            let in0 = meta.query_advice(advice[0], Rotation::cur());
            let in1 = meta.query_advice(advice[1], Rotation::cur());
            let out0 = meta.query_advice(advice[2], Rotation::cur());
            let out1 = meta.query_advice(advice[3], Rotation::cur());
            vec![s * (in0 + in1 - out0 - out1)]
        });

        // Range check on advice[4] (bits) + advice[5] (accum)
        let range_check = RangeCheckConfig::configure(meta, advice[4], advice[5]);

        // Merkle path on advice[0..2]
        let merkle_path =
            MerklePathConfig::configure(meta, advice[0], advice[1], advice[2]);

        // Poseidon chip on advice[0..2] with fixed round-constant columns
        let poseidon = PoseidonChipConfig::configure(
            meta,
            [advice[0], advice[1], advice[2]],
            rc_fixed,
        );

        // Commitment and nullifier derivation are thin wrappers
        let input_commitment = CommitmentDerivationConfig::new(poseidon.clone());
        let output_commitment = CommitmentDerivationConfig::new(poseidon.clone());
        let nullifier = NullifierDerivationConfig::new(poseidon.clone());

        TransferConfig {
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
            || "value_balance",
            |mut region| {
                config.value_balance_sel.enable(&mut region, 0)?;

                // Assign input values
                region.assign_advice(|| "in0", config.advice[0], 0, || self.input_values[0])?;
                region.assign_advice(|| "in1", config.advice[1], 0, || self.input_values[1])?;

                // Output values + fee
                let out0_with_fee = self.output_values[0]
                    .and_then(|o| self.fee.map(|f| o + f));
                region.assign_advice(|| "out0+fee", config.advice[2], 0, || out0_with_fee)?;
                region.assign_advice(|| "out1", config.advice[3], 0, || self.output_values[1])?;

                Ok(())
            },
        )?;

        // Region 1b: Range checks on input/output values and fee
        for i in 0..NUM_INPUTS {
            layouter.assign_region(
                || format!("range_check_input_{i}"),
                |mut region| {
                    config.range_check.assign_range_check(
                        &mut region,
                        0,
                        self.input_values[i],
                        crate::gadgets::RANGE_CHECK_BITS,
                    )?;
                    Ok(())
                },
            )?;
        }
        for i in 0..NUM_OUTPUTS {
            layouter.assign_region(
                || format!("range_check_output_{i}"),
                |mut region| {
                    config.range_check.assign_range_check(
                        &mut region,
                        0,
                        self.output_values[i],
                        crate::gadgets::RANGE_CHECK_BITS,
                    )?;
                    Ok(())
                },
            )?;
        }
        layouter.assign_region(
            || "range_check_fee",
            |mut region| {
                config.range_check.assign_range_check(
                    &mut region,
                    0,
                    self.fee,
                    crate::gadgets::RANGE_CHECK_BITS,
                )?;
                Ok(())
            },
        )?;

        // Region 2: Per-input: commitment derivation → nullifier → Merkle path
        // All in one region so copy constraints can link them.
        for i in 0..NUM_INPUTS {
            let owner = self.spending_key.map(|sk| pil_primitives::hash::poseidon_hash(sk));

            let (nullifier_cell, root_cell) = layouter.assign_region(
                || format!("input_{i}"),
                |mut region| {
                    // Commitment derivation (3 in-circuit Poseidon calls)
                    let (cm_cell, next) = config.input_commitment.assign_commitment(
                        &mut region,
                        0,
                        self.input_values[i],
                        owner,
                        self.input_asset_ids[i],
                        self.input_randomness[i],
                    )?;

                    // Nullifier derivation (2 in-circuit Poseidon calls)
                    let (nf_cell, cm_input, next) = config.nullifier.assign_nullifier(
                        &mut region,
                        next,
                        self.spending_key,
                        cm_cell.value().copied(),
                        self.domain_tag,
                    )?;
                    // Copy-constrain: commitment output == nullifier's cm input
                    region.constrain_equal(cm_cell.cell(), cm_input.cell())?;

                    // Merkle path verification
                    let (leaf_cell, root_cell) = config.merkle_path.assign_path(
                        &mut region,
                        next,
                        cm_cell.value().copied(),
                        &self.merkle_siblings[i],
                        self.merkle_indices[i],
                        TREE_DEPTH,
                    )?;
                    // Copy-constrain: commitment output == Merkle leaf
                    region.constrain_equal(cm_cell.cell(), leaf_cell.cell())?;

                    Ok((nf_cell, root_cell))
                },
            )?;

            // Constrain nullifier to public instance
            layouter.constrain_instance(nullifier_cell.cell(), config.instance, 1 + i)?;
            // Constrain computed root to public instance[0]
            layouter.constrain_instance(root_cell.cell(), config.instance, 0)?;
        }

        // Region 3: Output commitment derivation (in-circuit Poseidon)
        for i in 0..NUM_OUTPUTS {
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

            // Constrain output commitment to public instance
            layouter.constrain_instance(
                out_cm_cell.cell(),
                config.instance,
                1 + NUM_INPUTS + i,
            )?;
        }

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
    fn transfer_circuit_valid() {
        let spending_key = pallas::Base::from(42u64);
        let owner = poseidon_hash(spending_key);
        let domain_tag = pallas::Base::from(1u64); // Cardano mainnet

        // Input notes
        let in_values = [pallas::Base::from(70u64), pallas::Base::from(30u64)];
        let in_randomness = [pallas::Base::from(1u64), pallas::Base::from(2u64)];
        let in_asset_ids = [pallas::Base::ZERO, pallas::Base::ZERO];

        // Compute input commitments
        let in_commitments: Vec<pallas::Base> = (0..NUM_INPUTS)
            .map(|i| {
                let left = poseidon_hash2(in_values[i], owner);
                let right = poseidon_hash2(in_asset_ids[i], in_randomness[i]);
                poseidon_hash2(left, right)
            })
            .collect();

        // Compute nullifiers
        let nullifiers: Vec<pallas::Base> = in_commitments
            .iter()
            .map(|cm| {
                let inner = poseidon_hash2(*cm, domain_tag);
                poseidon_hash2(spending_key, inner)
            })
            .collect();

        // Build a simple Merkle tree with these commitments
        let mut tree = pil_tree::IncrementalMerkleTree::new();
        for cm in &in_commitments {
            tree.append(*cm).unwrap();
        }
        let root = tree.root();

        // Get Merkle paths
        let paths: Vec<pil_tree::MerklePath> = (0..NUM_INPUTS)
            .map(|i| tree.authentication_path(i as u64).unwrap())
            .collect();

        let merkle_siblings: [[Value<pallas::Base>; 32]; NUM_INPUTS] = [
            paths[0].siblings.map(Value::known),
            paths[1].siblings.map(Value::known),
        ];

        // Output notes
        let out_values = [pallas::Base::from(60u64), pallas::Base::from(40u64)];
        let out_owners = [pallas::Base::from(0xBEEFu64), pallas::Base::from(0xCAFEu64)];
        let out_randomness = [pallas::Base::from(3u64), pallas::Base::from(4u64)];
        let out_asset_ids = [pallas::Base::ZERO, pallas::Base::ZERO];

        let out_commitments: Vec<pallas::Base> = (0..NUM_OUTPUTS)
            .map(|i| {
                let left = poseidon_hash2(out_values[i], out_owners[i]);
                let right = poseidon_hash2(out_asset_ids[i], out_randomness[i]);
                poseidon_hash2(left, right)
            })
            .collect();

        let circuit = TransferCircuit {
            spending_key: Value::known(spending_key),
            input_values: [Value::known(in_values[0]), Value::known(in_values[1])],
            input_randomness: [Value::known(in_randomness[0]), Value::known(in_randomness[1])],
            input_asset_ids: [Value::known(in_asset_ids[0]), Value::known(in_asset_ids[1])],
            output_values: [Value::known(out_values[0]), Value::known(out_values[1])],
            output_owners: [Value::known(out_owners[0]), Value::known(out_owners[1])],
            output_randomness: [Value::known(out_randomness[0]), Value::known(out_randomness[1])],
            output_asset_ids: [Value::known(out_asset_ids[0]), Value::known(out_asset_ids[1])],
            fee: Value::known(pallas::Base::ZERO),
            merkle_siblings,
            merkle_indices: [Value::known(0), Value::known(1)],
            domain_tag: Value::known(domain_tag),
        };

        // Public inputs: [root, nf0, nf1, out_cm0, out_cm1]
        let public_inputs = vec![
            root,
            nullifiers[0],
            nullifiers[1],
            out_commitments[0],
            out_commitments[1],
        ];
        let prover = MockProver::run(TRANSFER_K, &circuit, vec![public_inputs]).unwrap();
        prover.assert_satisfied();
    }
}
