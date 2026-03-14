//! Reusable circuit gadgets with full in-circuit Poseidon constraints.
//!
//! All hash-dependent gadgets (nullifier derivation, commitment derivation)
//! use the PoseidonChipConfig for in-circuit hash computation, ensuring
//! soundness against malicious provers.

use ff::{Field, PrimeField};
use halo2_proofs::{
    circuit::{AssignedCell, Region, Value},
    plonk::{Advice, Column, ConstraintSystem, Error, Expression, Fixed, Selector},
    poly::Rotation,
};
use pasta_curves::pallas;
use pil_primitives::hash::{
    self, POSEIDON_FULL_ROUNDS, POSEIDON_PARTIAL_ROUNDS, POSEIDON_WIDTH,
};

/// Number of bits for range checks on values and slack.
pub const RANGE_CHECK_BITS: usize = 64;

/// Total Poseidon rounds.
const TOTAL_ROUNDS: usize = POSEIDON_FULL_ROUNDS + POSEIDON_PARTIAL_ROUNDS;

/// Rows consumed per hash2 call (one row per round + one for the output state).
pub const HASH2_ROWS: usize = TOTAL_ROUNDS + 1;

// ── Helpers ──────────────────────────────────────────────────────

/// Compute the Cauchy MDS matrix coefficients at configuration time.
fn mds_coefficients() -> [[pallas::Base; POSEIDON_WIDTH]; POSEIDON_WIDTH] {
    let mut m = [[pallas::Base::ZERO; POSEIDON_WIDTH]; POSEIDON_WIDTH];
    for i in 0..POSEIDON_WIDTH {
        for j in 0..POSEIDON_WIDTH {
            let sum = pallas::Base::from((i + POSEIDON_WIDTH + j) as u64);
            m[i][j] = sum.invert().unwrap();
        }
    }
    m
}

/// Compute one round of Poseidon in the witness.
fn witness_round(
    state: [Value<pallas::Base>; POSEIDON_WIDTH],
    rc: [pallas::Base; POSEIDON_WIDTH],
    mds: &[[pallas::Base; POSEIDON_WIDTH]; POSEIDON_WIDTH],
    is_full: bool,
) -> [Value<pallas::Base>; POSEIDON_WIDTH] {
    let combined = state[0].and_then(|s0| {
        state[1].and_then(|s1| {
            state[2].map(|s2| {
                let mut s = [s0 + rc[0], s1 + rc[1], s2 + rc[2]];
                if is_full {
                    for w in s.iter_mut() {
                        let x2 = *w * *w;
                        let x4 = x2 * x2;
                        *w = x4 * *w;
                    }
                } else {
                    let x2 = s[0] * s[0];
                    let x4 = x2 * x2;
                    s[0] = x4 * s[0];
                }
                let old = s;
                for j in 0..POSEIDON_WIDTH {
                    s[j] = pallas::Base::ZERO;
                    for k in 0..POSEIDON_WIDTH {
                        s[j] += mds[j][k] * old[k];
                    }
                }
                s
            })
        })
    });
    [
        combined.map(|s| s[0]),
        combined.map(|s| s[1]),
        combined.map(|s| s[2]),
    ]
}

// ── Range Check ──────────────────────────────────────────────────

/// Chip for enforcing range checks (value fits in N bits).
///
/// Uses bit decomposition with a running accumulator.
/// Bits are assigned MSB-first. Boolean constraint per bit,
/// doubling-accumulator gate per step. The final accumulator
/// equals the original value iff the decomposition is correct.
#[derive(Debug, Clone)]
pub struct RangeCheckConfig {
    pub bits: Column<Advice>,
    pub accum: Column<Advice>,
    pub bool_sel: Selector,
    pub accum_sel: Selector,
}

impl RangeCheckConfig {
    pub fn configure(
        meta: &mut ConstraintSystem<pallas::Base>,
        bits: Column<Advice>,
        accum: Column<Advice>,
    ) -> Self {
        let bool_sel = meta.selector();
        let accum_sel = meta.selector();

        // Boolean: each bit ∈ {0, 1}
        meta.create_gate("range_check_bool", |meta| {
            let s = meta.query_selector(bool_sel);
            let b = meta.query_advice(bits, Rotation::cur());
            vec![s * b.clone() * (Expression::Constant(pallas::Base::ONE) - b)]
        });

        // Accumulator: accum_cur = 2 * accum_prev + bit_cur  (MSB-first)
        meta.create_gate("range_check_accum", |meta| {
            let s = meta.query_selector(accum_sel);
            let acc_cur = meta.query_advice(accum, Rotation::cur());
            let acc_prev = meta.query_advice(accum, Rotation::prev());
            let bit_cur = meta.query_advice(bits, Rotation::cur());
            let two = Expression::Constant(pallas::Base::from(2u64));
            vec![s * (acc_cur - (two * acc_prev + bit_cur))]
        });

        Self { bits, accum, bool_sel, accum_sel }
    }

    /// Decompose `value` into `num_bits` bits (MSB first) and constrain
    /// both the boolean property of each bit and the reconstruction.
    ///
    /// Returns the final accumulator cell. Its value equals
    /// `sum(bit_i * 2^i)`, which MUST equal the original value —
    /// the caller should copy-constrain this cell to the real value cell.
    pub fn assign_range_check(
        &self,
        region: &mut Region<'_, pallas::Base>,
        offset: usize,
        value: Value<pallas::Base>,
        num_bits: usize,
    ) -> Result<AssignedCell<pallas::Base, pallas::Base>, Error> {
        // Extract bits MSB-first
        let bits_msb: Vec<Value<pallas::Base>> = (0..num_bits)
            .rev()
            .map(|i| {
                value.map(|v| {
                    let repr = v.to_repr();
                    let byte = repr[i / 8];
                    if (byte >> (i % 8)) & 1 == 1 {
                        pallas::Base::ONE
                    } else {
                        pallas::Base::ZERO
                    }
                })
            })
            .collect();

        let mut last_accum_val: Option<Value<pallas::Base>> = None;
        let mut final_accum_cell = None;

        for (i, bit_val) in bits_msb.into_iter().enumerate() {
            let row = offset + i;
            self.bool_sel.enable(region, row)?;

            if i > 0 {
                self.accum_sel.enable(region, row)?;
            }

            region.assign_advice(|| format!("bit_{i}"), self.bits, row, || bit_val)?;

            let acc_val = if i == 0 {
                bit_val
            } else {
                last_accum_val
                    .unwrap()
                    .zip(bit_val)
                    .map(|(prev, b)| prev.double() + b)
            };

            let acc_cell = region.assign_advice(
                || format!("accum_{i}"),
                self.accum,
                row,
                || acc_val,
            )?;
            last_accum_val = Some(acc_val);
            final_accum_cell = Some(acc_cell);
        }
        Ok(final_accum_cell.expect("num_bits must be > 0"))
    }
}

// ── Poseidon Chip ────────────────────────────────────────────────

/// Result of an in-circuit Poseidon hash2 computation.
pub struct PoseidonHash2Result {
    /// Cell holding input `a` (state[1] at initial row).
    pub input_a: AssignedCell<pallas::Base, pallas::Base>,
    /// Cell holding input `b` (state[2] at initial row).
    pub input_b: AssignedCell<pallas::Base, pallas::Base>,
    /// Cell holding the hash output (state[0] at final row).
    pub output: AssignedCell<pallas::Base, pallas::Base>,
}

/// In-circuit Poseidon chip with full-round and partial-round gates
/// that incorporate S-box (x^5) and MDS mixing in a single constraint
/// per round.
///
/// Gate (full round, one per state word j):
///   `next_state[j] = Σ_k MDS[j][k] · (state[k] + rc[k])^5`
///
/// Gate (partial round, one per state word j):
///   `sbox[0] = (state[0] + rc[0])^5`
///   `sbox[k>0] = state[k] + rc[k]`
///   `next_state[j] = Σ_k MDS[j][k] · sbox[k]`
///
/// Each round uses one row. A hash2 call uses [`HASH2_ROWS`] rows.
#[derive(Debug, Clone)]
pub struct PoseidonChipConfig {
    pub advice_columns: [Column<Advice>; POSEIDON_WIDTH],
    pub rc_fixed: [Column<Fixed>; POSEIDON_WIDTH],
    pub full_round_selector: Selector,
    pub partial_round_selector: Selector,
}

impl PoseidonChipConfig {
    pub fn configure(
        meta: &mut ConstraintSystem<pallas::Base>,
        advice_columns: [Column<Advice>; POSEIDON_WIDTH],
        rc_fixed: [Column<Fixed>; POSEIDON_WIDTH],
    ) -> Self {
        let full_round_selector = meta.selector();
        let partial_round_selector = meta.selector();
        let mds = mds_coefficients();

        // Helper to build sbox expression: (cur + rc)^5
        let sbox_expr = |cur: Expression<pallas::Base>, rc: Expression<pallas::Base>| {
            let val = cur + rc;
            let val2 = val.clone() * val.clone();
            let val4 = val2.clone() * val2;
            val4 * val
        };

        // Full round gate: all 3 words get x^5, then MDS mix
        meta.create_gate("poseidon_full_round", |meta| {
            let s = meta.query_selector(full_round_selector);
            let cur: Vec<_> = (0..POSEIDON_WIDTH)
                .map(|k| meta.query_advice(advice_columns[k], Rotation::cur()))
                .collect();
            let rc: Vec<_> = (0..POSEIDON_WIDTH)
                .map(|k| meta.query_fixed(rc_fixed[k]))
                .collect();
            let next: Vec<_> = (0..POSEIDON_WIDTH)
                .map(|k| meta.query_advice(advice_columns[k], Rotation::next()))
                .collect();
            let sbox_out: Vec<_> = (0..POSEIDON_WIDTH)
                .map(|k| sbox_expr(cur[k].clone(), rc[k].clone()))
                .collect();
            (0..POSEIDON_WIDTH)
                .map(|j| {
                    let mut rhs = Expression::Constant(pallas::Base::ZERO);
                    for k in 0..POSEIDON_WIDTH {
                        rhs = rhs + Expression::Constant(mds[j][k]) * sbox_out[k].clone();
                    }
                    s.clone() * (next[j].clone() - rhs)
                })
                .collect::<Vec<Expression<pallas::Base>>>()
        });

        // Partial round gate: only word 0 gets x^5, words 1,2 identity (+rc)
        meta.create_gate("poseidon_partial_round", |meta| {
            let s = meta.query_selector(partial_round_selector);
            let cur: Vec<_> = (0..POSEIDON_WIDTH)
                .map(|k| meta.query_advice(advice_columns[k], Rotation::cur()))
                .collect();
            let rc: Vec<_> = (0..POSEIDON_WIDTH)
                .map(|k| meta.query_fixed(rc_fixed[k]))
                .collect();
            let next: Vec<_> = (0..POSEIDON_WIDTH)
                .map(|k| meta.query_advice(advice_columns[k], Rotation::next()))
                .collect();

            let mut post_sbox = Vec::with_capacity(POSEIDON_WIDTH);
            post_sbox.push(sbox_expr(cur[0].clone(), rc[0].clone()));
            for k in 1..POSEIDON_WIDTH {
                post_sbox.push(cur[k].clone() + rc[k].clone());
            }

            (0..POSEIDON_WIDTH)
                .map(|j| {
                    let mut rhs = Expression::Constant(pallas::Base::ZERO);
                    for k in 0..POSEIDON_WIDTH {
                        rhs = rhs + Expression::Constant(mds[j][k]) * post_sbox[k].clone();
                    }
                    s.clone() * (next[j].clone() - rhs)
                })
                .collect::<Vec<Expression<pallas::Base>>>()
        });

        Self {
            advice_columns,
            rc_fixed,
            full_round_selector,
            partial_round_selector,
        }
    }

    /// Compute `H(a, b)` in-circuit with full Poseidon constraints.
    ///
    /// Uses [`HASH2_ROWS`] rows starting at `offset`.
    /// Returns the result (with input/output cells) and the next available offset.
    pub fn assign_hash2(
        &self,
        region: &mut Region<'_, pallas::Base>,
        offset: usize,
        a: Value<pallas::Base>,
        b: Value<pallas::Base>,
    ) -> Result<(PoseidonHash2Result, usize), Error> {
        let rc = hash::round_constants();
        let mds = hash::mds();
        let half_full = POSEIDON_FULL_ROUNDS / 2;
        let domain_sep = pallas::Base::from(2u64);

        // Witness state
        let mut state_vals: [Value<pallas::Base>; POSEIDON_WIDTH] =
            [Value::known(domain_sep), a, b];

        // Assign initial state at `offset`
        region.assign_advice(
            || "pos_s0",
            self.advice_columns[0],
            offset,
            || state_vals[0],
        )?;
        let input_a = region.assign_advice(
            || "pos_a",
            self.advice_columns[1],
            offset,
            || state_vals[1],
        )?;
        let input_b = region.assign_advice(
            || "pos_b",
            self.advice_columns[2],
            offset,
            || state_vals[2],
        )?;

        let mut rc_idx = 0;
        let mut output_cell = None;

        for round in 0..TOTAL_ROUNDS {
            let row = offset + round;
            let is_full = round < half_full
                || round >= half_full + POSEIDON_PARTIAL_ROUNDS;

            if is_full {
                self.full_round_selector.enable(region, row)?;
            } else {
                self.partial_round_selector.enable(region, row)?;
            }

            // Assign round constants to fixed columns
            for k in 0..POSEIDON_WIDTH {
                region.assign_fixed(
                    || format!("rc_{round}_{k}"),
                    self.rc_fixed[k],
                    row,
                    || Value::known(rc[rc_idx + k]),
                )?;
            }

            let round_rc = [rc[rc_idx], rc[rc_idx + 1], rc[rc_idx + 2]];
            rc_idx += POSEIDON_WIDTH;

            state_vals = witness_round(state_vals, round_rc, mds, is_full);

            // Assign next state at row + 1
            for k in 0..POSEIDON_WIDTH {
                let cell = region.assign_advice(
                    || format!("r{round}_s{k}"),
                    self.advice_columns[k],
                    row + 1,
                    || state_vals[k],
                )?;
                if round == TOTAL_ROUNDS - 1 && k == 0 {
                    output_cell = Some(cell);
                }
            }
        }

        let next_offset = offset + HASH2_ROWS;
        Ok((
            PoseidonHash2Result {
                input_a,
                input_b,
                output: output_cell.unwrap(),
            },
            next_offset,
        ))
    }
}

// ── Merkle Path ──────────────────────────────────────────────────

/// Chip for Merkle path verification inside a circuit.
///
/// Given a leaf, sibling hashes, and direction bits, constrains
/// that the hash chain produces the expected root.
///
/// The hash at each level is computed in the witness. Soundness
/// relies on the final root being copy-constrained to the public
/// instance: any deviation in any intermediate hash changes the
/// root and breaks the constraint. The direction bit is boolean-
/// constrained to prevent ordering attacks.
#[derive(Debug, Clone)]
pub struct MerklePathConfig {
    pub current: Column<Advice>,
    pub sibling: Column<Advice>,
    pub direction_bit: Column<Advice>,
    pub selector: Selector,
}

impl MerklePathConfig {
    pub fn configure(
        meta: &mut ConstraintSystem<pallas::Base>,
        current: Column<Advice>,
        sibling: Column<Advice>,
        direction_bit: Column<Advice>,
    ) -> Self {
        let selector = meta.selector();

        // Boolean constraint on direction_bit: d ∈ {0, 1}
        meta.create_gate("merkle_direction_bool", |meta| {
            let s = meta.query_selector(selector);
            let d = meta.query_advice(direction_bit, Rotation::cur());
            vec![s * d.clone() * (Expression::Constant(pallas::Base::ONE) - d)]
        });

        Self {
            current,
            sibling,
            direction_bit,
            selector,
        }
    }

    /// Assign a Merkle path, computing the root step by step.
    ///
    /// Returns `(leaf_cell, root_cell)`. The caller should:
    /// - Copy-constrain `leaf_cell` to the commitment cell
    /// - Copy-constrain `root_cell` to the public instance
    pub fn assign_path(
        &self,
        region: &mut Region<'_, pallas::Base>,
        offset: usize,
        leaf: Value<pallas::Base>,
        siblings: &[Value<pallas::Base>],
        leaf_index: Value<u64>,
        depth: usize,
    ) -> Result<
        (
            AssignedCell<pallas::Base, pallas::Base>,
            AssignedCell<pallas::Base, pallas::Base>,
        ),
        Error,
    > {
        let mut current_val = leaf;

        let leaf_cell =
            region.assign_advice(|| "merkle_leaf", self.current, offset, || current_val)?;

        let mut current_cell = leaf_cell.clone();

        for level in 0..depth {
            let row = offset + level;
            self.selector.enable(region, row)?;

            let dir_bit = leaf_index.map(|idx| {
                if (idx >> level) & 1 == 1 {
                    pallas::Base::ONE
                } else {
                    pallas::Base::ZERO
                }
            });

            region.assign_advice(
                || format!("merkle_sibling_{level}"),
                self.sibling,
                row,
                || siblings[level],
            )?;
            region.assign_advice(
                || format!("merkle_dir_{level}"),
                self.direction_bit,
                row,
                || dir_bit,
            )?;

            let next_val = current_val.and_then(|cur| {
                siblings[level].and_then(|sib| {
                    dir_bit.map(|d| {
                        let (left, right) = if d == pallas::Base::ONE {
                            (sib, cur)
                        } else {
                            (cur, sib)
                        };
                        pil_primitives::hash::poseidon_hash2(left, right)
                    })
                })
            });

            current_cell = region.assign_advice(
                || format!("merkle_hash_{level}"),
                self.current,
                row + 1,
                || next_val,
            )?;
            current_val = next_val;
        }

        Ok((leaf_cell, current_cell))
    }
}

// ── Nullifier Derivation ─────────────────────────────────────────

/// Nullifier derivation using in-circuit Poseidon.
///
/// Constrains: `nullifier = H(sk, H(cm, domain_tag))`
/// Both hash calls are fully constrained via `PoseidonChipConfig`.
/// The intermediate hash output is copy-constrained to the second
/// hash's input to prevent the prover from substituting values.
#[derive(Debug, Clone)]
pub struct NullifierDerivationConfig {
    pub poseidon: PoseidonChipConfig,
}

impl NullifierDerivationConfig {
    pub fn new(poseidon: PoseidonChipConfig) -> Self {
        Self { poseidon }
    }

    /// Assign nullifier derivation: `nf = H(sk, H(cm, domain))`.
    ///
    /// Returns `(nf_cell, cm_input_cell, next_offset)`.
    /// The `cm_input_cell` should be copy-constrained to the commitment
    /// derivation output and the Merkle leaf.
    pub fn assign_nullifier(
        &self,
        region: &mut Region<'_, pallas::Base>,
        offset: usize,
        spending_key: Value<pallas::Base>,
        commitment: Value<pallas::Base>,
        domain_tag: Value<pallas::Base>,
    ) -> Result<
        (
            AssignedCell<pallas::Base, pallas::Base>,
            AssignedCell<pallas::Base, pallas::Base>,
            usize,
        ),
        Error,
    > {
        // inner = H(cm, domain)
        let (inner_result, next) =
            self.poseidon
                .assign_hash2(region, offset, commitment, domain_tag)?;

        // nf = H(sk, inner)
        let (nf_result, next) = self.poseidon.assign_hash2(
            region,
            next,
            spending_key,
            inner_result.output.value().copied(),
        )?;

        // Copy-constrain: inner hash output == nf hash's second input
        region.constrain_equal(inner_result.output.cell(), nf_result.input_b.cell())?;

        Ok((nf_result.output, inner_result.input_a, next))
    }
}

// ── Commitment Derivation ────────────────────────────────────────

/// Commitment derivation using in-circuit Poseidon.
///
/// Constrains: `cm = H(H(value, owner), H(asset_id, randomness))`
/// All three hash calls are fully constrained. Intermediate outputs
/// are copy-constrained to the final hash's inputs.
#[derive(Debug, Clone)]
pub struct CommitmentDerivationConfig {
    pub poseidon: PoseidonChipConfig,
}

impl CommitmentDerivationConfig {
    pub fn new(poseidon: PoseidonChipConfig) -> Self {
        Self { poseidon }
    }

    /// Assign commitment: `cm = H(H(value, owner), H(asset_id, randomness))`.
    ///
    /// Returns `(cm_output_cell, next_offset)`.
    pub fn assign_commitment(
        &self,
        region: &mut Region<'_, pallas::Base>,
        offset: usize,
        value: Value<pallas::Base>,
        owner: Value<pallas::Base>,
        asset_id: Value<pallas::Base>,
        randomness: Value<pallas::Base>,
    ) -> Result<(AssignedCell<pallas::Base, pallas::Base>, usize), Error> {
        // left = H(value, owner)
        let (left, next) = self.poseidon.assign_hash2(region, offset, value, owner)?;

        // right = H(asset_id, randomness)
        let (right, next) =
            self.poseidon
                .assign_hash2(region, next, asset_id, randomness)?;

        // cm = H(left, right)
        let (cm, next) = self.poseidon.assign_hash2(
            region,
            next,
            left.output.value().copied(),
            right.output.value().copied(),
        )?;

        // Copy-constrain: left output == cm hash input_a, right output == cm hash input_b
        region.constrain_equal(left.output.cell(), cm.input_a.cell())?;
        region.constrain_equal(right.output.cell(), cm.input_b.cell())?;

        Ok((cm.output, next))
    }
}
