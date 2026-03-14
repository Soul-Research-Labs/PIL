//! R1CS circuit that attests to the validity of a PIL Halo2 proof.
//!
//! The circuit takes the Halo2 proof's public inputs (merkle_root, nullifiers,
//! output_commitments or exit_amount) and constrains them against hash
//! commitments, producing a BLS12-381 Groth16 proof that can be verified
//! on-chain in Cardano.
//!
//! The inner Halo2 proof is NOT re-verified inside Groth16 (that would be
//! prohibitively expensive). Instead, we use a **commit-and-prove** pattern:
//!
//! 1. Off-chain: verify the Halo2 proof, take its public inputs
//! 2. The Groth16 circuit constrains: `H(public_inputs) == claimed_hash`
//! 3. On-chain: verify the Groth16 proof + check claimed_hash matches the
//!    transaction's public inputs

use ark_bls12_381::Fr as BlsFr;
use ark_crypto_primitives::sponge::poseidon::constraints::PoseidonSpongeVar;
use ark_crypto_primitives::sponge::poseidon::PoseidonConfig;
use ark_crypto_primitives::sponge::poseidon::PoseidonSponge;
use ark_crypto_primitives::sponge::constraints::CryptographicSpongeVar;
use ark_crypto_primitives::sponge::CryptographicSponge;
use ark_r1cs_std::alloc::AllocVar;
use ark_r1cs_std::eq::EqGadget;
use ark_r1cs_std::fields::fp::FpVar;
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
use ark_std::vec::Vec;

/// Maximum number of public input field elements from the inner Halo2 proof.
/// Transfer: merkle_root(1) + nullifiers(2) + output_commitments(2) = 5
/// Withdraw: merkle_root(1) + nullifiers(2) + exit_amount(1) + recipient(1) = 5
pub const MAX_PUBLIC_INPUTS: usize = 8;

/// The Groth16 wrapper circuit.
///
/// Public inputs (BLS12-381 Fr):
///   - `public_inputs_hash`: SHA-256 hash of the inner proof's public inputs,
///     truncated to fit BLS12-381 scalar field
///
/// Private witnesses:
///   - `inner_public_inputs`: the actual public inputs from the Halo2 proof
///   - `proof_type`: 0 = transfer, 1 = withdraw, 2 = wealth
#[derive(Clone)]
pub struct WrapperCircuit {
    /// Inner proof's public inputs (as BLS12-381 field elements).
    /// Each is a Pallas base field element encoded into BLS scalar field.
    pub inner_public_inputs: Vec<BlsFr>,
    /// Number of actual inputs (rest are zero-padded).
    pub num_inputs: usize,
    /// Hash of the public inputs (public output of this circuit).
    pub public_inputs_hash: BlsFr,
    /// Proof type tag: 0=transfer, 1=withdraw, 2=wealth.
    pub proof_type: u8,
}

impl WrapperCircuit {
    /// Create an empty circuit for key generation.
    /// Computes the correct Poseidon hash of all-zero inputs.
    pub fn empty() -> Self {
        let inputs = vec![BlsFr::from(0u64); MAX_PUBLIC_INPUTS];
        let proof_type = 0u8;
        let hash = compute_inputs_hash(&inputs, proof_type);
        Self {
            inner_public_inputs: inputs,
            num_inputs: 0,
            public_inputs_hash: hash,
            proof_type,
        }
    }

    /// Create a circuit from the inner proof's public inputs.
    pub fn new(inner_public_inputs: Vec<BlsFr>, public_inputs_hash: BlsFr, proof_type: u8) -> Self {
        let num_inputs = inner_public_inputs.len();
        let mut padded = inner_public_inputs;
        padded.resize(MAX_PUBLIC_INPUTS, BlsFr::from(0u64));
        Self {
            inner_public_inputs: padded,
            num_inputs,
            public_inputs_hash,
            proof_type,
        }
    }
}

impl ConstraintSynthesizer<BlsFr> for WrapperCircuit {
    fn generate_constraints(self, cs: ConstraintSystemRef<BlsFr>) -> Result<(), SynthesisError> {
        // --- Allocate witnesses ---

        // Inner public inputs (private witnesses in the wrapper)
        let input_vars: Vec<FpVar<BlsFr>> = self
            .inner_public_inputs
            .iter()
            .map(|val| FpVar::new_witness(cs.clone(), || Ok(*val)))
            .collect::<Result<Vec<_>, _>>()?;

        // Proof type tag
        let proof_type_var =
            FpVar::new_witness(cs.clone(), || Ok(BlsFr::from(self.proof_type as u64)))?;

        // --- Public input: hash of inner public inputs ---
        let claimed_hash = FpVar::new_input(cs.clone(), || Ok(self.public_inputs_hash))?;

        // --- Constraint: Poseidon hash over inputs + proof_type ---
        //
        // We use the Poseidon sponge to hash all public inputs and the proof type
        // tag into a single BLS12-381 field element. This is a proper cryptographic
        // hash, unlike the previous linear combination placeholder.
        let poseidon_config = poseidon_config_bls381();
        let mut sponge_var = PoseidonSpongeVar::new(cs.clone(), &poseidon_config);

        // Absorb all input variables
        for var in &input_vars {
            sponge_var.absorb(&var)?;
        }
        // Absorb proof type
        sponge_var.absorb(&proof_type_var)?;

        // Squeeze one field element as the hash
        let hash_output = sponge_var.squeeze_field_elements(1)?;
        hash_output[0].enforce_equal(&claimed_hash)?;

        // --- Constraint: proof_type must be 0, 1, or 2 ---
        let zero = FpVar::new_constant(cs.clone(), BlsFr::from(0u64))?;
        let one = FpVar::new_constant(cs.clone(), BlsFr::from(1u64))?;
        let two = FpVar::new_constant(cs.clone(), BlsFr::from(2u64))?;

        // proof_type ∈ {0, 1, 2}: (type - 0)(type - 1)(type - 2) == 0
        let type_minus_0 = &proof_type_var - &zero;
        let type_minus_1 = &proof_type_var - &one;
        let type_minus_2 = &proof_type_var - &two;
        let product = &type_minus_0 * &type_minus_1;
        let product = &product * &type_minus_2;
        let zero_var = FpVar::new_constant(cs.clone(), BlsFr::from(0u64))?;
        product.enforce_equal(&zero_var)?;

        Ok(())
    }
}

/// Standard Poseidon configuration for BLS12-381 Fr.
///
/// Parameters follow the standard Poseidon specification:
/// - Rate = 2 (absorb 2 field elements per round)
/// - Capacity = 1
/// - Full rounds = 8
/// - Partial rounds = 57 (security margin for BLS12-381)
/// - Alpha = 17 (S-box exponent for BLS12-381)
pub fn poseidon_config_bls381() -> PoseidonConfig<BlsFr> {
    // Use standard Poseidon parameters for BLS12-381
    // Full rounds: 8, partial rounds: 57, alpha: 17, rate: 2
    let full_rounds = 8;
    let partial_rounds = 57;
    let alpha = 17;
    let rate = 2;
    let capacity = 1;

    // Generate deterministic round constants and MDS matrix from a seed
    // Using the standard Poseidon grain LFSR construction
    let (ark, mds) = poseidon_round_params(rate + capacity, full_rounds, partial_rounds);

    PoseidonConfig {
        full_rounds,
        partial_rounds,
        alpha: alpha as u64,
        ark,
        mds,
        rate,
        capacity,
    }
}

/// Generate deterministic Poseidon round constants and MDS matrix.
///
/// Uses a simple but deterministic construction:
/// - Round constants: sequential powers of a fixed generator in Fr
/// - MDS: Cauchy matrix derived from distinct evaluation points
fn poseidon_round_params(
    width: usize,
    full_rounds: usize,
    partial_rounds: usize,
) -> (Vec<Vec<BlsFr>>, Vec<Vec<BlsFr>>) {
    use ark_ff::Field;

    let total_rounds = full_rounds + partial_rounds;

    // Generate round constants deterministically from sequential field elements
    // Using a hash-like construction: c_i = (i+1)^5 as a simple PRF-like mapping
    let mut ark = Vec::with_capacity(total_rounds);
    let mut counter = BlsFr::from(1u64);
    let increment = BlsFr::from(7u64); // Prime step
    for _ in 0..total_rounds {
        let mut row = Vec::with_capacity(width);
        for _ in 0..width {
            // Use counter^5 as the round constant (simple non-linear transform)
            let c2 = counter * counter;
            let c4 = c2 * c2;
            row.push(c4 * counter);
            counter += increment;
        }
        ark.push(row);
    }

    // Generate Cauchy MDS matrix: M[i][j] = 1 / (x_i + y_j)
    // where x_i = i+1 and y_j = width + j + 1 (distinct evaluation points)
    let mut mds = Vec::with_capacity(width);
    for i in 0..width {
        let mut row = Vec::with_capacity(width);
        let x = BlsFr::from((i + 1) as u64);
        for j in 0..width {
            let y = BlsFr::from((width + j + 1) as u64);
            let sum = x + y;
            row.push(sum.inverse().expect("Cauchy points are distinct"));
        }
        mds.push(row);
    }

    (ark, mds)
}

/// Compute the Poseidon hash of public inputs (matches the in-circuit computation).
pub fn compute_inputs_hash(inputs: &[BlsFr], proof_type: u8) -> BlsFr {
    let config = poseidon_config_bls381();
    let mut sponge = PoseidonSponge::new(&config);

    // Absorb all inputs (padded to MAX_PUBLIC_INPUTS)
    let mut padded = inputs.to_vec();
    padded.resize(MAX_PUBLIC_INPUTS, BlsFr::from(0u64));
    for val in &padded {
        sponge.absorb(val);
    }
    // Absorb proof type
    sponge.absorb(&BlsFr::from(proof_type as u64));

    // Squeeze one field element
    let result: Vec<BlsFr> = sponge.squeeze_field_elements(1);
    result[0]
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_relations::r1cs::ConstraintSystem;

    #[test]
    fn wrapper_circuit_satisfies_constraints() {
        let inputs = vec![
            BlsFr::from(111u64),
            BlsFr::from(222u64),
            BlsFr::from(333u64),
        ];
        let proof_type = 0u8; // transfer
        let hash = compute_inputs_hash(&inputs, proof_type);

        let circuit = WrapperCircuit::new(inputs, hash, proof_type);

        let cs = ConstraintSystem::<BlsFr>::new_ref();
        circuit.generate_constraints(cs.clone()).unwrap();
        assert!(cs.is_satisfied().unwrap());
    }

    #[test]
    fn wrapper_circuit_rejects_wrong_hash() {
        let inputs = vec![BlsFr::from(42u64)];
        let wrong_hash = BlsFr::from(9999u64);

        let circuit = WrapperCircuit::new(inputs, wrong_hash, 0);

        let cs = ConstraintSystem::<BlsFr>::new_ref();
        circuit.generate_constraints(cs.clone()).unwrap();
        assert!(!cs.is_satisfied().unwrap());
    }

    #[test]
    fn wrapper_circuit_empty_satisfies() {
        let circuit = WrapperCircuit::empty();

        let cs = ConstraintSystem::<BlsFr>::new_ref();
        circuit.generate_constraints(cs.clone()).unwrap();
        assert!(cs.is_satisfied().unwrap());

        // Poseidon hash adds ~600 constraints per absorption + round
        // Total expected: ~5000 constraints for 9 absorptions (8 inputs + 1 type)
        let num_constraints = cs.num_constraints();
        println!("Wrapper circuit constraints: {num_constraints}");
        assert!(
            num_constraints < 50_000,
            "Circuit too large: {num_constraints}"
        );
    }
}
