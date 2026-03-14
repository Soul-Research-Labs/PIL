// PIL Cardano Library — helper functions for validator logic.

use aiken/crypto.{blake2b_256}

/// Verify that a byte array is a valid 32-byte hash (Poseidon output).
pub fn is_valid_hash(h: ByteArray) -> Bool {
  builtin.length_of_bytearray(h) == 32
}

/// Check that all elements in a list are unique.
pub fn all_unique(items: List<ByteArray>) -> Bool {
  check_unique(items, [])
}

fn check_unique(items: List<ByteArray>, seen: List<ByteArray>) -> Bool {
  when items is {
    [] -> True
    [head, ..tail] ->
      if list.has(seen, head) {
        False
      } else {
        check_unique(tail, [head, ..seen])
      }
  }
}

/// Compute a chain of hashes for Merkle path verification (Blake2b fallback).
/// Note: In production, this should use Poseidon hashing for ZK compatibility.
/// On-chain Poseidon is expensive in UPLC; prefer off-chain computation with
/// on-chain root commitment verification.
pub fn verify_merkle_inclusion_blake2b(
  leaf: ByteArray,
  siblings: List<ByteArray>,
  path_indices: List<Int>,
  expected_root: ByteArray,
) -> Bool {
  let computed_root = compute_root(leaf, siblings, path_indices)
  computed_root == expected_root
}

fn compute_root(
  current: ByteArray,
  siblings: List<ByteArray>,
  path_indices: List<Int>,
) -> ByteArray {
  when siblings is {
    [] -> current
    [sibling, ..rest_siblings] -> {
      expect [idx, ..rest_indices] = path_indices
      let next =
        if idx == 0 {
          blake2b_256(builtin.append_bytearray(current, sibling))
        } else {
          blake2b_256(builtin.append_bytearray(sibling, current))
        }
      compute_root(next, rest_siblings, rest_indices)
    }
  }
}

/// Verify a proof attestation signature.
/// In Phase 1, proofs are verified off-chain by a committee that signs
/// an attestation. This function checks the committee's multi-sig.
pub fn verify_committee_attestation(
  proof_hash: ByteArray,
  signatories: List<ByteArray>,
  required_signers: List<ByteArray>,
  threshold: Int,
) -> Bool {
  let matched =
    list.foldl(
      required_signers,
      0,
      fn(signer, acc) {
        if list.has(signatories, signer) {
          acc + 1
        } else {
          acc
        }
      },
    )
  matched >= threshold
}

// ─── Groth16 BLS12-381 On-Chain Verification ────────────────────────

/// Groth16 verifying key type.
/// All points are BLS12-381 compressed format.
type Groth16VK {
  alpha_g1: ByteArray,
  beta_g2: ByteArray,
  gamma_g2: ByteArray,
  delta_g2: ByteArray,
  ic: List<ByteArray>,
}

/// Verify a Groth16 proof on-chain using Plutus V3 BLS12-381 builtins.
///
/// The proof is a flat concatenation of:
///   A (48 bytes, G1 compressed) || B (96 bytes, G2 compressed) || C (48 bytes, G1 compressed)
///
/// Verification equation (Groth16 pairing check):
///   e(A, B) == e(alpha_g1, beta_g2) * e(vk_x, gamma_g2) * e(C, delta_g2)
///
/// Where vk_x = ic[0] + sum(ic[i+1] * public_input[i])
pub fn verify_groth16_proof(
  proof: ByteArray,
  vk: Groth16VK,
  public_inputs: List<ByteArray>,
) -> Bool {
  // Proof length: 48 (A/G1) + 96 (B/G2) + 48 (C/G1) = 192 bytes
  let proof_len = builtin.length_of_bytearray(proof)
  expect proof_len == 192

  // ic length must be public_inputs + 1
  expect list.length(vk.ic) == list.length(public_inputs) + 1

  // Decompress proof points
  let proof_a = builtin.bls12_381_g1_uncompress(builtin.slice_bytearray(0, 48, proof))
  let proof_b = builtin.bls12_381_g2_uncompress(builtin.slice_bytearray(48, 96, proof))
  let proof_c = builtin.bls12_381_g1_uncompress(builtin.slice_bytearray(144, 48, proof))

  // Decompress VK points
  let alpha = builtin.bls12_381_g1_uncompress(vk.alpha_g1)
  let beta = builtin.bls12_381_g2_uncompress(vk.beta_g2)
  let gamma = builtin.bls12_381_g2_uncompress(vk.gamma_g2)
  let delta = builtin.bls12_381_g2_uncompress(vk.delta_g2)

  // Compute vk_x = ic[0] + sum(ic[i+1] * input[i])
  expect [ic0_bytes, ..ic_rest] = vk.ic
  let ic0 = builtin.bls12_381_g1_uncompress(ic0_bytes)
  let vk_x = compute_vk_x(ic0, ic_rest, public_inputs)

  // Groth16 pairing check using negated points:
  // e(A, B) * e(-alpha, beta) * e(-vk_x, gamma) * e(-C, delta) == identity
  let neg_alpha = builtin.bls12_381_g1_neg(alpha)
  let neg_vk_x = builtin.bls12_381_g1_neg(vk_x)
  let neg_c = builtin.bls12_381_g1_neg(proof_c)

  let ml_ab = builtin.bls12_381_miller_loop(proof_a, proof_b)
  let ml_alpha_beta = builtin.bls12_381_miller_loop(neg_alpha, beta)
  let ml_vkx_gamma = builtin.bls12_381_miller_loop(neg_vk_x, gamma)
  let ml_c_delta = builtin.bls12_381_miller_loop(neg_c, delta)

  let combined =
    builtin.bls12_381_mul_miller_loop_result(
      ml_ab,
      builtin.bls12_381_mul_miller_loop_result(
        ml_alpha_beta,
        builtin.bls12_381_mul_miller_loop_result(ml_vkx_gamma, ml_c_delta),
      ),
    )

  builtin.bls12_381_final_verify(
    combined,
    builtin.bls12_381_miller_loop(
      builtin.bls12_381_g1_uncompress(
        #"c00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
      ),
      builtin.bls12_381_g2_uncompress(
        #"c00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
      ),
    ),
  )
}

/// Recursively compute vk_x = acc + sum(ic[i] * input[i]) for Groth16.
fn compute_vk_x(
  acc: G1Element,
  ic_rest: List<ByteArray>,
  inputs: List<ByteArray>,
) -> G1Element {
  when ic_rest is {
    [] -> acc
    [ic_bytes, ..remaining_ic] -> {
      expect [input_bytes, ..remaining_inputs] = inputs
      let ic_point = builtin.bls12_381_g1_uncompress(ic_bytes)
      let scaled = builtin.bls12_381_g1_scalar_mul(
        builtin.bytearray_to_integer(True, input_bytes),
        ic_point,
      )
      let new_acc = builtin.bls12_381_g1_add(acc, scaled)
      compute_vk_x(new_acc, remaining_ic, remaining_inputs)
    }
  }
}
