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
