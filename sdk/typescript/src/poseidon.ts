/**
 * Poseidon hash wrapper for the PIL SDK.
 *
 * Uses poseidon-lite, a pure JavaScript implementation of the Poseidon hash
 * function over the BN254 scalar field. This provides ZK-friendly hashing
 * compatible with the Halo2 circuits used in PIL.
 *
 * The Pallas curve scalar field and BN254 scalar field are both ~254-bit
 * primes; we operate on byte representations and reduce mod p as needed.
 */

import { poseidon2 } from "poseidon-lite";

/**
 * The BN254 scalar field prime (used by poseidon-lite).
 * p = 21888242871839275222246405745257275088548364400416034343698204186575808495617
 */
const BN254_P = BigInt(
  "21888242871839275222246405745257275088548364400416034343698204186575808495617",
);

/** Convert a Uint8Array to a bigint (big-endian). */
function bytesToBigInt(bytes: Uint8Array): bigint {
  let result = 0n;
  for (const b of bytes) {
    result = (result << 8n) | BigInt(b);
  }
  return result;
}

/** Convert a bigint to a 32-byte Uint8Array (big-endian). */
function bigIntToBytes(n: bigint): Uint8Array {
  const bytes = new Uint8Array(32);
  let val = n;
  for (let i = 31; i >= 0; i--) {
    bytes[i] = Number(val & 0xffn);
    val >>= 8n;
  }
  return bytes;
}

/**
 * Hash arbitrary bytes into a single field element using Poseidon.
 *
 * Splits the input into 31-byte chunks (to fit in a field element),
 * converts each to a field element, then iteratively hashes pairs
 * using poseidon2 (the 2-input variant) in a Merkle-Damgård-like chain:
 *
 *   state = chunks[0]
 *   for i in 1..chunks.length:
 *     state = poseidon2([state, chunks[i]])
 *
 * If input is empty, returns poseidon2([0, 0]).
 */
export function poseidonHash(data: Uint8Array): Uint8Array {
  if (data.length === 0) {
    return bigIntToBytes(poseidon2([0n, 0n]));
  }

  // Split into 31-byte chunks (each fits in a field element < p)
  const chunks: bigint[] = [];
  for (let i = 0; i < data.length; i += 31) {
    const chunk = data.slice(i, Math.min(i + 31, data.length));
    const fe = bytesToBigInt(chunk) % BN254_P;
    chunks.push(fe);
  }

  // Merkle-Damgård chain using poseidon2
  let state = chunks[0];
  for (let i = 1; i < chunks.length; i++) {
    state = poseidon2([state, chunks[i]]);
  }

  // Final squeeze: hash with a domain separator (length)
  state = poseidon2([state, BigInt(data.length)]);

  return bigIntToBytes(state);
}

/**
 * Hash two field elements using Poseidon-2.
 * Useful for Merkle tree hashing where left and right are already field elements.
 */
export function poseidonHash2(
  left: Uint8Array,
  right: Uint8Array,
): Uint8Array {
  const l = bytesToBigInt(left) % BN254_P;
  const r = bytesToBigInt(right) % BN254_P;
  return bigIntToBytes(poseidon2([l, r]));
}
