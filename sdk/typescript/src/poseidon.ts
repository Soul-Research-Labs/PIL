/**
 * Poseidon hash wrapper for the PIL SDK.
 *
 * **IMPORTANT**: This implementation operates over the Pallas base field,
 * matching the Rust `pil-primitives` crate. Parameters:
 *   - Width 3 (rate 2, capacity 1)
 *   - Full rounds: 8, Partial rounds: 56
 *   - S-box: x^5
 *   - MDS: Cauchy matrix from x=[0,1,2], y=[3,4,5]
 *   - Round constants: Blake2b-derived (matching `generate_round_constants()` in Rust)
 *
 * The Pallas base field prime:
 *   p = 0x40000000000000000000000000000000224698fc094cf91b992d30ed00000001
 */

/**
 * The Pallas base field modulus.
 * p = 28948022309329048855892746252171976963363056481941560715954676764349967630337
 */
const PALLAS_P = BigInt(
  "28948022309329048855892746252171976963363056481941560715954676764349967630337",
);

const WIDTH = 3;
const FULL_ROUNDS = 8;
const PARTIAL_ROUNDS = 56;
const TOTAL_ROUNDS = FULL_ROUNDS + PARTIAL_ROUNDS;

/** Modular arithmetic helpers for Pallas field. */
function mod(a: bigint, p: bigint = PALLAS_P): bigint {
  const r = a % p;
  return r >= 0n ? r : r + p;
}

function addMod(a: bigint, b: bigint): bigint {
  return mod(a + b);
}

function mulMod(a: bigint, b: bigint): bigint {
  return mod(a * b);
}

function invMod(a: bigint, p: bigint = PALLAS_P): bigint {
  // Extended Euclidean algorithm
  let [old_r, r] = [a, p];
  let [old_s, s] = [1n, 0n];
  while (r !== 0n) {
    const q = old_r / r;
    [old_r, r] = [r, old_r - q * r];
    [old_s, s] = [s, old_s - q * s];
  }
  return mod(old_s, p);
}

/** S-box: x^5 mod p */
function sbox(x: bigint): bigint {
  const x2 = mulMod(x, x);
  const x4 = mulMod(x2, x2);
  return mulMod(x4, x);
}

/**
 * Generate round constants matching the Rust implementation.
 * Uses Blake2b-512 with domain tag "PIL_Poseidon_RC_" || index.
 *
 * Since we can't easily use Blake2b in pure TS without a dependency,
 * we use a SHA-256-based equivalent that produces deterministic constants.
 *
 * **NOTE**: For full cross-language compatibility, this should match the
 * exact Rust `generate_round_constants()` output. In production, these
 * constants should be precomputed and hardcoded from the Rust implementation.
 *
 * For now, we use a placeholder that will be replaced with the actual
 * constants exported from the Rust crate via WASM or a build script.
 */
let _cachedRoundConstants: bigint[] | null = null;
let _cachedMDS: bigint[][] | null = null;

/**
 * Compute the Cauchy MDS matrix: M[i][j] = 1 / (x_i + y_j)
 * where x_i = i, y_j = WIDTH + j (matching Rust: x={0,1,2}, y={3,4,5}).
 */
function getMDS(): bigint[][] {
  if (_cachedMDS) return _cachedMDS;
  const m: bigint[][] = [];
  for (let i = 0; i < WIDTH; i++) {
    const row: bigint[] = [];
    for (let j = 0; j < WIDTH; j++) {
      const sum = BigInt(i + WIDTH + j);
      row.push(invMod(sum));
    }
    m.push(row);
  }
  _cachedMDS = m;
  return m;
}

/** MDS matrix-vector multiply */
function mdsMultiply(state: bigint[]): bigint[] {
  const m = getMDS();
  const out: bigint[] = new Array(WIDTH).fill(0n);
  for (let i = 0; i < WIDTH; i++) {
    for (let j = 0; j < WIDTH; j++) {
      out[i] = addMod(out[i], mulMod(m[i][j], state[j]));
    }
  }
  return out;
}

/** Convert a Uint8Array to a bigint (little-endian, matching Rust field repr). */
function bytesToFieldElement(bytes: Uint8Array): bigint {
  let result = 0n;
  for (let i = bytes.length - 1; i >= 0; i--) {
    result = (result << 8n) | BigInt(bytes[i]);
  }
  return mod(result);
}

/** Convert a bigint to a 32-byte Uint8Array (little-endian, matching Rust field repr). */
function fieldElementToBytes(n: bigint): Uint8Array {
  const bytes = new Uint8Array(32);
  let val = mod(n);
  for (let i = 0; i < 32; i++) {
    bytes[i] = Number(val & 0xffn);
    val >>= 8n;
  }
  return bytes;
}

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
 * Poseidon permutation over a WIDTH-element state.
 *
 * **IMPORTANT**: Round constants must be provided by the caller.
 * In production, these should be the exact constants from the Rust crate.
 */
function poseidonPermutation(
  state: bigint[],
  roundConstants: bigint[],
): bigint[] {
  let s = [...state];
  let rcIdx = 0;

  // First half of full rounds
  for (let r = 0; r < FULL_ROUNDS / 2; r++) {
    for (let j = 0; j < WIDTH; j++) {
      s[j] = addMod(s[j], roundConstants[rcIdx + j]);
    }
    rcIdx += WIDTH;
    for (let j = 0; j < WIDTH; j++) {
      s[j] = sbox(s[j]);
    }
    s = mdsMultiply(s);
  }

  // Partial rounds (S-box on first element only)
  for (let r = 0; r < PARTIAL_ROUNDS; r++) {
    for (let j = 0; j < WIDTH; j++) {
      s[j] = addMod(s[j], roundConstants[rcIdx + j]);
    }
    rcIdx += WIDTH;
    s[0] = sbox(s[0]);
    s = mdsMultiply(s);
  }

  // Second half of full rounds
  for (let r = 0; r < FULL_ROUNDS / 2; r++) {
    for (let j = 0; j < WIDTH; j++) {
      s[j] = addMod(s[j], roundConstants[rcIdx + j]);
    }
    rcIdx += WIDTH;
    for (let j = 0; j < WIDTH; j++) {
      s[j] = sbox(s[j]);
    }
    s = mdsMultiply(s);
  }

  return s;
}

/**
 * Poseidon hash of a single field element.
 * state = [0 (capacity), input, 0 (padding)]
 */
export function poseidonHashSingle(
  input: bigint,
  roundConstants: bigint[],
): bigint {
  const state = [0n, mod(input), 0n];
  const result = poseidonPermutation(state, roundConstants);
  return result[0];
}

/**
 * Poseidon hash of two field elements.
 * state = [0 (capacity), left, right]
 */
export function poseidonHash2Field(
  left: bigint,
  right: bigint,
  roundConstants: bigint[],
): bigint {
  const state = [0n, mod(left), mod(right)];
  const result = poseidonPermutation(state, roundConstants);
  return result[0];
}

/**
 * High-level API: Hash arbitrary bytes into a single field element using Poseidon.
 *
 * Splits the input into 31-byte chunks, converts each to a field element,
 * then chains using poseidon2 in a Merkle-Damgård-like construction.
 *
 * **Requires round constants** — call `setRoundConstants()` first or pass
 * constants directly. Without constants, throws an error.
 */
let _roundConstants: bigint[] | null = null;

/**
 * Set the round constants for the Poseidon hash.
 * These must match the Rust `generate_round_constants()` output exactly.
 * Export them from the Rust crate via WASM or a build script.
 */
export function setRoundConstants(constants: bigint[]): void {
  const expected = TOTAL_ROUNDS * WIDTH;
  if (constants.length !== expected) {
    throw new Error(
      `Expected ${expected} round constants, got ${constants.length}`,
    );
  }
  _roundConstants = constants;
}

function getRoundConstants(): bigint[] {
  if (!_roundConstants) {
    throw new Error(
      "Poseidon round constants not initialized. " +
        "Call setRoundConstants() with constants exported from the Rust pil-primitives crate. " +
        "The TS SDK and Rust must use identical constants for hash compatibility.",
    );
  }
  return _roundConstants;
}

/**
 * Hash arbitrary bytes into a single field element using Poseidon.
 */
export function poseidonHash(data: Uint8Array): Uint8Array {
  const rc = getRoundConstants();
  if (data.length === 0) {
    return bigIntToBytes(poseidonHash2Field(0n, 0n, rc));
  }

  // Split into 31-byte chunks (each fits in a field element < p)
  const chunks: bigint[] = [];
  for (let i = 0; i < data.length; i += 31) {
    const chunk = data.slice(i, Math.min(i + 31, data.length));
    const fe = bytesToBigInt(chunk) % PALLAS_P;
    chunks.push(fe);
  }

  // Merkle-Damgård chain using poseidon2
  let state = chunks[0];
  for (let i = 1; i < chunks.length; i++) {
    state = poseidonHash2Field(state, chunks[i], rc);
  }

  // Final squeeze: hash with a domain separator (length)
  state = poseidonHash2Field(state, BigInt(data.length), rc);

  return bigIntToBytes(state);
}

/**
 * Hash two field elements using Poseidon-2.
 * Input/output as 32-byte big-endian Uint8Arrays.
 */
export function poseidonHash2(left: Uint8Array, right: Uint8Array): Uint8Array {
  const rc = getRoundConstants();
  const l = bytesToBigInt(left) % PALLAS_P;
  const r = bytesToBigInt(right) % PALLAS_P;
  return bigIntToBytes(poseidonHash2Field(l, r, rc));
}
