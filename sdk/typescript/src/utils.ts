import { randomBytes as nodeRandomBytes, createHash } from "node:crypto";

/** Convert a Uint8Array to a hex string. */
export function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

/** Convert a hex string to a Uint8Array. */
export function hexToBytes(hex: string): Uint8Array {
  if (hex.length % 2 !== 0) {
    throw new Error("hex string must have even length");
  }
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    bytes[i / 2] = parseInt(hex.substring(i, i + 2), 16);
  }
  return bytes;
}

/** Generate cryptographically secure random bytes. */
export function randomBytes(length: number): Uint8Array {
  return new Uint8Array(nodeRandomBytes(length));
}

/** Concatenate multiple Uint8Arrays. */
export function concatBytes(...arrays: Uint8Array[]): Uint8Array {
  const totalLen = arrays.reduce((sum, a) => sum + a.length, 0);
  const result = new Uint8Array(totalLen);
  let offset = 0;
  for (const arr of arrays) {
    result.set(arr, offset);
    offset += arr.length;
  }
  return result;
}

/** SHA-256 hash. */
export function sha256(data: Uint8Array): Uint8Array {
  const hash = createHash("sha256");
  hash.update(data);
  return new Uint8Array(hash.digest());
}
