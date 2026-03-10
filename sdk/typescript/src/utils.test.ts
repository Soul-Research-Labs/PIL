import { describe, it, expect } from "vitest";
import { bytesToHex, hexToBytes, concatBytes, sha256 } from "./utils.js";

describe("bytesToHex", () => {
  it("converts empty array", () => {
    expect(bytesToHex(new Uint8Array([]))).toBe("");
  });

  it("converts bytes to hex", () => {
    expect(bytesToHex(new Uint8Array([0xde, 0xad, 0xbe, 0xef]))).toBe(
      "deadbeef",
    );
  });

  it("pads single-digit hex values", () => {
    expect(bytesToHex(new Uint8Array([0, 1, 15]))).toBe("00010f");
  });
});

describe("hexToBytes", () => {
  it("converts hex to bytes", () => {
    const bytes = hexToBytes("deadbeef");
    expect(Array.from(bytes)).toEqual([0xde, 0xad, 0xbe, 0xef]);
  });

  it("throws on odd-length hex", () => {
    expect(() => hexToBytes("abc")).toThrow("even length");
  });

  it("roundtrips with bytesToHex", () => {
    const original = new Uint8Array([1, 2, 3, 255, 0]);
    expect(hexToBytes(bytesToHex(original))).toEqual(original);
  });
});

describe("concatBytes", () => {
  it("concatenates arrays", () => {
    const a = new Uint8Array([1, 2]);
    const b = new Uint8Array([3, 4]);
    expect(Array.from(concatBytes(a, b))).toEqual([1, 2, 3, 4]);
  });

  it("handles empty arrays", () => {
    const a = new Uint8Array([]);
    const b = new Uint8Array([1]);
    expect(Array.from(concatBytes(a, b))).toEqual([1]);
  });
});

describe("sha256", () => {
  it("produces 32-byte hash", () => {
    const hash = sha256(new Uint8Array([1, 2, 3]));
    expect(hash.length).toBe(32);
  });

  it("is deterministic", () => {
    const input = new Uint8Array([42]);
    expect(sha256(input)).toEqual(sha256(input));
  });

  it("different inputs produce different hashes", () => {
    const h1 = sha256(new Uint8Array([1]));
    const h2 = sha256(new Uint8Array([2]));
    expect(h1).not.toEqual(h2);
  });
});
