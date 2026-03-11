import { describe, it, expect } from "vitest";
import type { CardanoPoolConfig, CardanoTxPayload } from "./cardano.js";

/**
 * Cardano builder tests — structure and type validation only.
 * The full CSL-dependent build methods require the native
 * @emurgo/cardano-serialization-lib-nodejs to be installed.
 * These tests validate the config and payload shapes independently.
 */

describe("CardanoPoolConfig", () => {
  const config: CardanoPoolConfig = {
    poolScriptAddress:
      "addr_test1wz0r0qx5nxlqxn8hnr3pk8hk4cqylwvkqm0jvkjhxtepsgf3hx3",
    poolNftPolicyId: "aa".repeat(28),
    poolNftAssetName: "bb".repeat(8),
    networkId: 0,
  };

  it("has required fields", () => {
    expect(config.poolScriptAddress).toBeDefined();
    expect(config.poolNftPolicyId).toHaveLength(56);
    expect(config.poolNftAssetName).toHaveLength(16);
    expect(config.networkId).toBe(0);
  });

  it("distinguishes testnet and mainnet", () => {
    const mainnet: CardanoPoolConfig = { ...config, networkId: 1 };
    expect(mainnet.networkId).toBe(1);
  });
});

describe("CardanoTxPayload shape", () => {
  it("represents a deposit payload", () => {
    const payload: CardanoTxPayload = {
      txCborHex: "a100818258200000",
      redeemer: {
        constructor: 0,
        fields: [{ bytes: "aabb" }, { int: "2000000" }],
      },
      datum: {
        constructor: 0,
        fields: [{ bytes: "aabb" }],
      },
    };

    expect(payload.txCborHex).toBeDefined();
    expect(payload.redeemer.constructor).toBe(0);
    expect(payload.datum).toBeDefined();
  });

  it("represents a transfer payload (no datum)", () => {
    const payload: CardanoTxPayload = {
      txCborHex: "a100818258200001",
      redeemer: {
        constructor: 1,
        fields: [
          { bytes: "proof" },
          { bytes: "root" },
          { list: [{ bytes: "nf1" }] },
          { list: [{ bytes: "out1" }] },
        ],
      },
    };

    expect(payload.datum).toBeUndefined();
    expect(payload.redeemer.constructor).toBe(1);
  });

  it("represents a withdraw payload", () => {
    const payload: CardanoTxPayload = {
      txCborHex: "a100818258200002",
      redeemer: {
        constructor: 2,
        fields: [
          { bytes: "proof" },
          { bytes: "root" },
          { list: [{ bytes: "nf1" }] },
          { list: [] },
          { int: "5000000" },
          { bytes: "addr_test1abc" },
        ],
      },
    };

    expect(payload.redeemer.constructor).toBe(2);
  });
});
