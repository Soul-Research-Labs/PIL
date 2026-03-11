import { describe, it, expect } from "vitest";
import { CosmosTxBuilder } from "./cosmos.js";
import type { CosmosPoolConfig, CosmosTxPayload } from "./cosmos.js";

const config: CosmosPoolConfig = {
  contractAddress: "cosmos1abc123def456",
  denom: "uatom",
  rpcUrl: "http://localhost:26657",
  chainId: "cosmoshub-4",
  gasPrice: "0.025",
};

describe("CosmosTxBuilder", () => {
  const builder = new CosmosTxBuilder(config);

  describe("buildDeposit", () => {
    it("produces correct execute message", () => {
      const tx = builder.buildDeposit("aabbccdd", "1000000");
      expect(tx.contractAddress).toBe(config.contractAddress);
      expect(tx.msg).toEqual({ deposit: { commitment: "aabbccdd" } });
      expect(tx.funds).toEqual([{ denom: "uatom", amount: "1000000" }]);
    });
  });

  describe("buildTransfer", () => {
    it("includes all transfer fields", () => {
      const tx = builder.buildTransfer(
        "proof_hex",
        "root_hex",
        ["nf1", "nf2"],
        ["out1"],
        1,
        10,
      );
      expect(tx.msg).toHaveProperty("transfer");
      const transfer = tx.msg.transfer as Record<string, unknown>;
      expect(transfer.merkle_root).toBe("root_hex");
      expect(transfer.nullifiers).toEqual(["nf1", "nf2"]);
      expect(transfer.output_commitments).toEqual(["out1"]);
      expect(transfer.domain_chain_id).toBe(1);
      expect(transfer.domain_app_id).toBe(10);
      expect(tx.funds).toEqual([]);
    });
  });

  describe("buildWithdraw", () => {
    it("includes recipient and exit amount", () => {
      const tx = builder.buildWithdraw(
        "proof",
        "root",
        ["nf"],
        ["change"],
        "500000",
        "cosmos1recipient",
      );
      const w = tx.msg.withdraw as Record<string, unknown>;
      expect(w.exit_amount).toBe("500000");
      expect(w.recipient).toBe("cosmos1recipient");
      expect(w.change_commitments).toEqual(["change"]);
    });
  });

  describe("buildFinalizeEpoch", () => {
    it("produces admin message with no funds", () => {
      const tx = builder.buildFinalizeEpoch();
      expect(tx.msg).toEqual({ finalize_epoch: {} });
      expect(tx.funds).toEqual([]);
    });
  });

  describe("queries", () => {
    it("queryStatus", () => {
      expect(builder.queryStatus()).toEqual({ status: {} });
    });

    it("queryNullifier", () => {
      expect(builder.queryNullifier("nf_hex")).toEqual({
        nullifier_status: { nullifier: "nf_hex" },
      });
    });

    it("queryEpochRoot", () => {
      expect(builder.queryEpochRoot(3)).toEqual({
        epoch_root: { epoch: 3 },
      });
    });
  });

  describe("estimateGas", () => {
    it("computes gas for deposit", () => {
      const est = builder.estimateGas("deposit");
      expect(est.gasWanted).toBe(Math.ceil(200_000 * 1.4));
      expect(est.fee.denom).toBe("uatom");
      expect(Number(est.fee.amount)).toBeGreaterThan(0);
    });

    it("uses custom multiplier", () => {
      const est = builder.estimateGas("transfer", 2.0);
      expect(est.gasWanted).toBe(Math.ceil(450_000 * 2.0));
    });

    it("defaults gasPrice when not set", () => {
      const noGas = new CosmosTxBuilder({ ...config, gasPrice: undefined });
      const est = noGas.estimateGas("withdraw");
      // Default price is 0.025
      expect(est.gasWanted).toBe(Math.ceil(400_000 * 1.4));
    });
  });

  describe("withGas", () => {
    it("wraps payload with gas estimate", () => {
      const payload: CosmosTxPayload = {
        contractAddress: config.contractAddress,
        msg: { finalize_epoch: {} },
        funds: [],
      };
      const result = builder.withGas(payload, "finalize_epoch");
      expect(result.estimatedGas).toBeDefined();
      expect(result.estimatedGas.gasWanted).toBeGreaterThan(0);
      expect(result.contractAddress).toBe(config.contractAddress);
    });
  });
});
