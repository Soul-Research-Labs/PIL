/**
 * Cosmos (CosmWasm) transaction builder for PIL privacy pool operations.
 * Uses @cosmjs/cosmwasm-stargate for message construction and query helpers.
 */

import type { Coin } from "@cosmjs/stargate";

export interface CosmosPoolConfig {
  /** Bech32 contract address of the deployed PIL CosmWasm contract. */
  contractAddress: string;
  /** Native denom used by the pool (e.g., "uatom", "uosmo"). */
  denom: string;
  /** RPC endpoint URL. */
  rpcUrl: string;
  /** Chain ID (e.g., "cosmoshub-4", "osmosis-1"). */
  chainId: string;
  /** Gas price in the pool denom (e.g. "0.025uatom"). */
  gasPrice?: string;
}

/** An unsigned CosmWasm execute message ready to sign. */
export interface CosmosTxPayload {
  contractAddress: string;
  msg: Record<string, unknown>;
  funds: Coin[];
}

/** Gas estimation result. */
export interface GasEstimate {
  /** Estimated gas units. */
  gasWanted: number;
  /** Fee amount in the pool denom. */
  fee: Coin;
}

/** Pool on-chain status. */
export interface PoolStatus {
  noteCount: number;
  nullifierCount: number;
  poolBalance: string;
  currentEpoch: number;
}

/** Epoch root query result. */
export interface EpochRootResult {
  epoch: number;
  root: string;
}

/**
 * Builds CosmWasm execute messages that interact with the PIL contract
 * defined in contracts/cosmwasm/.
 */
export class CosmosTxBuilder {
  constructor(private readonly config: CosmosPoolConfig) {}

  /**
   * Build a Deposit execute message.
   *
   * @param commitment - 32-byte hex note commitment
   * @param amount - deposit amount (string, in smallest denom unit)
   */
  buildDeposit(commitment: string, amount: string): CosmosTxPayload {
    return {
      contractAddress: this.config.contractAddress,
      msg: {
        deposit: { commitment },
      },
      funds: [{ denom: this.config.denom, amount }],
    };
  }

  /**
   * Build a Transfer execute message.
   */
  buildTransfer(
    proof: string,
    merkleRoot: string,
    nullifiers: string[],
    outputCommitments: string[],
    domainChainId: number,
    domainAppId: number,
  ): CosmosTxPayload {
    return {
      contractAddress: this.config.contractAddress,
      msg: {
        transfer: {
          proof,
          merkle_root: merkleRoot,
          nullifiers,
          output_commitments: outputCommitments,
          domain_chain_id: domainChainId,
          domain_app_id: domainAppId,
        },
      },
      funds: [],
    };
  }

  /**
   * Build a Withdraw execute message.
   */
  buildWithdraw(
    proof: string,
    merkleRoot: string,
    nullifiers: string[],
    changeCommitments: string[],
    exitAmount: string,
    recipient: string,
  ): CosmosTxPayload {
    return {
      contractAddress: this.config.contractAddress,
      msg: {
        withdraw: {
          proof,
          merkle_root: merkleRoot,
          nullifiers,
          change_commitments: changeCommitments,
          exit_amount: exitAmount,
          recipient,
        },
      },
      funds: [],
    };
  }

  /**
   * Build a FinalizeEpoch execute message (admin-only).
   */
  buildFinalizeEpoch(): CosmosTxPayload {
    return {
      contractAddress: this.config.contractAddress,
      msg: { finalize_epoch: {} },
      funds: [],
    };
  }

  /**
   * Build a query for pool status.
   */
  queryStatus(): Record<string, unknown> {
    return { status: {} };
  }

  /**
   * Build a query for nullifier status.
   */
  queryNullifier(nullifier: string): Record<string, unknown> {
    return { nullifier_status: { nullifier } };
  }

  /**
   * Build a query for an epoch root.
   */
  queryEpochRoot(epoch: number): Record<string, unknown> {
    return { epoch_root: { epoch } };
  }

  /**
   * Estimate gas for an execute message.
   * Uses a fixed multiplier over a base cost per message type.
   */
  estimateGas(
    msgType: "deposit" | "transfer" | "withdraw" | "finalize_epoch",
    multiplier = 1.4,
  ): GasEstimate {
    const baseCosts: Record<string, number> = {
      deposit: 200_000,
      transfer: 450_000,
      withdraw: 400_000,
      finalize_epoch: 150_000,
    };
    const gasWanted = Math.ceil((baseCosts[msgType] ?? 300_000) * multiplier);
    const priceNum = parseFloat(this.config.gasPrice ?? "0.025");
    const feeAmount = Math.ceil(gasWanted * priceNum).toString();
    return {
      gasWanted,
      fee: { denom: this.config.denom, amount: feeAmount },
    };
  }

  /**
   * Build a signed execute message envelope with gas estimation.
   * Wraps a CosmosTxPayload with the estimated fee for convenience.
   */
  withGas(
    payload: CosmosTxPayload,
    msgType: "deposit" | "transfer" | "withdraw" | "finalize_epoch",
  ): CosmosTxPayload & { estimatedGas: GasEstimate } {
    return {
      ...payload,
      estimatedGas: this.estimateGas(msgType),
    };
  }
}
