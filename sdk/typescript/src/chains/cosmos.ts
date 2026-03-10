/**
 * Cosmos (CosmWasm) transaction builder for PIL privacy pool operations.
 * Uses @cosmjs/cosmwasm-stargate for message construction.
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
}

/** An unsigned CosmWasm execute message ready to sign. */
export interface CosmosTxPayload {
  contractAddress: string;
  msg: Record<string, unknown>;
  funds: Coin[];
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
}
