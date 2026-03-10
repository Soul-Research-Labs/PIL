/**
 * Cardano transaction builder for PIL privacy pool operations.
 * Uses @emurgo/cardano-serialization-lib for UTXO handling and CBOR
 * serialization of Plutus datum / redeemer structures that correspond
 * to the Aiken validators in contracts/cardano/.
 */

import * as CSL from "@emurgo/cardano-serialization-lib-nodejs";

export interface CardanoPoolConfig {
  /** Bech32 script address of the privacy pool validator. */
  poolScriptAddress: string;
  /** Policy ID of the PIL pool NFT (hex). */
  poolNftPolicyId: string;
  /** Asset name of the pool NFT (hex). */
  poolNftAssetName: string;
  /** Network ID: 0 = testnet, 1 = mainnet. */
  networkId: number;
}

/** Encoded Cardano transaction ready to sign + submit. */
export interface CardanoTxPayload {
  /** CBOR-hex encoded unsigned transaction. */
  txCborHex: string;
  /** Plutus redeemer JSON (for wallet signing). */
  redeemer: Record<string, unknown>;
  /** Datum to attach (for deposit). */
  datum?: Record<string, unknown>;
}

/**
 * Builds Cardano transactions that interact with the PIL Aiken validators.
 * Uses @emurgo/cardano-serialization-lib for CBOR encoding of Plutus
 * data structures (datum, redeemer) and transaction body construction.
 */
export class CardanoTxBuilder {
  constructor(private readonly config: CardanoPoolConfig) {}

  /**
   * Build a deposit transaction.
   *
   * @param commitment - 32-byte hex note commitment
   * @param amountLovelace - deposit amount in lovelace
   * @param utxos - available UTXOs (CBOR-hex array)
   * @param changeAddress - bech32 change address
   */
  buildDeposit(
    commitment: string,
    amountLovelace: bigint,
    utxos: string[],
    changeAddress: string,
  ): CardanoTxPayload {
    // Datum: PoolDatum inline with new commitment appended
    const datum = {
      constructor: 0,
      fields: [{ bytes: commitment }],
    };

    // Redeemer: PoolRedeemer::Deposit { commitment, amount }
    const redeemer = {
      constructor: 0, // Deposit variant
      fields: [{ bytes: commitment }, { int: amountLovelace.toString() }],
    };

    // Encode Plutus datum as CBOR
    const plutusDatum = encodePlutusData(datum);
    const plutusRedeemer = encodePlutusData(redeemer);

    // Build CBOR transaction body
    const txBuilder = createTxBuilder();
    const scriptAddr = CSL.Address.from_bech32(this.config.poolScriptAddress);

    // Add inputs from provided UTXOs
    const txInputsBuilder = CSL.TxInputsBuilder.new();
    for (const utxoCbor of utxos) {
      const utxo = CSL.TransactionUnspentOutput.from_hex(utxoCbor);
      txInputsBuilder.add_regular_input(
        utxo.output().address(),
        utxo.input(),
        utxo.output().amount(),
      );
    }
    txBuilder.set_inputs(txInputsBuilder);

    // Add output to script address with inline datum
    const outputValue = CSL.Value.new(
      CSL.BigNum.from_str(amountLovelace.toString()),
    );
    const outputBuilder = CSL.TransactionOutputBuilder.new()
      .with_address(scriptAddr)
      .with_data_hash(CSL.hash_plutus_data(plutusDatum));
    txBuilder.add_output(outputBuilder.next().with_value(outputValue).build());

    // Set change
    const change = CSL.Address.from_bech32(changeAddress);
    txBuilder.add_change_if_needed(change);

    const txBody = txBuilder.build();
    const txCborHex = Buffer.from(txBody.to_bytes()).toString("hex");

    return { txCborHex, redeemer, datum };
  }

  /**
   * Build a transfer transaction (private, within the pool).
   */
  buildTransfer(
    proof: string,
    merkleRoot: string,
    nullifiers: string[],
    outputCommitments: string[],
  ): CardanoTxPayload {
    const redeemer = {
      constructor: 1, // Transfer variant
      fields: [
        { bytes: proof },
        { bytes: merkleRoot },
        { list: nullifiers.map((n) => ({ bytes: n })) },
        { list: outputCommitments.map((c) => ({ bytes: c })) },
      ],
    };

    const plutusRedeemer = encodePlutusData(redeemer);
    const txCborHex = Buffer.from(plutusRedeemer.to_bytes()).toString("hex");

    return { txCborHex, redeemer };
  }

  /**
   * Build a withdraw transaction.
   */
  buildWithdraw(
    proof: string,
    merkleRoot: string,
    nullifiers: string[],
    changeCommitments: string[],
    exitAmountLovelace: bigint,
    recipientAddress: string,
  ): CardanoTxPayload {
    const redeemer = {
      constructor: 2, // Withdraw variant
      fields: [
        { bytes: proof },
        { bytes: merkleRoot },
        { list: nullifiers.map((n) => ({ bytes: n })) },
        { list: changeCommitments.map((c) => ({ bytes: c })) },
        { int: exitAmountLovelace.toString() },
        { bytes: recipientAddress },
      ],
    };

    const plutusRedeemer = encodePlutusData(redeemer);
    const txCborHex = Buffer.from(plutusRedeemer.to_bytes()).toString("hex");

    return { txCborHex, redeemer };
  }
}

// ---------------------------------------------------------------------------
// Internal helpers — Plutus data encoding via CSL
// ---------------------------------------------------------------------------

interface PlutusField {
  bytes?: string;
  int?: string;
  list?: PlutusField[];
}

interface PlutusStructure {
  constructor: number;
  fields: PlutusField[];
}

/** Encode a JSON-style Plutus datum/redeemer to CSL PlutusData. */
function encodePlutusData(data: PlutusStructure): CSL.PlutusData {
  const fields = CSL.PlutusList.new();
  for (const f of data.fields) {
    fields.add(encodeField(f));
  }
  return CSL.PlutusData.new_constr_plutus_data(
    CSL.ConstrPlutusData.new(
      CSL.BigNum.from_str(data.constructor.toString()),
      fields,
    ),
  );
}

function encodeField(f: PlutusField): CSL.PlutusData {
  if (f.bytes !== undefined) {
    return CSL.PlutusData.new_bytes(Buffer.from(f.bytes, "hex"));
  }
  if (f.int !== undefined) {
    return CSL.PlutusData.new_integer(CSL.BigInt.from_str(f.int));
  }
  if (f.list !== undefined) {
    const list = CSL.PlutusList.new();
    for (const item of f.list) {
      list.add(encodeField(item));
    }
    return CSL.PlutusData.new_list(list);
  }
  return CSL.PlutusData.new_bytes(Buffer.alloc(0));
}

/** Create a TransactionBuilder with Cardano Babbage-era protocol params. */
function createTxBuilder(): CSL.TransactionBuilder {
  const cfg = CSL.TransactionBuilderConfigBuilder.new()
    .fee_algo(CSL.LinearFee.new(
      CSL.BigNum.from_str("44"),
      CSL.BigNum.from_str("155381"),
    ))
    .pool_deposit(CSL.BigNum.from_str("500000000"))
    .key_deposit(CSL.BigNum.from_str("2000000"))
    .coins_per_utxo_byte(CSL.BigNum.from_str("4310"))
    .max_value_size(5000)
    .max_tx_size(16384)
    .build();
  return CSL.TransactionBuilder.new(cfg);
}
