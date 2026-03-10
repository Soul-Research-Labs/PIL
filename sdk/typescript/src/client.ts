import { type ProverBackend, type Proof } from "./prover.js";
import { PilWallet, type WalletNote } from "./wallet.js";
import { NoteManager, type NoteData } from "./note.js";
import { ChainDomain } from "./domain.js";
import { bytesToHex, randomBytes } from "./utils.js";

export interface PilClientConfig {
  /** Prover backend (WASM or mock). */
  prover: ProverBackend;
  /** Owner's public key (32 bytes hex). */
  ownerPubKey: string;
  /** Default chain domain. */
  defaultChain: ChainDomain;
  /** Default app ID. */
  defaultAppId: number;
}

/**
 * High-level client orchestrating deposit → transfer → withdraw flows.
 * Chain-specific transaction builders are composed separately.
 */
export class PilClient {
  readonly wallet: PilWallet;
  private readonly prover: ProverBackend;
  private readonly ownerPubKey: string;
  private readonly defaultChain: ChainDomain;
  private readonly defaultAppId: number;

  constructor(config: PilClientConfig) {
    this.wallet = new PilWallet();
    this.prover = config.prover;
    this.ownerPubKey = config.ownerPubKey;
    this.defaultChain = config.defaultChain;
    this.defaultAppId = config.defaultAppId;
  }

  /**
   * Create a deposit note. Returns the note data and commitment
   * to submit on-chain. The note is added to the wallet once
   * the on-chain tx is confirmed (call `confirmDeposit`).
   */
  createDepositNote(
    value: bigint,
    chain?: ChainDomain,
    appId?: number,
  ): NoteData {
    return NoteManager.create({
      value,
      ownerPubKey: this.ownerPubKey,
      chain: chain ?? this.defaultChain,
      appId: appId ?? this.defaultAppId,
    });
  }

  /** After a deposit tx is confirmed on-chain, track the note. */
  confirmDeposit(note: NoteData, leafIndex: number): void {
    this.wallet.addNote(note, leafIndex);
  }

  /**
   * Build a private transfer.
   * Returns the proof and transaction payload (nullifiers + output commitments).
   */
  async transfer(
    amount: bigint,
    recipientPubKey: string,
    merkleRoot: string,
    merklePaths: Map<number, string[]>,
    chain?: ChainDomain,
    appId?: number,
  ): Promise<{
    proof: Proof;
    nullifiers: string[];
    outputCommitments: string[];
    outputNotes: NoteData[];
  }> {
    const ch = chain ?? this.defaultChain;
    const app = appId ?? this.defaultAppId;

    const { selected, change } = this.wallet.selectNotes(amount, ch);
    const nullifiers = this.wallet.deriveNullifiers(selected);

    // Build output notes
    const outputNotes: NoteData[] = [];

    // Recipient note
    const recipientNote = NoteManager.create({
      value: amount,
      ownerPubKey: recipientPubKey,
      chain: ch,
      appId: app,
    });
    outputNotes.push(recipientNote);

    // Change note (if any)
    if (change > 0n) {
      const changeNote = NoteManager.create({
        value: change,
        ownerPubKey: this.ownerPubKey,
        chain: ch,
        appId: app,
      });
      outputNotes.push(changeNote);
    }

    const proof = await this.prover.prove({
      type: "transfer",
      merkleRoot,
      inputs: selected.map((wn) => ({
        nullifierKey: wn.note.nullifierKey,
        leafIndex: wn.leafIndex,
        value: wn.note.value,
        merklePath: merklePaths.get(wn.leafIndex) ?? [],
      })),
      outputs: outputNotes.map((n) => ({
        commitment: n.commitment,
        value: n.value,
      })),
    });

    // Mark inputs as spent
    for (const wn of selected) {
      this.wallet.markSpent(wn.note.commitment);
    }

    return {
      proof,
      nullifiers,
      outputCommitments: outputNotes.map((n) => n.commitment),
      outputNotes,
    };
  }

  /**
   * Build a withdrawal.
   * Returns the proof and transaction payload.
   */
  async withdraw(
    amount: bigint,
    recipient: string,
    merkleRoot: string,
    merklePaths: Map<number, string[]>,
    chain?: ChainDomain,
    appId?: number,
  ): Promise<{
    proof: Proof;
    nullifiers: string[];
    changeCommitments: string[];
    changeNotes: NoteData[];
  }> {
    const ch = chain ?? this.defaultChain;
    const app = appId ?? this.defaultAppId;

    const { selected, change } = this.wallet.selectNotes(amount, ch);
    const nullifiers = this.wallet.deriveNullifiers(selected);

    const changeNotes: NoteData[] = [];
    if (change > 0n) {
      const changeNote = NoteManager.create({
        value: change,
        ownerPubKey: this.ownerPubKey,
        chain: ch,
        appId: app,
      });
      changeNotes.push(changeNote);
    }

    const proof = await this.prover.prove({
      type: "withdraw",
      merkleRoot,
      inputs: selected.map((wn) => ({
        nullifierKey: wn.note.nullifierKey,
        leafIndex: wn.leafIndex,
        value: wn.note.value,
        merklePath: merklePaths.get(wn.leafIndex) ?? [],
      })),
      outputs: changeNotes.map((n) => ({
        commitment: n.commitment,
        value: n.value,
      })),
      exitAmount: amount,
      recipient,
    });

    for (const wn of selected) {
      this.wallet.markSpent(wn.note.commitment);
    }

    return {
      proof,
      nullifiers,
      changeCommitments: changeNotes.map((n) => n.commitment),
      changeNotes,
    };
  }
}
