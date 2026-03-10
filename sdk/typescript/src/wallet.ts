import { type NoteData, NoteManager } from "./note.js";
import { ChainDomain } from "./domain.js";

/** A note held in the wallet with its tree position. */
export interface WalletNote {
  note: NoteData;
  leafIndex: number;
  spent: boolean;
}

/**
 * In-memory wallet that tracks unspent notes across chains.
 * For production use, extend with encrypted persistence (IndexedDB / file).
 */
export class PilWallet {
  private notes: Map<string, WalletNote> = new Map(); // commitment → WalletNote

  /** Add a newly created note to the wallet. */
  addNote(note: NoteData, leafIndex: number): void {
    this.notes.set(note.commitment, { note, leafIndex, spent: false });
  }

  /** Mark a note as spent by its commitment. */
  markSpent(commitment: string): void {
    const entry = this.notes.get(commitment);
    if (entry) entry.spent = true;
  }

  /** Get all unspent notes, optionally filtered by chain. */
  unspentNotes(chain?: ChainDomain): WalletNote[] {
    const result: WalletNote[] = [];
    for (const wn of this.notes.values()) {
      if (!wn.spent && (chain === undefined || wn.note.chain === chain)) {
        result.push(wn);
      }
    }
    return result;
  }

  /** Total unspent balance, optionally filtered by chain. */
  balance(chain?: ChainDomain): bigint {
    return this.unspentNotes(chain).reduce(
      (sum, wn) => sum + wn.note.value,
      0n,
    );
  }

  /**
   * Select notes whose combined value meets the target.
   * Returns selected notes and the change amount.
   */
  selectNotes(
    target: bigint,
    chain: ChainDomain,
  ): { selected: WalletNote[]; change: bigint } {
    const available = this.unspentNotes(chain);
    // Sort largest-first for simple greedy coin selection
    available.sort((a, b) =>
      a.note.value > b.note.value ? -1 : a.note.value < b.note.value ? 1 : 0,
    );

    const selected: WalletNote[] = [];
    let sum = 0n;
    for (const wn of available) {
      if (sum >= target) break;
      selected.push(wn);
      sum += wn.note.value;
    }
    if (sum < target) {
      throw new Error(`Insufficient balance: need ${target}, have ${sum}`);
    }
    return { selected, change: sum - target };
  }

  /** Derive nullifiers for a set of wallet notes. */
  deriveNullifiers(notes: WalletNote[]): string[] {
    return notes.map((wn) =>
      NoteManager.deriveNullifier(
        wn.note.nullifierKey,
        wn.leafIndex,
        wn.note.chain,
        wn.note.appId,
      ),
    );
  }

  /** Number of total notes in the wallet. */
  get size(): number {
    return this.notes.size;
  }

  /** Export wallet state as JSON-serialisable array (for persistence). */
  export(): WalletNote[] {
    return Array.from(this.notes.values());
  }

  /** Import wallet notes from a previously exported array. */
  import(notes: WalletNote[]): void {
    for (const wn of notes) {
      this.notes.set(wn.note.commitment, wn);
    }
  }
}
