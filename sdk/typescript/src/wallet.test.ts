import { describe, it, expect, beforeEach } from "vitest";
import { PilWallet } from "./wallet.js";
import { NoteManager } from "./note.js";
import { ChainDomain } from "./domain.js";

describe("PilWallet", () => {
  let wallet: PilWallet;
  const ownerPubKey = "ab".repeat(32);

  beforeEach(() => {
    wallet = new PilWallet();
  });

  it("starts empty", () => {
    expect(wallet.size).toBe(0);
    expect(wallet.balance()).toBe(0n);
  });

  it("tracks added notes", () => {
    const note = NoteManager.create({
      value: 100n,
      ownerPubKey,
      chain: ChainDomain.CardanoMainnet,
      appId: 0,
    });
    wallet.addNote(note, 0);
    expect(wallet.size).toBe(1);
    expect(wallet.balance()).toBe(100n);
  });

  it("marks notes as spent", () => {
    const note = NoteManager.create({
      value: 100n,
      ownerPubKey,
      chain: ChainDomain.CardanoMainnet,
      appId: 0,
    });
    wallet.addNote(note, 0);
    wallet.markSpent(note.commitment);
    expect(wallet.balance()).toBe(0n);
    expect(wallet.unspentNotes().length).toBe(0);
  });

  it("selects notes to meet target", () => {
    const n1 = NoteManager.create({
      value: 50n,
      ownerPubKey,
      chain: ChainDomain.CardanoMainnet,
      appId: 0,
    });
    const n2 = NoteManager.create({
      value: 70n,
      ownerPubKey,
      chain: ChainDomain.CardanoMainnet,
      appId: 0,
    });
    wallet.addNote(n1, 0);
    wallet.addNote(n2, 1);

    const { selected, change } = wallet.selectNotes(
      60n,
      ChainDomain.CardanoMainnet,
    );
    // Greedy largest-first: selects 70, change = 10
    expect(selected.length).toBe(1);
    expect(selected[0].note.value).toBe(70n);
    expect(change).toBe(10n);
  });

  it("throws on insufficient balance", () => {
    expect(() => wallet.selectNotes(100n, ChainDomain.CardanoMainnet)).toThrow(
      "Insufficient balance",
    );
  });

  it("exports and imports notes", () => {
    const note = NoteManager.create({
      value: 42n,
      ownerPubKey,
      chain: ChainDomain.CosmosHub,
      appId: 1,
    });
    wallet.addNote(note, 5);

    const exported = wallet.export();
    expect(exported.length).toBe(1);

    const wallet2 = new PilWallet();
    wallet2.import(exported);
    expect(wallet2.balance(ChainDomain.CosmosHub)).toBe(42n);
  });

  it("derives nullifiers for selected notes", () => {
    const note = NoteManager.create({
      value: 100n,
      ownerPubKey,
      chain: ChainDomain.CardanoMainnet,
      appId: 0,
    });
    wallet.addNote(note, 3);
    const unspent = wallet.unspentNotes();
    const nullifiers = wallet.deriveNullifiers(unspent);
    expect(nullifiers.length).toBe(1);
    expect(nullifiers[0].length).toBe(64);
  });
});
