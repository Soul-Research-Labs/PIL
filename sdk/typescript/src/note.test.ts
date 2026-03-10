import { describe, it, expect } from "vitest";
import { NoteManager } from "./note.js";
import { ChainDomain } from "./domain.js";
import { bytesToHex } from "./utils.js";

describe("NoteManager.create", () => {
  const ownerPubKey = "ab".repeat(32);

  it("produces note with 32-byte commitment", () => {
    const note = NoteManager.create({
      value: 100n,
      ownerPubKey,
      chain: ChainDomain.CardanoMainnet,
      appId: 0,
    });
    expect(note.commitment.length).toBe(64); // 32 bytes hex
  });

  it("produces note with 32-byte nullifier key", () => {
    const note = NoteManager.create({
      value: 100n,
      ownerPubKey,
      chain: ChainDomain.CardanoMainnet,
      appId: 0,
    });
    expect(note.nullifierKey.length).toBe(64);
  });

  it("preserves value and owner", () => {
    const note = NoteManager.create({
      value: 42n,
      ownerPubKey,
      chain: ChainDomain.CosmosHub,
      appId: 1,
    });
    expect(note.value).toBe(42n);
    expect(note.ownerPubKey).toBe(ownerPubKey);
    expect(note.chain).toBe(ChainDomain.CosmosHub);
    expect(note.appId).toBe(1);
  });

  it("different values produce different commitments", () => {
    const n1 = NoteManager.create({
      value: 100n,
      ownerPubKey,
      chain: ChainDomain.CardanoMainnet,
      appId: 0,
    });
    const n2 = NoteManager.create({
      value: 200n,
      ownerPubKey,
      chain: ChainDomain.CardanoMainnet,
      appId: 0,
    });
    // Different values + different random blinding → different commitments
    expect(n1.commitment).not.toBe(n2.commitment);
  });
});

describe("NoteManager.deriveNullifier", () => {
  it("produces 32-byte nullifier", () => {
    const nf = NoteManager.deriveNullifier(
      "aa".repeat(32),
      0,
      ChainDomain.CardanoMainnet,
      0,
    );
    expect(nf.length).toBe(64);
  });

  it("different leaf indices produce different nullifiers", () => {
    const nk = "bb".repeat(32);
    const nf1 = NoteManager.deriveNullifier(
      nk,
      0,
      ChainDomain.CardanoMainnet,
      0,
    );
    const nf2 = NoteManager.deriveNullifier(
      nk,
      1,
      ChainDomain.CardanoMainnet,
      0,
    );
    expect(nf1).not.toBe(nf2);
  });

  it("different chains produce different nullifiers", () => {
    const nk = "cc".repeat(32);
    const nf1 = NoteManager.deriveNullifier(
      nk,
      0,
      ChainDomain.CardanoMainnet,
      0,
    );
    const nf2 = NoteManager.deriveNullifier(nk, 0, ChainDomain.CosmosHub, 0);
    expect(nf1).not.toBe(nf2);
  });
});
