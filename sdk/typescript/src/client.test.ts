import { describe, it, expect } from "vitest";
import { PilClient } from "./client.js";
import { MockProver } from "./prover.js";
import { ChainDomain } from "./domain.js";

function makeClient() {
  return new PilClient({
    prover: new MockProver(),
    ownerPubKey: "ab".repeat(32),
    defaultChain: ChainDomain.CardanoMainnet,
    defaultAppId: 0,
  });
}

describe("PilClient", () => {
  it("creates a deposit note with correct value", () => {
    const client = makeClient();
    const note = client.createDepositNote(500n);
    expect(note.value).toBe(500n);
    expect(note.chain).toBe(ChainDomain.CardanoMainnet);
    expect(note.commitment.length).toBe(64);
  });

  it("confirmDeposit tracks the note in the wallet", () => {
    const client = makeClient();
    const note = client.createDepositNote(100n);
    client.confirmDeposit(note, 0);
    expect(client.wallet.balance()).toBe(100n);
  });

  it("transfer produces proof and nullifiers", async () => {
    const client = makeClient();
    const note = client.createDepositNote(200n);
    client.confirmDeposit(note, 0);

    const recipientPub = "cd".repeat(32);
    const merkleRoot = "00".repeat(32);
    const merklePaths = new Map<number, string[]>();
    merklePaths.set(0, ["00".repeat(32)]);

    const result = await client.transfer(
      100n,
      recipientPub,
      merkleRoot,
      merklePaths,
    );

    expect(result.proof.data.length).toBeGreaterThan(0);
    expect(result.nullifiers.length).toBe(1);
    // 100 to recipient + 100 change
    expect(result.outputCommitments.length).toBe(2);
    expect(result.outputNotes.length).toBe(2);
    expect(result.outputNotes[0].value).toBe(100n);
    expect(result.outputNotes[1].value).toBe(100n);
  });

  it("transfer marks input notes as spent", async () => {
    const client = makeClient();
    const note = client.createDepositNote(100n);
    client.confirmDeposit(note, 0);

    const merkleRoot = "00".repeat(32);
    const merklePaths = new Map<number, string[]>();
    merklePaths.set(0, ["00".repeat(32)]);

    await client.transfer(100n, "cd".repeat(32), merkleRoot, merklePaths);
    // Original note should be spent, balance = 0
    expect(client.wallet.balance()).toBe(0n);
  });

  it("withdraw produces proof and nullifiers", async () => {
    const client = makeClient();
    const note = client.createDepositNote(300n);
    client.confirmDeposit(note, 0);

    const merkleRoot = "00".repeat(32);
    const merklePaths = new Map<number, string[]>();
    merklePaths.set(0, ["00".repeat(32)]);
    const recipient = "addr1_test_recipient";

    const result = await client.withdraw(
      250n,
      recipient,
      merkleRoot,
      merklePaths,
    );

    expect(result.proof.data.length).toBeGreaterThan(0);
    expect(result.nullifiers.length).toBe(1);
    // 50 change note
    expect(result.changeCommitments.length).toBe(1);
    expect(result.changeNotes[0].value).toBe(50n);
  });

  it("withdraw with exact amount produces no change", async () => {
    const client = makeClient();
    const note = client.createDepositNote(100n);
    client.confirmDeposit(note, 0);

    const merkleRoot = "00".repeat(32);
    const merklePaths = new Map<number, string[]>();
    merklePaths.set(0, ["00".repeat(32)]);

    const result = await client.withdraw(
      100n,
      "addr1_exact",
      merkleRoot,
      merklePaths,
    );

    expect(result.changeCommitments.length).toBe(0);
    expect(result.changeNotes.length).toBe(0);
  });

  it("uses custom chain and appId overrides", () => {
    const client = makeClient();
    const note = client.createDepositNote(10n, ChainDomain.CosmosHub, 5);
    expect(note.chain).toBe(ChainDomain.CosmosHub);
    expect(note.appId).toBe(5);
  });
});
