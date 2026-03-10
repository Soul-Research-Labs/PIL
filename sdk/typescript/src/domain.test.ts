import { describe, it, expect } from "vitest";
import { ChainDomain, domainTag } from "./domain.js";

describe("ChainDomain", () => {
  it("has correct Cardano mainnet value", () => {
    expect(ChainDomain.CardanoMainnet).toBe(1);
  });

  it("has correct Cosmos chain values starting at 10", () => {
    expect(ChainDomain.CosmosHub).toBe(10);
    expect(ChainDomain.Osmosis).toBe(11);
    expect(ChainDomain.Neutron).toBe(12);
  });

  it("CardanoPreprod is 2", () => {
    expect(ChainDomain.CardanoPreprod).toBe(2);
  });

  it("matches Rust pil-primitives domain values", () => {
    // These values MUST stay in sync with crates/pil-primitives/src/domain.rs
    expect(ChainDomain.CardanoMainnet).toBe(1);
    expect(ChainDomain.CardanoPreprod).toBe(2);
    expect(ChainDomain.CardanoPreview).toBe(3);
    expect(ChainDomain.CosmosHub).toBe(10);
    expect(ChainDomain.Osmosis).toBe(11);
    expect(ChainDomain.Neutron).toBe(12);
    expect(ChainDomain.Injective).toBe(13);
    expect(ChainDomain.SecretNetwork).toBe(14);
    expect(ChainDomain.Celestia).toBe(15);
    expect(ChainDomain.Sei).toBe(16);
    expect(ChainDomain.Archway).toBe(17);
    expect(ChainDomain.Dymension).toBe(18);
    expect(ChainDomain.Stargaze).toBe(19);
    expect(ChainDomain.Akash).toBe(20);
    expect(ChainDomain.Juno).toBe(21);
  });
});

describe("domainTag", () => {
  it("produces 8 bytes", () => {
    const tag = domainTag(ChainDomain.CardanoMainnet, 0);
    expect(tag.length).toBe(8);
  });

  it("encodes chain ID in first 4 bytes (little-endian)", () => {
    const tag = domainTag(ChainDomain.CosmosHub, 0);
    const view = new DataView(tag.buffer);
    expect(view.getUint32(0, true)).toBe(10);
  });

  it("encodes app ID in last 4 bytes (little-endian)", () => {
    const tag = domainTag(ChainDomain.CardanoMainnet, 42);
    const view = new DataView(tag.buffer);
    expect(view.getUint32(4, true)).toBe(42);
  });

  it("different chains produce different tags", () => {
    const t1 = domainTag(ChainDomain.CardanoMainnet, 0);
    const t2 = domainTag(ChainDomain.CosmosHub, 0);
    expect(t1).not.toEqual(t2);
  });

  it("different apps produce different tags", () => {
    const t1 = domainTag(ChainDomain.CardanoMainnet, 0);
    const t2 = domainTag(ChainDomain.CardanoMainnet, 1);
    expect(t1).not.toEqual(t2);
  });
});
