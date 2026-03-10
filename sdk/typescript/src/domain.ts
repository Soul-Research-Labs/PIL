/**
 * Chain domains for cross-chain nullifier isolation.
 * Values MUST match the Rust `ChainDomain` enum in pil-primitives/src/domain.rs.
 */
export enum ChainDomain {
  // Cardano ecosystem
  CardanoMainnet = 1,
  CardanoPreprod = 2,
  CardanoPreview = 3,

  // Cosmos ecosystem (starting at 10)
  CosmosHub = 10,
  Osmosis = 11,
  Neutron = 12,
  Injective = 13,
  SecretNetwork = 14,
  Celestia = 15,
  Sei = 16,
  Archway = 17,
  Dymension = 18,
  Stargaze = 19,
  Akash = 20,
  Juno = 21,
}

/**
 * Compute the domain separation tag bytes for a given chain/app pair.
 * Used as input to Poseidon-based nullifier derivation.
 */
export function domainTag(chain: ChainDomain, appId: number): Uint8Array {
  const buf = new Uint8Array(8);
  const view = new DataView(buf.buffer);
  view.setUint32(0, chain, true); // little-endian
  view.setUint32(4, appId, true);
  return buf;
}
