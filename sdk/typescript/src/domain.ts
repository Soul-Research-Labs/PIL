/**
 * Chain domains for cross-chain nullifier isolation.
 * Mirrors the Rust `ChainDomain` enum in pil-primitives.
 */
export enum ChainDomain {
  Cardano = 0,
  CardanoTestnet = 1,
  CosmosHub = 2,
  Osmosis = 3,
  Neutron = 4,
  Injective = 5,
  Sei = 6,
  Archway = 7,
  Stargaze = 8,
  Juno = 9,
  Secret = 10,
  Akash = 11,
  Celestia = 12,
  Dymension = 13,
  Noble = 14,
  Stride = 15,
  Mars = 16,
  Kujira = 17,
  Coreum = 18,
  Persistence = 19,
  Migaloo = 20,
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
