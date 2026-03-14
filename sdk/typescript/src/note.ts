import {
  bytesToHex,
  hexToBytes,
  randomBytes,
  concatBytes,
} from "./utils.js";
import { poseidonHash } from "./poseidon.js";
import { domainTag, ChainDomain } from "./domain.js";

/** Parameters to create a new shielded note. */
export interface NoteParams {
  /** Value in smallest denomination. */
  value: bigint;
  /** Owner's public key (32 bytes hex). */
  ownerPubKey: string;
  /** Chain domain for nullifier derivation. */
  chain: ChainDomain;
  /** Application ID. */
  appId: number;
}

/** Serialised note data. */
export interface NoteData {
  /** Note commitment (32 bytes hex). */
  commitment: string;
  /** Nullifier key material (32 bytes hex). */
  nullifierKey: string;
  /** Blinding factor (32 bytes hex). */
  blinding: string;
  /** Value in smallest denomination. */
  value: bigint;
  /** Owner public key (hex). */
  ownerPubKey: string;
  /** Chain domain. */
  chain: ChainDomain;
  /** App ID. */
  appId: number;
}

/**
 * Manages creation and derivation of shielded notes.
 *
 * Uses Poseidon hashing for ZK-friendly commitments and nullifier derivation.
 * Poseidon is compatible with the Halo2 circuits used for proof generation.
 */
export class NoteManager {
  /**
   * Create a new shielded note.
   * Returns the note data including the commitment and nullifier key material.
   */
  static create(params: NoteParams): NoteData {
    const blinding = randomBytes(32);
    const ownerBytes = hexToBytes(params.ownerPubKey);
    const valueBuf = new Uint8Array(8);
    new DataView(valueBuf.buffer).setBigUint64(0, params.value, true);

    // commitment = Poseidon(owner || value || blinding || domain)
    const domain = domainTag(params.chain, params.appId);
    const preimage = concatBytes(ownerBytes, valueBuf, blinding, domain);
    const commitment = poseidonHash(preimage);

    // nullifier_key = Poseidon(owner || blinding)
    const nkPreimage = concatBytes(ownerBytes, blinding);
    const nullifierKey = poseidonHash(nkPreimage);

    return {
      commitment: bytesToHex(commitment),
      nullifierKey: bytesToHex(nullifierKey),
      blinding: bytesToHex(blinding),
      value: params.value,
      ownerPubKey: params.ownerPubKey,
      chain: params.chain,
      appId: params.appId,
    };
  }

  /**
   * Derive the nullifier for a note given its key material and leaf index.
   * nullifier = Poseidon(nullifier_key || leaf_index || domain)
   */
  static deriveNullifier(
    nullifierKey: string,
    leafIndex: number,
    chain: ChainDomain,
    appId: number,
  ): string {
    const nkBytes = hexToBytes(nullifierKey);
    const idxBuf = new Uint8Array(8);
    new DataView(idxBuf.buffer).setBigUint64(0, BigInt(leafIndex), true);
    const domain = domainTag(chain, appId);

    const preimage = concatBytes(nkBytes, idxBuf, domain);
    return bytesToHex(poseidonHash(preimage));
  }
}
