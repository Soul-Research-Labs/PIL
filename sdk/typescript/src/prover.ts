/** A serialised ZK proof (hex-encoded bytes). */
export interface Proof {
  /** Hex-encoded proof data. */
  data: string;
  /** Hex-encoded public inputs. */
  publicInputs: string[];
}

/** Request to generate a proof. */
export interface ProofRequest {
  type: "transfer" | "withdraw" | "wealth";
  /** Hex-encoded Merkle root. */
  merkleRoot: string;
  /** Input note nullifier keys + leaf indices. */
  inputs: Array<{
    nullifierKey: string;
    leafIndex: number;
    value: bigint;
    merklePath: string[];
  }>;
  /** Output note commitments + values. */
  outputs: Array<{
    commitment: string;
    value: bigint;
  }>;
  /** For withdraw: exit amount and recipient. */
  exitAmount?: bigint;
  recipient?: string;
}

/**
 * Abstract prover backend. In production this is backed by
 * WASM bindings to the pil-prover Rust crate (compiled via wasm-pack).
 * The interface allows swapping in a mock prover for tests.
 */
export interface ProverBackend {
  /** Generate a ZK proof from the given request. */
  prove(request: ProofRequest): Promise<Proof>;

  /** Verify a proof against public inputs. */
  verify(proof: Proof): Promise<boolean>;
}

/**
 * Placeholder prover that returns a dummy proof.
 * Useful for integration testing the SDK without WASM bindings.
 */
export class MockProver implements ProverBackend {
  async prove(request: ProofRequest): Promise<Proof> {
    // Deterministic dummy — the real prover calls into pil-prover WASM
    const tag =
      request.type === "transfer"
        ? "01"
        : request.type === "withdraw"
          ? "02"
          : "03";
    return {
      data: tag + "00".repeat(63),
      publicInputs: [request.merkleRoot],
    };
  }

  async verify(_proof: Proof): Promise<boolean> {
    return true;
  }
}
