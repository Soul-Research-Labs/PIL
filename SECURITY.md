# PIL Security Model & Threat Analysis

## Overview

PIL (Privacy Interoperability Layer) provides ZK-shielded transactions across Cardano and Cosmos ecosystems. This document outlines the security model, threat vectors, and mitigations.

## Cryptographic Foundations

### ZK Proof System

| Property            | Implementation                                |
| ------------------- | --------------------------------------------- |
| **Proving system**  | Halo2 (IPA commitment, no trusted setup)      |
| **Curve**           | Pallas/Vesta cycle (embedded curves)          |
| **Hash**            | Poseidon P128Pow5T3 (algebraic, ZK-friendly)  |
| **Commitment**      | Pedersen commitment (hiding + binding)        |
| **Merkle tree**     | Depth-32 incremental (Poseidon-based)         |
| **On-chain verify** | BLS12-381 Groth16 wrapper (Cardano Plutus V3) |

### Key Properties

- **Zero-knowledge**: Proofs reveal nothing beyond statement validity.
- **Soundness**: Computationally infeasible to forge proofs (Halo2 IPA + Pallas discrete log).
- **No trusted setup**: IPA commitments eliminate toxic waste risk.
- **Binding commitments**: Pedersen commitments prevent value manipulation.

## Threat Model

### T1: Double-Spend Attacks

**Threat**: Spending the same note twice on the same chain or across chains.

**Mitigations**:

- **Nullifier set**: Each spent note produces a unique nullifier. The nullifier set is checked before accepting any spend.
- **Domain separation**: Nullifiers include a chain domain tag (`ChainDomain` discriminant). A nullifier valid on Cardano (`domain=1`) differs from the same note on Cosmos (`domain=10`).
- **Epoch sync**: Cross-chain nullifier roots are exchanged via IBC. Any chain can verify whether a nullifier was already spent elsewhere.
- **Merkle inclusion proofs**: Spends must prove the note exists in the pool's Merkle tree.

### T2: Replay Attacks

**Threat**: Replaying a valid proof on a different chain or application.

**Mitigations**:

- **Domain-separated nullifiers**: `nullifier = H(spending_key, commitment, domain_tag)`. Different chains produce different nullifiers.
- **App ID isolation**: Each application within a chain has its own app ID in the domain separator.
- **21 chain domains**: `CardanoMainnet(1)`, `CardanoPreprod(2)`, `CardanoPreview(3)`, `CosmosHub(10)`, `Osmosis(11)`, `Neutron(12)`, `Injective(13)`, `SecretNetwork(14)`, `Celestia(15)`, `Sei(16)`, `Archway(17)`, `Dymension(18)`, `Stargaze(19)`, `Akash(20)`, `Juno(21)`, plus `Custom(u32)`.

### T3: Front-Running / MEV

**Threat**: Miners/validators extracting value by reordering or inserting transactions.

**Mitigations**:

- **ZK privacy**: Transaction values, senders, and receivers are hidden. MEV extractors cannot see the economic value of transactions.
- **Stealth addresses**: One-time recipient addresses prevent linking transactions.
- **Commitment scheme**: Note commitments reveal nothing about the note's value or owner.

### T4: Bridge Relay Attacks

**Threat**: Malicious relayer submitting false epoch roots.

**Mitigations**:

- **Light-client proofs**: Cardano→Cosmos uses Mithril multi-signatures (SPO quorum >50%). Cosmos→Cardano uses Tendermint/CometBFT validator signatures (>⅔ quorum).
- **Epoch root verification**: Destination chains verify the light-client proof before accepting an epoch root.
- **SHA-256 Merkle root chain hashing**: On-chain epoch roots use `SHA-256(old_root || commitment)` for collision-resistant state binding.
- **IBC SendPacket**: Cosmos epoch publishing constructs a proper `IbcMsg::SendPacket` with 300-second timeout and `EpochSyncPacketData` binding.
- **Stale attestation rejection**: Attestations older than 24 hours are rejected.
- **Duplicate detection**: The relayer tracks relayed epochs and rejects duplicates.
- **Multi-chain aggregation**: The `EpochAggregator` collects attestations from all source chains and produces a deterministic digest (`SHA-256("PIL-AGG" || epoch || chain_roots)`) before forwarding.
- **Rate limiting**: Per-chain-pair rate limiting prevents relay spam (configurable via `RateLimiter`).

### T5: Key Compromise

**Threat**: Spending key leaked; attacker can derive nullifiers and spend notes.

**Mitigations**:

- **Viewing key separation**: `ViewingKey` can detect incoming notes without spending authority.
- **Stealth address protocol**: DH key exchange generates one-time addresses, limiting exposure.
- **Encrypted note storage**: Notes are encrypted with ChaCha20-Poly1305 or AES-256-GCM.
- **Key derivation**: Argon2id for password-based key derivation (memory-hard, resists GPU/ASIC).

### T6: Merkle Tree Manipulation

**Threat**: Inserting forged commitments or manipulating the tree state.

**Mitigations**:

- **Append-only tree**: The incremental Merkle tree only appends; no deletions or modifications.
- **Poseidon hash**: Algebraic hash function with well-studied collision resistance (~128-bit security).
- **Root consensus**: All participants see the same root. Epoch finalization publishes the root on-chain.

### T7: Groth16 Wrapper Soundness

**Threat**: The Groth16 wrapper circuit introduces a different proof system; errors could break soundness.

**Mitigations**:

- **Commit-and-prove pattern**: The Groth16 circuit does NOT re-verify the Halo2 proof. It only binds the Halo2 public inputs into a BLS12-381 Groth16 proof.
- **Algebraic hash binding**: `H(inputs) = sum(input_i * (i+1)) + proof_type * (n+1)`. This is a binding commitment under the discrete log assumption.
- **Proof type constraint**: `(type - 0)(type - 1)(type - 2) == 0` ensures only valid proof types.
- **Small circuit**: ~2K constraints, minimizing the attack surface.
- **Production note**: For mainnet deployment, replace the algebraic hash with a Poseidon gadget over BLS12-381.

### T8: Hydra L2 State Channel Attacks

**Threat**: Malicious participant in a Hydra head submitting outdated state on close.

**Mitigations**:

- **Contestation period**: Configurable period where participants can submit newer snapshots.
- **Snapshot commitments**: Each snapshot includes pool root, nullifier count, and note count.
- **Isomorphic execution**: Same validators run in L2 as L1 — no new trust assumptions.
- **Fanout settlement**: On close, all L2 UTXOs settle back to L1 with full verification.

## Security Boundaries

### Trusted Components

| Component            | Trust Assumption                          |
| -------------------- | ----------------------------------------- |
| Halo2 + Pallas/Vesta | Discrete log hardness on Pallas curve     |
| Poseidon hash        | Collision resistance (~128-bit)           |
| BLS12-381 Groth16    | Knowledge-of-exponent assumption          |
| Cardano L1           | Ouroboros Praos consensus security        |
| Cosmos L1            | CometBFT 2/3+ honest validator assumption |
| Mithril              | SPO quorum threshold (majority honest)    |
| IBC                  | Relayer liveness (not safety)             |

### Untrusted Components

| Component      | Why Untrusted                                          |
| -------------- | ------------------------------------------------------ |
| Bridge relayer | Only relays; cannot forge proofs                       |
| RPC server     | Stateless; all state transitions verified by ZK proofs |
| Client wallet  | Holds keys but can't bypass on-chain verification      |

## Recommendations for Production Deployment

1. **Poseidon over BLS12-381**: Replace the algebraic hash in the Groth16 wrapper circuit with a full Poseidon implementation for 128-bit collision resistance.
2. **Formal verification**: Verify R1CS constraint satisfaction with a formal tool (e.g., Ecne, Circomscribe).
3. **Groth16 ceremony**: Conduct a multi-party computation (MPC) trusted setup for the BLS12-381 Groth16 keys. The wrapper circuit is small (~2K constraints), making this practical.
4. **Audit**: Professional security audit of ZK circuits, on-chain validators, and bridge relay logic.
5. **Rate limiting**: Implement per-epoch submission limits on the relayer to prevent spam.
6. **Monitoring**: Deploy real-time monitoring for nullifier set anomalies, epoch root mismatches, and bridge latency.
7. **Key management**: Use hardware security modules (HSMs) for relayer signing keys.
8. **Testnet first**: Deploy on Cardano Preprod + Cosmos testnet before mainnet.
9. **Cross-chain E2E testing**: Run the integration test suite (`cargo test -p pil-integration-tests`) which includes Cardano↔Cosmos relay, bidirectional epoch sync, and cross-chain double-spend prevention.

## Versioning

- Security model version: 1.1
- Last updated: 2026-03-10
- Applies to: PIL v0.1.0
