# PIL

> Zero-knowledge privacy infrastructure for **Cardano**, **Cosmos**, and compatible blockchains.

PIL brings ZK-shielded transfers, nullifier-based double-spend prevention, and cross-chain epoch synchronisation to non-EVM ecosystems — inspired by [ZAseon](https://github.com/Soul-Research-Labs/ZAseon) and [Lumora](https://github.com/Soul-Research-Labs/Lumora).

---

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                    PIL Core (Rust)                      │
│  ┌────────────┐  ┌────────────┐  ┌──────────────────┐   │
│  │ primitives │  │    note    │  │      tree        │   │
│  │ (Poseidon, │  │ (keys,     │  │ (Merkle depth-32)│   │
│  │  domain)   │  │  stealth)  │  │                  │   │
│  └────────────┘  └────────────┘  └──────────────────┘   │
│  ┌────────────┐  ┌────────────┐  ┌──────────────────┐   │
│  │  circuits  │  │   prover   │  │    verifier      │   │
│  │ (Halo2 ZK) │  │ (IPA, no   │  │ (batch verify)   │   │
│  │            │  │  setup)    │  │                  │   │
│  └────────────┘  └────────────┘  └──────────────────┘   │
│  ┌────────────┐  ┌────────────┐  ┌──────────────────┐   │
│  │    pool    │  │   bridge   │  │     sdk          │   │
│  │ (deposit,  │  │ (Cardano ↔ │  │ (orchestrate     │   │
│  │  withdraw) │  │  Cosmos)   │  │  full flows)     │   │
│  └────────────┘  └────────────┘  └──────────────────┘   │
│  ┌────────────┐  ┌────────────┐  ┌──────────────────┐   │
│  │  cardano   │  │   cosmos   │  │  node / rpc /cli │   │
│  │ (eUTXO     │  │ (CosmWasm  │  │ (Axum server,    │   │
│  │  adapter)  │  │  + IBC)    │  │  REPL)           │   │
│  └────────────┘  └────────────┘  └──────────────────┘   │
└─────────────────────────────────────────────────────────┘
┌───────────────────────────┬─────────────────────────────┐
│  contracts/cardano/       │  contracts/cosmwasm/        │
│  (Aiken validators)       │  (CosmWasm smart contract)  │
└───────────────────────────┴─────────────────────────────┘
┌─────────────────────────────────────────────────────────┐
│  sdk/typescript/  — @pil/sdk (wallet, notes, tx build)  │
└─────────────────────────────────────────────────────────┘
```

## Key Features

| Feature                         | Description                                                                |
| ------------------------------- | -------------------------------------------------------------------------- |
| **Halo2 ZK Proofs**             | IPA-based proving system over Pallas/Vesta curves — no trusted setup       |
| **Domain-Separated Nullifiers** | 21 chain domains prevent cross-chain replay attacks                        |
| **Poseidon Hashing**            | Algebraic hash (P128Pow5T3, width 3, rate 2) native to arithmetic circuits |
| **Incremental Merkle Tree**     | Depth-32 append-only tree with O(log n) proof generation                   |
| **Stealth Addresses**           | One-time recipient addresses via Diffie-Hellman key exchange               |
| **Epoch Synchronisation**       | Cross-chain nullifier root publishing via IBC                              |
| **Cardano Support**             | Aiken validators, CBOR tx serialization, eUTXO batching                    |
| **Cosmos Support**              | CosmWasm contract with IBC SendPacket, SHA-256 Merkle root, full queries   |
| **Groth16 BLS12-381 Wrapper**   | Re-proves Halo2 outputs into BLS12-381 Groth16 for Cardano on-chain verify |
| **Hydra L2 Support**            | Cardano Hydra head management for high-throughput private transactions     |
| **Bridge Aggregator**           | Multi-chain epoch root aggregation with deterministic digest               |
| **Mithril Light Client**        | SPO quorum verification for trustless Cardano→Cosmos relay                 |
| **Property-Based Testing**      | Proptest + fuzz targets for core crypto primitives                         |
| **CI/CD + Docker**              | GitHub Actions (5 jobs) + multi-stage Docker build                         |

## Project Structure

```
PIL/
├── Cargo.toml                    # Workspace root (18 crates)
├── ANALYSIS.md                   # Feasibility study & roadmap
├── SECURITY.md                   # Threat model & security considerations
├── .github/workflows/ci.yml      # GitHub Actions CI (5 jobs)
├── Dockerfile                    # Multi-stage Docker build
├── crates/
│   ├── pil-primitives/           # Core types, Poseidon, commitments, domain
│   ├── pil-note/                 # Note model, keys, encryption, stealth
│   ├── pil-tree/                 # Incremental Merkle tree
│   ├── pil-circuits/             # Halo2 ZK circuits (transfer, withdraw, wealth)
│   ├── pil-prover/               # Proof generation (ProvingKeys, IPA)
│   ├── pil-verifier/             # Proof verification (single + batch)
│   ├── pil-pool/                 # Privacy pool state machine
│   ├── pil-cardano/              # Cardano eUTXO adapter
│   ├── pil-cosmos/               # Cosmos CosmWasm/IBC adapter
│   ├── pil-bridge/               # Cardano ↔ Cosmos bridge relayer
│   ├── pil-groth16-wrapper/      # BLS12-381 Groth16 wrapper for Cardano on-chain
│   ├── pil-hydra/                # Cardano Hydra L2 head management
│   ├── pil-node/                 # Node server
│   ├── pil-client/               # Wallet with coin selection
│   ├── pil-sdk/                  # High-level orchestrator
│   ├── pil-rpc/                  # Axum REST API server
│   ├── pil-cli/                  # CLI binary with REPL
│   ├── pil-integration-tests/    # Cross-crate integration tests
│   └── pil-benchmarks/           # Performance benchmarks
├── contracts/
│   ├── cardano/                  # Aiken smart contracts
│   │   ├── aiken.toml
│   │   ├── validators/privacy_pool.ak
│   │   └── lib/pil.ak
│   └── cosmwasm/                 # CosmWasm smart contract
│       └── src/{contract,msg,state,error,lib}.rs
└── sdk/
    └── typescript/               # @pil/sdk TypeScript package
        └── src/{index,client,wallet,note,prover,domain,utils}.ts
            └── chains/{cardano,cosmos}.ts
```

## Prerequisites

- **Rust** ≥ 1.75 (with `cargo`)
- **Node.js** ≥ 20 (for TypeScript SDK)
- **Aiken** ≥ 1.0 (for Cardano contracts, optional)

## Quick Start

### Build the Rust workspace

```bash
cd PIL
cargo build --release
```

### Run all tests

```bash
cargo test
```

All **130+ tests** should pass across 18 crates:

```
test result: ok. 130+ passed; 0 failed; 0 ignored
```

### Run the CLI

```bash
cargo run --bin pil-cli -- --help
```

### Build the TypeScript SDK

```bash
cd sdk/typescript
npm install
npm run build
```

### Build Cardano validators (requires Aiken)

```bash
cd contracts/cardano
aiken build
```

## Usage

### Rust SDK — End-to-End Flow

```rust
use pil_sdk::Orchestrator;
use pil_primitives::domain::ChainDomain;

let mut orch = Orchestrator::new(prover, verifier, pool, wallet);

// 1. Deposit 1000 units into the shielded pool
let receipt = orch.deposit(1000, ChainDomain::Cardano, 0)?;

// 2. Private transfer to another stealth address
let receipt = orch.send(500, recipient_addr, ChainDomain::Cardano, 0)?;

// 3. Withdraw to a public address
let receipt = orch.withdraw(300, ChainDomain::Cardano, 0)?;
```

### TypeScript SDK

```typescript
import { PilClient, MockProver, ChainDomain } from "@pil/sdk";

const client = new PilClient({
  prover: new MockProver(),
  ownerPubKey: "abcd...1234",
  defaultChain: ChainDomain.CosmosHub,
  defaultAppId: 1,
});

// Create a deposit note
const note = client.createDepositNote(1000n);
console.log("Commitment:", note.commitment);

// After on-chain confirmation
client.confirmDeposit(note, 0);

// Private transfer
const { proof, nullifiers, outputCommitments } = await client.transfer(
  500n,
  recipientPubKey,
  currentMerkleRoot,
  merklePaths,
);
```

### CosmWasm Contract Interaction

```typescript
import { CosmosTxBuilder } from "@pil/sdk";

const builder = new CosmosTxBuilder({
  contractAddress: "cosmos1...",
  denom: "uatom",
  rpcUrl: "https://rpc.cosmos.network",
  chainId: "cosmoshub-4",
});

// Build a deposit message
const tx = builder.buildDeposit(note.commitment, "1000000");
// Sign & broadcast with cosmjs SigningCosmWasmClient
```

## ZK Circuits

PIL includes three Halo2 circuits:

| Circuit              | Purpose                   | Public Inputs                                   |
| -------------------- | ------------------------- | ----------------------------------------------- |
| `TransferCircuit`    | Private value transfer    | merkle_root, nullifiers, output_commitments     |
| `WithdrawCircuit`    | Exit from shielded pool   | merkle_root, nullifiers, exit_amount, recipient |
| `WealthProofCircuit` | Prove balance ≥ threshold | merkle_root, threshold (value stays private)    |

All circuits use the **IPA commitment scheme** over the **Pallas/Vesta** curve cycle — no trusted setup ceremony required.

## Cross-Chain Design

```
  Cardano                         Cosmos Hub
  ┌──────────┐                    ┌──────────┐
  │ Aiken    │                    │ CosmWasm  │
  │ Privacy  │    PIL Bridge      │ Privacy   │
  │ Pool     │◄──────────────────►│ Pool      │
  │ Validator│    (epoch roots)   │ Contract  │
  └──────────┘                    └──────────┘
       │                               │
       │        Epoch Root Sync        │
       │   (nullifier set snapshots    │
       │    prevent cross-chain        │
       │    double-spending)           │
       │                               │
       └──────────── IBC ──────────────┘
                     │
              ┌──────┴──────┐
              │  Osmosis    │
              │  Neutron    │
              │  Injective  │
              │  60+ chains │
              └─────────────┘
```

**Nullifier isolation**: Each chain domain has a unique 32-bit tag prepended to all nullifier derivations, ensuring a nullifier valid on Cardano cannot be replayed on Cosmos.

**Epoch sync**: Periodically, each chain publishes its nullifier set Merkle root. The bridge relayer propagates these roots via IBC packets, allowing any chain to verify that a nullifier was (or wasn't) spent on another chain.

## Roadmap

| Phase | Milestone                                                    | Status      |
| ----- | ------------------------------------------------------------ | ----------- |
| 1     | Core Rust workspace (18 crates, ZK circuits, tests)          | ✅ Complete |
| 2     | On-chain contracts (Aiken + CosmWasm) + TypeScript SDK       | ✅ Complete |
| 3     | Groth16 wrapper, IBC relay, CI/CD, Docker, integration tests | ✅ Complete |
| 4     | Hydra L2 integration + relayer + benchmarks + security model | ✅ Complete |
| 5     | Mithril light client, CBOR tx, eUTXO batching, Aiken scaffold | ✅ Complete |
| 6     | IBC SendPacket, SHA-256 Merkle root, full Cosmos queries      | ✅ Complete |
| 7     | Bridge aggregator, cross-chain E2E tests, TS SDK hardening    | ✅ Complete |
| 8     | Audit & mainnet deployment                                    | Planned     |

See [ANALYSIS.md](ANALYSIS.md) for the full feasibility study and risk assessment.

## License

Dual-licensed under MIT or Apache-2.0.
