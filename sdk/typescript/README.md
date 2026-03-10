# @pil/sdk

TypeScript SDK for **PIL** (Privacy Interoperability Layer) — build private deposit, transfer, and withdraw flows across **Cardano** and **Cosmos** chains.

## Installation

```bash
npm install @pil/sdk
```

## Quick Start

```typescript
import {
  PilClient,
  ChainDomain,
  CardanoTxBuilder,
  CosmosTxBuilder,
  MockProver,
} from "@pil/sdk";

// 1. Create a client
const client = new PilClient({
  prover: new MockProver(), // replace with real WASM prover
  ownerPubKey: "abcd...1234", // 32-byte hex public key
  defaultChain: ChainDomain.CosmosHub,
  defaultAppId: 0,
});

// 2. Deposit
const note = client.createDepositNote(1_000_000n);
// Submit `note.commitment` on-chain, then:
client.confirmDeposit(note, /* leafIndex */ 0);

// 3. Transfer (private)
const { proof, nullifiers, outputCommitments } = await client.transfer(
  500_000n,
  "recipient_pub_key_hex",
  "merkle_root_hex",
  new Map(), // leaf index → merkle path
);

// 4. Withdraw
const result = await client.withdraw(
  300_000n,
  "recipient_address",
  "merkle_root_hex",
  new Map(),
);
```

## Modules

| Module             | Purpose                                                    |
| ------------------ | ---------------------------------------------------------- |
| `PilClient`        | High-level orchestrator for deposit → transfer → withdraw  |
| `PilWallet`        | In-memory note storage with coin selection                 |
| `NoteManager`      | Commitment and nullifier derivation (SHA-256)              |
| `CardanoTxBuilder` | Cardano Plutus datum/redeemer CBOR encoding                |
| `CosmosTxBuilder`  | CosmWasm execute message construction + gas estimation     |
| `ChainDomain`      | Domain separation constants matching Rust `pil-primitives` |

## Chain Builders

### Cardano

```typescript
import { CardanoTxBuilder } from "@pil/sdk";

const cardano = new CardanoTxBuilder({
  poolScriptAddress: "addr_test1...",
  poolNftPolicyId: "aabb...",
  poolNftAssetName: "504f4f4c",
  networkId: 0, // testnet
});

const tx = cardano.buildDeposit(commitment, 2_000_000n, utxos, changeAddr);
// tx.txCborHex contains the CBOR-encoded unsigned transaction
```

### Cosmos

```typescript
import { CosmosTxBuilder } from "@pil/sdk";

const cosmos = new CosmosTxBuilder({
  contractAddress: "cosmos1...",
  denom: "uatom",
  rpcUrl: "https://rpc.cosmos.network",
  chainId: "cosmoshub-4",
  gasPrice: "0.025",
});

const payload = cosmos.buildDeposit(commitment, "1000000");
const withGas = cosmos.withGas(payload, "deposit");
// withGas.estimatedGas.fee → { denom: "uatom", amount: "7000" }
```

## Pool Queries

When a `cosmosConfig` is provided to `PilClient`, you can build query messages:

```typescript
const client = new PilClient({
  // ... config
  cosmosConfig: {
    contractAddress: "cosmos1...",
    denom: "uatom",
    rpcUrl: "...",
    chainId: "...",
  },
});

const statusQuery = client.getPoolStatusQuery();
// → { status: {} }

const epochQuery = client.getEpochRootQuery(0);
// → { epoch_root: { epoch: 0 } }
```

## Wallet

```typescript
import { PilWallet } from "@pil/sdk";

const wallet = new PilWallet();
wallet.addNote(noteData, leafIndex);

// Coin selection (greedy largest-first)
const { selected, change } = wallet.selectNotes(
  500_000n,
  ChainDomain.CosmosHub,
);

// Export / import for persistence
const json = wallet.export();
wallet.import(json);
```

## Domain Separation

The SDK uses the same domain tag encoding as the Rust `pil-primitives` crate — chain ID + app ID packed into 8 little-endian bytes:

```typescript
import { ChainDomain, domainTag } from "@pil/sdk";

const tag = domainTag(ChainDomain.CardanoMainnet, 0);
// Uint8Array(8) [ 1, 0, 0, 0, 0, 0, 0, 0 ]
```

## Prover Backend

Implement the `ProverBackend` interface to plug in a real ZK prover:

```typescript
import type { ProverBackend, Proof, ProofRequest } from "@pil/sdk";

class MyWasmProver implements ProverBackend {
  async prove(request: ProofRequest): Promise<Proof> {
    /* ... */
  }
  async verify(proof: Proof): Promise<boolean> {
    /* ... */
  }
}
```

A `MockProver` is included for testing.

## Development

```bash
npm install
npm run build    # compile TypeScript
npm test         # run vitest
npm run lint     # eslint
```

## License

See repository root.
