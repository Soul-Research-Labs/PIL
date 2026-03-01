# ADR-001: Forge-Backed EVM Execution

## Status

Accepted

## Date

2025-08-15

## Context

PIL++ needs to execute Solidity smart contracts with full EVM semantics to evaluate fuzzing inputs. There are several options:

1. **Embedded EVM** (e.g., py-evm, revm Python bindings) — Run an EVM implementation in-process.
2. **Ganache / Hardhat fork** — Spin up a local Ethereum node for each test.
3. **Foundry Forge** — Generate Solidity test harnesses and execute them via `forge test`.

Key requirements:

- Correct EVM semantics with all opcodes, precompiles, and cheatcodes.
- Execution tracing for coverage extraction (branch hit bitmaps).
- Support for `vm.prank`, `vm.deal`, `vm.warp` and other test helpers.
- Ability to fork mainnet/testnet state for real-world testing.
- Sub-second per-input execution latency.

## Decision

Use **Foundry's `forge test`** as the execution backend. PIL++ generates Solidity test harness files dynamically (via `ForgeTestGenerator`), writes them to a temporary Foundry project, and runs `forge test --json -vvvv` to get structured output including pass/fail, gas usage, traces, and state changes.

### Rationale

- Forge is the de-facto standard for Solidity testing; its EVM implementation is battle-tested.
- Built-in cheatcodes (`vm.*`) provide powerful state manipulation for exploit PoCs.
- `forge test --json` output includes execution traces parseable for branch coverage.
- Fork mode (`--fork-url`) allows testing against real on-chain state.
- Foundry is already a dependency for most Solidity developers.

### Trade-offs

- **Process overhead**: Each input requires a subprocess call. Mitigated by batching multiple inputs into a single harness file with multiple `test_*` functions.
- **Compilation latency**: First run compiles the project; subsequent runs benefit from Forge's incremental compilation cache.
- **No in-process state**: Cannot inspect EVM state directly from Python. Mitigated by parsing JSON traces.

## Consequences

- The fuzzer depends on Foundry (`forge`) being installed on the host or in the Docker image.
- All test/PoC generation produces valid Solidity, making outputs directly usable by auditors.
- Coverage extraction is limited to what Forge's trace output exposes (function calls, branches via `JUMPI`).
- Python-side symbolic execution (`engine/fuzzer/symbolic.py`) complements Forge by generating targeted inputs without needing to invoke a subprocess.
