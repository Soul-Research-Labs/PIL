# ADR-002: Pure-Python Fuzzer (No AFL++ Fork)

## Status

Accepted

## Date

2026-02-28

## Context

PIL++ was originally described as a "fork of AFL++" in early documentation. An internal audit (February 2026) revealed that:

- There are **zero C source files** in the repository.
- There is no AFL++ forkserver, shared-memory bitmap, or `afl-fuzz` binary.
- The entire fuzzer (~18,000 lines) is pure Python.
- Power schedules (FAST, COE, EXPLORE, etc.) are **reimplemented in Python**, inspired by the AFL++ paper but not using AFL++ code.

The mismatch between documentation and reality created confusion for contributors and auditors trying to understand the architecture.

## Decision

1. **Drop all AFL++ fork branding.** PIL++ is its own fuzzer, not a fork.
2. Keep academic citations to the AFL++ paper (Fioraldi et al., WOOT 2020) where power-schedule algorithms are inspired by it.
3. Describe PIL++ as a _"Python-based, Forge-backed, coverage-guided smart contract fuzzer with semantic ABI-aware mutations"_.

### Rationale

- Accuracy: The codebase never depended on AFL++. Honest documentation builds trust.
- Maintainability: No C build chain to maintain; single Python toolchain.
- Extensibility: Python allows rapid iteration on new mutation strategies, detectors, and protocol-specific oracles (Soul Protocol ZK invariants).
- The Forge execution backend provides real EVM semantics that AFL++'s generic binary instrumentation could never offer for smart contracts.

## Consequences

- README, ROADMAP, and CHANGELOG have been rewritten to remove AFL++ fork claims.
- 15 code-level docstring references across 5 engine files were updated to say "inspired by the AFL++ paper" rather than "AFL++-style".
- Contributors should understand that coverage bitmaps and power schedules are Python-native, not derived from AFL++.
- Future work to integrate native instrumentation (e.g., via revm Rust bindings) would be a separate ADR.
