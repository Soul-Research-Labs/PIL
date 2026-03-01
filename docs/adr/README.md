# Architecture Decision Records

This directory contains Architecture Decision Records (ADRs) for the PIL++ / ZASEON project.

ADRs document significant technical decisions, the context behind them, and their consequences. They serve as a lightweight, version-controlled log that helps current and future contributors understand _why_ the system is built the way it is.

## Index

| #                                          | Title                                 | Status   | Date       |
| ------------------------------------------ | ------------------------------------- | -------- | ---------- |
| [001](001-forge-backed-execution.md)       | Forge-backed EVM execution            | Accepted | 2025-08-15 |
| [002](002-python-fuzzer-no-afl-fork.md)    | Pure-Python fuzzer (no AFL++ fork)    | Accepted | 2026-02-28 |
| [003](003-z3-array-theory-for-mappings.md) | Z3 array theory for Solidity mappings | Accepted | 2026-03-01 |

## Template

```markdown
# ADR-NNN: Title

## Status

Proposed | Accepted | Deprecated | Superseded by ADR-XXX

## Context

What is the issue that we're seeing that is motivating this decision?

## Decision

What is the change that we're proposing and/or doing?

## Consequences

What becomes easier or harder because of this change?
```
