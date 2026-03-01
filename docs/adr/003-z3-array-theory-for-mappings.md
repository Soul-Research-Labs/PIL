# ADR-003: Z3 Array Theory for Solidity Mappings

## Status

Accepted

## Date

2026-03-01

## Context

PIL++'s concolic execution engine (`engine/fuzzer/concolic.py`) uses Z3 as its constraint solver via the `ConstraintSolver` class in `engine/fuzzer/symbolic.py`. Prior to this change, all symbolic values were modeled as 256-bit bitvectors (`z3.BitVec(name, 256)`).

Solidity `mapping(keyType => valueType)` and dynamic `array[]` accesses compile to storage operations involving `keccak256(key . slot)`. When the concolic engine encounters a branch condition like `require(balances[msg.sender] >= amount)`, it could not reason about the relationship between the key (`msg.sender`) and the stored value because:

1. `balances[msg.sender]` was treated as a single opaque symbolic variable.
2. Two accesses to the same mapping with different keys (e.g., `balances[alice]` vs `balances[bob]`) were modeled as independent variables — missing the constraint that they share a backing store.
3. The solver could not generate inputs that exercise specific mapping states.

## Decision

Extend the symbolic execution and constraint solver to use **Z3's array theory** (`z3.Array(name, BitVecSort(256), BitVecSort(256))`) for Solidity mappings and arrays.

### Changes

1. **New `BinOp` values**: `SELECT` (read from mapping) and `STORE` (write to mapping) added to the symbolic value expression tree.
2. **`SymbolicVM._parse_value()`**: Mapping access patterns `mapping[key]` now produce a `SELECT` expression node instead of an opaque symbolic variable.
3. **`ConstraintSolver._to_z3()`**: Recognizes `SELECT`/`STORE` ops and translates them to `z3.Select(array, key)` / `z3.Store(array, key, value)`. Also detects the `name[key]` string pattern in variable names and auto-creates an array + Select.
4. **`_solve_z3()`**: Maintains a separate `z3_arrays` dict alongside `z3_vars`.

### Modeling approach

```
mapping(address => uint256) balances;

balances[alice]    → z3.Select(Array("balances", BV256, BV256), alice)
balances[bob]      → z3.Select(Array("balances", BV256, BV256), bob)
balances[alice] = 42 → Array("balances") = z3.Store(arr, alice, 42)
```

This lets Z3 reason about:

- `balances[alice] + balances[bob] == totalSupply` (conservation)
- `balances[msg.sender] >= amount` (sufficient-balance checks)
- Two keys indexing into the same store (aliasing)

### Limitations

- Keccak256 is not modeled — Z3 treats the hash as uninterpreted. This means nested mappings (`mapping(a => mapping(b => uint))`) are approximated as a flat array keyed by the outer key.
- Writes produce a new array version; the solver does not track SSA versions of the array across time steps.
- The fallback interval solver (`_solve_interval`) does not benefit from array theory — it only narrows scalar intervals.

## Consequences

- Concolic execution can now generate inputs for branches guarded by mapping lookups (e.g., balance checks, allowance checks, nullifier registry checks).
- Soul Protocol invariants involving `nullifierUsed[n]` and `balances[sender]` become solvable.
- Solver timeout may increase for complex array constraints; the existing 5-second timeout caps worst-case latency.
- Future work: model `keccak256` as an uninterpreted function to support nested mappings and storage slot computation.
