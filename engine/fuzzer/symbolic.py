"""Symbolic Execution Engine for Soul Protocol Fuzzing.

Implements lightweight symbolic execution over Solidity bytecode patterns
to discover path constraints, generate targeted inputs, and explore
unreachable branches that pure mutation-based fuzzing cannot reach.

Architecture:
  1. SymbolicValue   — Abstract symbolic values with constraint tracking
  2. PathConstraint  — Collected branch conditions along an execution path
  3. ConstraintSolver— Z3-like constraint solving (pure Python fallback)
  4. SymbolicVM      — Symbolic EVM interpreter for Solidity operations
  5. SymbolicExecutor— Top-level engine that drives symbolic exploration
"""

from __future__ import annotations

import hashlib
import logging
import re
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable

logger = logging.getLogger(__name__)


# ── Symbolic Value Types ─────────────────────────────────────────────────────


class SymType(Enum):
    """Types of symbolic values."""
    UINT256 = "uint256"
    INT256 = "int256"
    BYTES32 = "bytes32"
    ADDRESS = "address"
    BOOL = "bool"
    BYTES = "bytes"
    UNKNOWN = "unknown"


class BinOp(Enum):
    """Binary operations for symbolic expressions."""
    ADD = "+"
    SUB = "-"
    MUL = "*"
    DIV = "/"
    MOD = "%"
    EXP = "**"
    AND = "&"
    OR = "|"
    XOR = "^"
    SHL = "<<"
    SHR = ">>"
    EQ = "=="
    NE = "!="
    LT = "<"
    GT = ">"
    LE = "<="
    GE = ">="
    LAND = "&&"
    LOR = "||"
    # Array / mapping operations (Z3 array theory)
    SELECT = "select"   # mapping[key]  → z3.Select(arr, key)
    STORE = "store"     # mapping[key] = val → z3.Store(arr, key, val)


class UnaryOp(Enum):
    """Unary operations."""
    NOT = "!"
    BNOT = "~"
    NEG = "-"


@dataclass
class SymbolicValue:
    """A symbolic value that tracks its origin and constraints.

    Can be concrete (known value), symbolic (free variable), or
    an expression tree combining both.
    """
    name: str
    sym_type: SymType = SymType.UINT256
    concrete: int | bytes | str | bool | None = None
    is_symbolic: bool = True
    # Expression tree
    op: BinOp | UnaryOp | None = None
    left: SymbolicValue | None = None
    right: SymbolicValue | None = None
    # Tracking
    origin: str = ""  # calldata, storage, memory, etc.
    taint: set[str] = field(default_factory=set)

    @property
    def is_concrete(self) -> bool:
        return self.concrete is not None and not self.is_symbolic

    def __repr__(self) -> str:
        if self.is_concrete:
            return f"C({self.concrete})"
        if self.op and self.left:
            if self.right:
                return f"({self.left} {self.op.value} {self.right})"
            return f"({self.op.value}{self.left})"
        return f"S({self.name})"

    @staticmethod
    def concrete_val(value: int | bytes | str | bool, sym_type: SymType = SymType.UINT256) -> SymbolicValue:
        return SymbolicValue(
            name=f"const_{value}",
            sym_type=sym_type,
            concrete=value,
            is_symbolic=False,
        )

    @staticmethod
    def symbolic_var(name: str, sym_type: SymType = SymType.UINT256, origin: str = "calldata") -> SymbolicValue:
        return SymbolicValue(
            name=name,
            sym_type=sym_type,
            is_symbolic=True,
            origin=origin,
            taint={name},
        )

    def binop(self, op: BinOp, other: SymbolicValue) -> SymbolicValue:
        """Create a binary operation expression."""
        # Constant folding
        if self.is_concrete and other.is_concrete:
            result = _eval_binop(op, self.concrete, other.concrete)
            if result is not None:
                return SymbolicValue.concrete_val(result, self.sym_type)

        return SymbolicValue(
            name=f"({self.name}{op.value}{other.name})",
            sym_type=self.sym_type,
            is_symbolic=True,
            op=op,
            left=self,
            right=other,
            taint=self.taint | other.taint,
        )

    def unop(self, op: UnaryOp) -> SymbolicValue:
        """Create a unary operation expression."""
        if self.is_concrete:
            result = _eval_unop(op, self.concrete)
            if result is not None:
                return SymbolicValue.concrete_val(result, self.sym_type)

        return SymbolicValue(
            name=f"({op.value}{self.name})",
            sym_type=sym_type if (sym_type := self.sym_type) else SymType.UINT256,
            is_symbolic=True,
            op=op,
            left=self,
            taint=self.taint,
        )


def _eval_binop(op: BinOp, a: Any, b: Any) -> int | bool | None:
    """Evaluate a binary operation on concrete values."""
    try:
        if not isinstance(a, (int, bool)) or not isinstance(b, (int, bool)):
            return None
        a, b = int(a), int(b)
        m = 2**256

        ops: dict[BinOp, Callable] = {
            BinOp.ADD: lambda: (a + b) % m,
            BinOp.SUB: lambda: (a - b) % m,
            BinOp.MUL: lambda: (a * b) % m,
            BinOp.DIV: lambda: a // b if b else 0,
            BinOp.MOD: lambda: a % b if b else 0,
            BinOp.EXP: lambda: pow(a, min(b, 256), m),
            BinOp.AND: lambda: a & b,
            BinOp.OR: lambda: a | b,
            BinOp.XOR: lambda: a ^ b,
            BinOp.SHL: lambda: (a << min(b, 256)) % m,
            BinOp.SHR: lambda: a >> min(b, 256),
            BinOp.EQ: lambda: int(a == b),
            BinOp.NE: lambda: int(a != b),
            BinOp.LT: lambda: int(a < b),
            BinOp.GT: lambda: int(a > b),
            BinOp.LE: lambda: int(a <= b),
            BinOp.GE: lambda: int(a >= b),
            BinOp.LAND: lambda: int(bool(a) and bool(b)),
            BinOp.LOR: lambda: int(bool(a) or bool(b)),
        }
        fn = ops.get(op)
        return fn() if fn else None
    except Exception:
        return None


def _eval_unop(op: UnaryOp, a: Any) -> int | None:
    """Evaluate a unary operation on a concrete value."""
    try:
        if not isinstance(a, (int, bool)):
            return None
        a = int(a)
        if op == UnaryOp.NOT:
            return int(not a)
        if op == UnaryOp.BNOT:
            return (2**256 - 1) ^ a
        if op == UnaryOp.NEG:
            return (2**256 - a) % (2**256)
        return None
    except Exception:
        return None


# ── Path Constraints ─────────────────────────────────────────────────────────


@dataclass
class BranchCondition:
    """A single branch condition along an execution path."""
    condition: SymbolicValue
    taken: bool  # True = condition was True, False = condition was False
    pc: int = 0  # Program counter / source location
    source_line: int = 0
    branch_id: str = ""

    def negate(self) -> BranchCondition:
        """Create the negation of this branch condition."""
        return BranchCondition(
            condition=self.condition,
            taken=not self.taken,
            pc=self.pc,
            source_line=self.source_line,
            branch_id=self.branch_id,
        )


@dataclass
class PathConstraint:
    """A complete set of constraints along one execution path."""
    conditions: list[BranchCondition] = field(default_factory=list)
    path_hash: str = ""
    depth: int = 0
    feasible: bool = True
    model: dict[str, int | bytes | str] = field(default_factory=dict)

    def add_condition(self, cond: BranchCondition) -> None:
        self.conditions.append(cond)
        self.depth = len(self.conditions)
        self._update_hash()

    def _update_hash(self) -> None:
        sig = ":".join(
            f"{c.branch_id}:{'T' if c.taken else 'F'}"
            for c in self.conditions
        )
        self.path_hash = hashlib.md5(sig.encode()).hexdigest()[:16]

    def negate_last(self) -> PathConstraint:
        """Create a new path constraint with the last condition negated.

        This is the core of symbolic exploration — negate the last
        branch to explore the other side.
        """
        if not self.conditions:
            return PathConstraint()

        new_conditions = list(self.conditions[:-1])
        new_conditions.append(self.conditions[-1].negate())

        pc = PathConstraint(conditions=new_conditions)
        pc._update_hash()
        return pc

    def negate_at(self, index: int) -> PathConstraint:
        """Negate the condition at a specific index."""
        if index < 0 or index >= len(self.conditions):
            return PathConstraint()

        new_conditions = list(self.conditions[:index])
        new_conditions.append(self.conditions[index].negate())

        pc = PathConstraint(conditions=new_conditions)
        pc._update_hash()
        return pc


# ── Constraint Solver ────────────────────────────────────────────────────────


class SolverResult(Enum):
    SAT = "sat"
    UNSAT = "unsat"
    UNKNOWN = "unknown"
    TIMEOUT = "timeout"


@dataclass
class SolverSolution:
    """Solution from the constraint solver."""
    result: SolverResult
    model: dict[str, int | bytes | str] = field(default_factory=dict)
    solve_time_ms: float = 0.0


class ConstraintSolver:
    """Lightweight constraint solver for path constraints.

    Implements:
    - Interval-based reasoning for numeric constraints
    - Equality propagation
    - Simple inequality chains
    - Bit-level reasoning for masks
    - Modular arithmetic awareness (uint256 wrapping)

    For complex constraints, falls back to heuristic solving
    with boundary values and random satisfying assignments.
    """

    def __init__(self, timeout_ms: float = 5000.0) -> None:
        self.timeout_ms = timeout_ms
        self._z3_available = self._check_z3()

    @staticmethod
    def _check_z3() -> bool:
        """Check if Z3 is available for advanced solving."""
        try:
            import z3  # noqa: F401
            return True
        except ImportError:
            return False

    def solve(self, path: PathConstraint) -> SolverSolution:
        """Solve a path constraint to find satisfying inputs.

        Strategy:
        1. Try Z3 if available (exact, handles complex constraints)
        2. Fall back to interval analysis + heuristic solving
        """
        start = time.time()

        if self._z3_available:
            try:
                result = self._solve_z3(path)
                result.solve_time_ms = (time.time() - start) * 1000
                return result
            except Exception as e:
                logger.debug("Z3 solver failed, falling back: %s", e)

        result = self._solve_interval(path)
        result.solve_time_ms = (time.time() - start) * 1000
        return result

    def _solve_z3(self, path: PathConstraint) -> SolverSolution:
        """Solve using Z3 SMT solver."""
        import z3

        solver = z3.Solver()
        solver.set("timeout", int(self.timeout_ms))

        # Create Z3 variables for all symbolic values
        z3_vars: dict[str, z3.BitVecRef] = {}
        # Z3 arrays for Solidity mappings (mapping slot → z3.Array(BV256 → BV256))
        z3_arrays: dict[str, z3.ArrayRef] = {}

        for cond in path.conditions:
            z3_expr = self._to_z3(cond.condition, z3_vars, z3_arrays)
            if z3_expr is not None:
                if cond.taken:
                    solver.add(z3_expr != 0)
                else:
                    solver.add(z3_expr == 0)

        result = solver.check()

        if result == z3.sat:
            model = solver.model()
            solution_model: dict[str, int | bytes | str] = {}
            for name, var in z3_vars.items():
                val = model.eval(var, model_completion=True)
                try:
                    solution_model[name] = val.as_long()
                except Exception:
                    solution_model[name] = 0
            return SolverSolution(
                result=SolverResult.SAT,
                model=solution_model,
            )
        elif result == z3.unsat:
            return SolverSolution(result=SolverResult.UNSAT)
        else:
            return SolverSolution(result=SolverResult.UNKNOWN)

    def _to_z3(
        self,
        sym: SymbolicValue,
        vars_map: dict,
        arrays_map: dict | None = None,
    ) -> Any:
        """Convert a SymbolicValue to a Z3 expression.

        Supports:
        - Concrete values → BitVecVal(v, 256)
        - Symbolic scalars → BitVec(name, 256)
        - Binary / unary operations → Z3 operator tree
        - Mapping access (``mapping[key]``) → z3.Select on an Array(BV256, BV256)
        - Array store (``mapping[key] = val``) → z3.Store
        """
        import z3

        if arrays_map is None:
            arrays_map = {}

        if sym.is_concrete and isinstance(sym.concrete, (int, bool)):
            return z3.BitVecVal(int(sym.concrete), 256)

        if sym.is_symbolic and sym.op is None:
            # ── Mapping access pattern: "mapping[key]" ───────────────────
            import re as _re
            map_match = _re.match(r"^(\w+)\[(.+)\]$", sym.name)
            if map_match:
                arr_name = map_match.group(1)
                key_str = map_match.group(2)
                if arr_name not in arrays_map:
                    bv256 = z3.BitVecSort(256)
                    arrays_map[arr_name] = z3.Array(arr_name, bv256, bv256)
                key_sym = SymbolicValue.symbolic_var(key_str)
                key_z3 = self._to_z3(key_sym, vars_map, arrays_map)
                if key_z3 is not None:
                    return z3.Select(arrays_map[arr_name], key_z3)
                return None

            if sym.name not in vars_map:
                vars_map[sym.name] = z3.BitVec(sym.name, 256)
            return vars_map[sym.name]

        if sym.op and sym.left:
            left = self._to_z3(sym.left, vars_map, arrays_map)
            if left is None:
                return None

            if isinstance(sym.op, UnaryOp):
                if sym.op == UnaryOp.NOT:
                    return z3.If(left == 0, z3.BitVecVal(1, 256), z3.BitVecVal(0, 256))
                if sym.op == UnaryOp.BNOT:
                    return ~left
                if sym.op == UnaryOp.NEG:
                    return -left
                return None

            if sym.right is None:
                return None
            right = self._to_z3(sym.right, vars_map, arrays_map)
            if right is None:
                return None

            # ── Array theory operations ──────────────────────────────────
            if sym.op == BinOp.SELECT:
                # left = array name (stored as concrete string), right = key
                arr_name = sym.left.name if sym.left else "arr"
                bv256 = z3.BitVecSort(256)
                if arr_name not in arrays_map:
                    arrays_map[arr_name] = z3.Array(arr_name, bv256, bv256)
                return z3.Select(arrays_map[arr_name], right)

            if sym.op == BinOp.STORE:
                # For STORE we only add a constraint; the "result" is the
                # updated array.  We return the stored value as expression.
                arr_name = sym.left.name if sym.left else "arr"
                bv256 = z3.BitVecSort(256)
                if arr_name not in arrays_map:
                    arrays_map[arr_name] = z3.Array(arr_name, bv256, bv256)
                # A STORE is modeled as: arrays_map[arr] = Store(arr, key, val)
                # Right is encoded as (key, val) pair via nested binop.
                # For simplicity, return the value written:
                return right

            z3_ops = {
                BinOp.ADD: lambda: left + right,
                BinOp.SUB: lambda: left - right,
                BinOp.MUL: lambda: left * right,
                BinOp.DIV: lambda: z3.UDiv(left, right),
                BinOp.MOD: lambda: z3.URem(left, right),
                BinOp.AND: lambda: left & right,
                BinOp.OR: lambda: left | right,
                BinOp.XOR: lambda: left ^ right,
                BinOp.SHL: lambda: left << right,
                BinOp.SHR: lambda: z3.LShR(left, right),
                BinOp.EQ: lambda: z3.If(left == right, z3.BitVecVal(1, 256), z3.BitVecVal(0, 256)),
                BinOp.NE: lambda: z3.If(left != right, z3.BitVecVal(1, 256), z3.BitVecVal(0, 256)),
                BinOp.LT: lambda: z3.If(z3.ULT(left, right), z3.BitVecVal(1, 256), z3.BitVecVal(0, 256)),
                BinOp.GT: lambda: z3.If(z3.UGT(left, right), z3.BitVecVal(1, 256), z3.BitVecVal(0, 256)),
                BinOp.LE: lambda: z3.If(z3.ULE(left, right), z3.BitVecVal(1, 256), z3.BitVecVal(0, 256)),
                BinOp.GE: lambda: z3.If(z3.UGE(left, right), z3.BitVecVal(1, 256), z3.BitVecVal(0, 256)),
            }

            fn = z3_ops.get(sym.op)
            return fn() if fn else None

        return None

    def _solve_interval(self, path: PathConstraint) -> SolverSolution:
        """Solve using interval analysis — lightweight fallback.

        Maintains intervals [lo, hi] for each variable and propagates
        constraints to narrow the feasible region.
        """
        # Collect all symbolic variable names
        var_names: set[str] = set()
        for cond in path.conditions:
            var_names |= cond.condition.taint

        # Initialize intervals: [0, 2^256 - 1]
        MAX = 2**256 - 1
        intervals: dict[str, tuple[int, int]] = {
            name: (0, MAX) for name in var_names
        }

        # Extract simple constraints and propagate
        for cond in path.conditions:
            self._propagate_constraint(cond, intervals)

        # Check feasibility
        for name, (lo, hi) in intervals.items():
            if lo > hi:
                return SolverSolution(result=SolverResult.UNSAT)

        # Generate satisfying values
        model: dict[str, int] = {}
        for name, (lo, hi) in intervals.items():
            if lo == hi:
                model[name] = lo
            else:
                # Pick boundary values or midpoint
                candidates = [lo, hi, (lo + hi) // 2]
                # Also try common interesting values in range
                for v in [0, 1, 2**128, 2**255, MAX]:
                    if lo <= v <= hi:
                        candidates.append(v)
                model[name] = candidates[0]

        return SolverSolution(result=SolverResult.SAT, model=model)

    def _propagate_constraint(
        self,
        cond: BranchCondition,
        intervals: dict[str, tuple[int, int]],
    ) -> None:
        """Extract and propagate a constraint to narrow intervals."""
        sym = cond.condition
        taken = cond.taken

        # Pattern: (x op constant) == taken
        if sym.op in (BinOp.LT, BinOp.GT, BinOp.LE, BinOp.GE, BinOp.EQ, BinOp.NE):
            if sym.left and sym.right:
                var, val = None, None

                if sym.left.is_symbolic and not sym.left.op and sym.right.is_concrete:
                    var = sym.left.name
                    val = int(sym.right.concrete) if sym.right.concrete is not None else 0
                elif sym.right.is_symbolic and not sym.right.op and sym.left.is_concrete:
                    var = sym.right.name
                    val = int(sym.left.concrete) if sym.left.concrete is not None else 0

                if var and val is not None and var in intervals:
                    lo, hi = intervals[var]
                    MAX = 2**256 - 1

                    if sym.op == BinOp.LT:
                        if taken:
                            hi = min(hi, val - 1) if val > 0 else -1
                        else:
                            lo = max(lo, val)
                    elif sym.op == BinOp.GT:
                        if taken:
                            lo = max(lo, val + 1)
                        else:
                            hi = min(hi, val)
                    elif sym.op == BinOp.LE:
                        if taken:
                            hi = min(hi, val)
                        else:
                            lo = max(lo, val + 1)
                    elif sym.op == BinOp.GE:
                        if taken:
                            lo = max(lo, val)
                        else:
                            hi = min(hi, val - 1) if val > 0 else -1
                    elif sym.op == BinOp.EQ:
                        if taken:
                            lo = max(lo, val)
                            hi = min(hi, val)
                        # NE doesn't narrow easily
                    elif sym.op == BinOp.NE:
                        if taken and lo == hi == val:
                            # Infeasible
                            hi = -1

                    intervals[var] = (lo, hi)


# ── Symbolic EVM ─────────────────────────────────────────────────────────────


@dataclass
class SymbolicState:
    """Symbolic execution state for one path."""
    stack: list[SymbolicValue] = field(default_factory=list)
    memory: dict[int, SymbolicValue] = field(default_factory=dict)
    storage: dict[int, SymbolicValue] = field(default_factory=dict)
    calldata: dict[str, SymbolicValue] = field(default_factory=dict)
    path: PathConstraint = field(default_factory=PathConstraint)
    pc: int = 0
    halted: bool = False
    reverted: bool = False
    revert_reason: str = ""
    gas_used: int = 0
    depth: int = 0
    # Tracking
    branches_explored: int = 0
    state_reads: list[str] = field(default_factory=list)
    state_writes: list[str] = field(default_factory=list)
    external_calls: list[str] = field(default_factory=list)
    events_emitted: list[str] = field(default_factory=list)

    def clone(self) -> SymbolicState:
        """Deep clone the state for path forking."""
        new_state = SymbolicState(
            stack=list(self.stack),
            memory=dict(self.memory),
            storage=dict(self.storage),
            calldata=dict(self.calldata),
            path=PathConstraint(
                conditions=list(self.path.conditions),
                path_hash=self.path.path_hash,
                depth=self.path.depth,
                feasible=self.path.feasible,
            ),
            pc=self.pc,
            halted=self.halted,
            reverted=self.reverted,
            gas_used=self.gas_used,
            depth=self.depth,
            branches_explored=self.branches_explored,
            state_reads=list(self.state_reads),
            state_writes=list(self.state_writes),
            external_calls=list(self.external_calls),
            events_emitted=list(self.events_emitted),
        )
        return new_state


class SymbolicVM:
    """Lightweight symbolic EVM that operates on Solidity source patterns.

    Instead of interpreting bytecode, we parse Solidity source to extract:
    - Require/assert conditions → path constraints
    - If/else branches → forking points
    - State reads/writes → storage model
    - External calls → inter-contract flow
    - Arithmetic operations → symbolic expressions

    This gives us constraint-guided input generation without needing
    a full EVM implementation.
    """

    # Solidity patterns for constraint extraction
    REQUIRE_PATTERN = re.compile(
        r'require\s*\(\s*(.+?)\s*(?:,\s*["\'](.+?)["\']\s*)?\)',
        re.DOTALL,
    )
    ASSERT_PATTERN = re.compile(r'assert\s*\(\s*(.+?)\s*\)', re.DOTALL)
    IF_PATTERN = re.compile(r'if\s*\(\s*(.+?)\s*\)\s*{', re.DOTALL)
    COMPARISON_PATTERN = re.compile(
        r'(\w+(?:\.\w+)*)\s*(==|!=|>=|<=|>|<)\s*(.+?)(?:\s*[;,)\]&|]|$)',
    )
    MODIFIER_PATTERN = re.compile(r'modifier\s+(\w+)')
    SLOAD_PATTERN = re.compile(r'(\w+)\[(\w+)\]')
    EMIT_PATTERN = re.compile(r'emit\s+(\w+)\s*\(')
    CALL_PATTERN = re.compile(r'(\w+)\.(\w+)\s*\(')

    def __init__(self, max_depth: int = 50) -> None:
        self.max_depth = max_depth

    def analyze_function(
        self,
        source_code: str,
        function_name: str,
        parameters: list[dict[str, str]],
    ) -> list[SymbolicState]:
        """Symbolically execute a function, returning all explored paths.

        Returns a list of terminal states, each representing one
        execution path through the function.
        """
        # Create initial symbolic state
        initial = SymbolicState()
        for param in parameters:
            name = param.get("name", f"param_{len(initial.calldata)}")
            ptype = param.get("type", "uint256")
            sym_type = self._sol_to_sym_type(ptype)
            initial.calldata[name] = SymbolicValue.symbolic_var(name, sym_type)

        # Extract function body
        body = self._extract_function_body(source_code, function_name)
        if not body:
            return [initial]

        # Execute symbolically
        terminal_states: list[SymbolicState] = []
        worklist: list[tuple[SymbolicState, str]] = [(initial, body)]

        while worklist:
            state, code = worklist.pop()

            if state.depth >= self.max_depth:
                state.halted = True
                terminal_states.append(state)
                continue

            # Process the code block
            new_states = self._execute_block(state, code)
            for ns in new_states:
                if ns.halted or ns.reverted:
                    terminal_states.append(ns)
                else:
                    terminal_states.append(ns)

            if len(terminal_states) > 200:  # Safety limit
                break

        return terminal_states

    def extract_constraints(
        self,
        source_code: str,
        function_name: str,
    ) -> list[BranchCondition]:
        """Extract all branch constraints from a function.

        Returns the constraints without executing — useful for
        quickly building a constraint map of the function.
        """
        body = self._extract_function_body(source_code, function_name)
        if not body:
            return []

        constraints: list[BranchCondition] = []
        line_num = 0

        for line in body.splitlines():
            line_num += 1
            line = line.strip()

            # Process require() statements
            for match in self.REQUIRE_PATTERN.finditer(line):
                cond_str = match.group(1)
                error_msg = match.group(2) or ""
                sym_cond = self._parse_condition(cond_str)
                constraints.append(BranchCondition(
                    condition=sym_cond,
                    taken=True,  # require must be true
                    source_line=line_num,
                    branch_id=f"require:{line_num}:{hashlib.md5(cond_str.encode()).hexdigest()[:8]}",
                ))

            # Process assert() statements
            for match in self.ASSERT_PATTERN.finditer(line):
                cond_str = match.group(1)
                sym_cond = self._parse_condition(cond_str)
                constraints.append(BranchCondition(
                    condition=sym_cond,
                    taken=True,
                    source_line=line_num,
                    branch_id=f"assert:{line_num}:{hashlib.md5(cond_str.encode()).hexdigest()[:8]}",
                ))

            # Process if() conditions
            for match in self.IF_PATTERN.finditer(line):
                cond_str = match.group(1)
                sym_cond = self._parse_condition(cond_str)
                # Both branches are interesting
                constraints.append(BranchCondition(
                    condition=sym_cond,
                    taken=True,
                    source_line=line_num,
                    branch_id=f"if_true:{line_num}:{hashlib.md5(cond_str.encode()).hexdigest()[:8]}",
                ))
                constraints.append(BranchCondition(
                    condition=sym_cond,
                    taken=False,
                    source_line=line_num,
                    branch_id=f"if_false:{line_num}:{hashlib.md5(cond_str.encode()).hexdigest()[:8]}",
                ))

        return constraints

    def _execute_block(
        self,
        state: SymbolicState,
        code: str,
    ) -> list[SymbolicState]:
        """Execute a code block symbolically, forking on branches."""
        states: list[SymbolicState] = []
        current = state
        current.depth += 1

        for line in code.splitlines():
            line = line.strip()
            if not line or line.startswith("//"):
                continue

            # Handle require() — must-true constraint
            for match in self.REQUIRE_PATTERN.finditer(line):
                cond_str = match.group(1)
                error_msg = match.group(2) or "require failed"
                sym_cond = self._parse_condition(cond_str)

                # Fork: require passes vs fails
                pass_state = current.clone()
                fail_state = current.clone()

                branch_id = f"req:{current.depth}:{hashlib.md5(cond_str.encode()).hexdigest()[:8]}"
                pass_state.path.add_condition(BranchCondition(
                    condition=sym_cond, taken=True, branch_id=branch_id,
                ))
                fail_state.path.add_condition(BranchCondition(
                    condition=sym_cond, taken=False, branch_id=branch_id,
                ))
                fail_state.reverted = True
                fail_state.revert_reason = error_msg

                states.append(fail_state)
                current = pass_state

            # Handle if/else — branching
            for match in self.IF_PATTERN.finditer(line):
                cond_str = match.group(1)
                sym_cond = self._parse_condition(cond_str)

                true_state = current.clone()
                false_state = current.clone()

                branch_id = f"if:{current.depth}:{hashlib.md5(cond_str.encode()).hexdigest()[:8]}"
                true_state.path.add_condition(BranchCondition(
                    condition=sym_cond, taken=True, branch_id=branch_id,
                ))
                true_state.branches_explored += 1
                false_state.path.add_condition(BranchCondition(
                    condition=sym_cond, taken=False, branch_id=branch_id,
                ))
                false_state.branches_explored += 1

                states.append(false_state)
                current = true_state

            # Track state read/write
            for match in self.SLOAD_PATTERN.finditer(line):
                mapping_name = match.group(1)
                key = match.group(2)
                if "=" in line and line.index(match.group(0)) < line.index("="):
                    current.state_writes.append(f"{mapping_name}[{key}]")
                else:
                    current.state_reads.append(f"{mapping_name}[{key}]")

            # Track external calls
            for match in self.CALL_PATTERN.finditer(line):
                target = match.group(1)
                method = match.group(2)
                if target not in ("msg", "block", "tx", "abi", "require", "assert"):
                    current.external_calls.append(f"{target}.{method}()")

            # Track events
            for match in self.EMIT_PATTERN.finditer(line):
                current.events_emitted.append(match.group(1))

        states.append(current)
        return states

    def _parse_condition(self, cond_str: str) -> SymbolicValue:
        """Parse a Solidity condition string into a SymbolicValue expression."""
        cond_str = cond_str.strip()

        # Handle logical operators (&&, ||)
        if "&&" in cond_str:
            parts = cond_str.split("&&", 1)
            left = self._parse_condition(parts[0])
            right = self._parse_condition(parts[1])
            return left.binop(BinOp.LAND, right)

        if "||" in cond_str:
            parts = cond_str.split("||", 1)
            left = self._parse_condition(parts[0])
            right = self._parse_condition(parts[1])
            return left.binop(BinOp.LOR, right)

        # Handle negation
        if cond_str.startswith("!"):
            inner = self._parse_condition(cond_str[1:].strip().strip("()"))
            return inner.unop(UnaryOp.NOT)

        # Handle comparison operators
        for match in self.COMPARISON_PATTERN.finditer(cond_str):
            left_str = match.group(1).strip()
            op_str = match.group(2)
            right_str = match.group(3).strip()

            left = self._parse_value(left_str)
            right = self._parse_value(right_str)

            op_map = {
                "==": BinOp.EQ,
                "!=": BinOp.NE,
                ">=": BinOp.GE,
                "<=": BinOp.LE,
                ">": BinOp.GT,
                "<": BinOp.LT,
            }
            op = op_map.get(op_str, BinOp.EQ)
            return left.binop(op, right)

        # Fallback: treat as boolean variable
        return self._parse_value(cond_str)

    def _parse_value(self, val_str: str) -> SymbolicValue:
        """Parse a value string into a SymbolicValue."""
        val_str = val_str.strip().strip("()")

        # Numeric literal
        if val_str.isdigit():
            return SymbolicValue.concrete_val(int(val_str))

        # Hex literal
        if val_str.startswith("0x"):
            try:
                return SymbolicValue.concrete_val(int(val_str, 16))
            except ValueError:
                pass

        # Known constants
        if val_str == "true":
            return SymbolicValue.concrete_val(1, SymType.BOOL)
        if val_str == "false":
            return SymbolicValue.concrete_val(0, SymType.BOOL)
        if val_str == "address(0)":
            return SymbolicValue.concrete_val(0, SymType.ADDRESS)

        # msg.sender, msg.value, etc.
        if val_str.startswith("msg."):
            return SymbolicValue.symbolic_var(val_str, origin="environment")
        if val_str.startswith("block."):
            return SymbolicValue.symbolic_var(val_str, origin="environment")

        # Type cast: uint256(x), address(x), etc.
        type_cast = re.match(r'(\w+)\((.+)\)', val_str)
        if type_cast:
            inner = self._parse_value(type_cast.group(2))
            return inner

        # Mapping access: mapping[key] → SELECT expression for Z3 array theory
        map_access = re.match(r'(\w+)\[(.+)\]', val_str)
        if map_access:
            arr_name = map_access.group(1)
            key_str = map_access.group(2)
            arr_sym = SymbolicValue.symbolic_var(arr_name, origin="storage")
            key_sym = self._parse_value(key_str)
            return SymbolicValue(
                name=f"{arr_name}[{key_str}]",
                sym_type=SymType.UINT256,
                is_symbolic=True,
                op=BinOp.SELECT,
                left=arr_sym,
                right=key_sym,
                origin="storage",
                taint=arr_sym.taint | key_sym.taint,
            )

        # Member access: x.y
        if "." in val_str:
            return SymbolicValue.symbolic_var(val_str, origin="storage")

        # Default: symbolic variable (parameter or state)
        return SymbolicValue.symbolic_var(val_str)

    def _extract_function_body(self, source_code: str, function_name: str) -> str:
        """Extract the body of a function from Solidity source."""
        # Match function declaration
        pattern = re.compile(
            rf'function\s+{re.escape(function_name)}\s*\([^)]*\)[^{{]*\{{',
            re.MULTILINE,
        )
        match = pattern.search(source_code)
        if not match:
            return ""

        # Find matching closing brace
        start = match.end()
        depth = 1
        pos = start
        while pos < len(source_code) and depth > 0:
            if source_code[pos] == '{':
                depth += 1
            elif source_code[pos] == '}':
                depth -= 1
            pos += 1

        return source_code[start:pos - 1] if depth == 0 else ""

    @staticmethod
    def _sol_to_sym_type(sol_type: str) -> SymType:
        """Convert Solidity type to symbolic type."""
        if "uint" in sol_type:
            return SymType.UINT256
        if "int" in sol_type:
            return SymType.INT256
        if sol_type == "bytes32":
            return SymType.BYTES32
        if sol_type == "address":
            return SymType.ADDRESS
        if sol_type == "bool":
            return SymType.BOOL
        if "bytes" in sol_type:
            return SymType.BYTES
        return SymType.UNKNOWN


# ── Symbolic Executor (Top-Level) ────────────────────────────────────────────


@dataclass
class SymExecResult:
    """Result of symbolic execution for a function."""
    function_name: str
    paths_explored: int = 0
    feasible_paths: int = 0
    infeasible_paths: int = 0
    revert_paths: int = 0
    max_depth: int = 0
    constraints: list[PathConstraint] = field(default_factory=list)
    generated_inputs: list[dict[str, Any]] = field(default_factory=list)
    state_reads: list[str] = field(default_factory=list)
    state_writes: list[str] = field(default_factory=list)
    external_calls: list[str] = field(default_factory=list)
    branch_coverage_potential: float = 0.0
    analysis_time_ms: float = 0.0


class SymbolicExecutor:
    """Top-level symbolic execution engine for Soul Protocol contracts.

    Combines the SymbolicVM (path exploration) with the ConstraintSolver
    (input generation) to systematically explore contract behavior.

    Usage:
        executor = SymbolicExecutor()
        result = executor.analyze(source_code, "withdraw", params)
        # result.generated_inputs contains constraint-solving inputs
    """

    def __init__(
        self,
        max_paths: int = 200,
        solver_timeout_ms: float = 5000.0,
        max_depth: int = 50,
    ) -> None:
        self.max_paths = max_paths
        self.vm = SymbolicVM(max_depth=max_depth)
        self.solver = ConstraintSolver(timeout_ms=solver_timeout_ms)
        self._explored_paths: set[str] = set()

    def analyze(
        self,
        source_code: str,
        function_name: str,
        parameters: list[dict[str, str]] | None = None,
    ) -> SymExecResult:
        """Symbolically execute a function and generate targeted inputs.

        Args:
            source_code: Solidity source
            function_name: Function to analyze
            parameters: Function parameter types [{name, type}]

        Returns:
            SymExecResult with paths, constraints, and generated inputs
        """
        start = time.time()
        parameters = parameters or []
        result = SymExecResult(function_name=function_name)

        # Phase 1: Extract constraints
        constraints = self.vm.extract_constraints(source_code, function_name)

        # Phase 2: Explore paths
        paths = self.vm.analyze_function(source_code, function_name, parameters)
        result.paths_explored = len(paths)

        # Phase 3: Solve constraints for each path to generate inputs
        for state in paths:
            if state.path.path_hash in self._explored_paths:
                continue
            self._explored_paths.add(state.path.path_hash)

            result.constraints.append(state.path)
            result.max_depth = max(result.max_depth, state.path.depth)

            if state.reverted:
                result.revert_paths += 1

            # Collect metadata
            result.state_reads.extend(state.state_reads)
            result.state_writes.extend(state.state_writes)
            result.external_calls.extend(state.external_calls)

            # Solve path constraints
            solution = self.solver.solve(state.path)
            if solution.result == SolverResult.SAT:
                result.feasible_paths += 1
                result.generated_inputs.append({
                    "path_hash": state.path.path_hash,
                    "depth": state.path.depth,
                    "reverted": state.reverted,
                    "revert_reason": state.revert_reason,
                    "model": solution.model,
                    "solve_time_ms": solution.solve_time_ms,
                })
            elif solution.result == SolverResult.UNSAT:
                result.infeasible_paths += 1

            # Also try negated paths (explore the other branch)
            for i in range(len(state.path.conditions)):
                negated = state.path.negate_at(i)
                if negated.path_hash not in self._explored_paths:
                    neg_solution = self.solver.solve(negated)
                    if neg_solution.result == SolverResult.SAT:
                        result.generated_inputs.append({
                            "path_hash": negated.path_hash,
                            "depth": negated.depth,
                            "reverted": False,
                            "model": neg_solution.model,
                            "solve_time_ms": neg_solution.solve_time_ms,
                            "negated_from": state.path.path_hash,
                        })
                    self._explored_paths.add(negated.path_hash)

        # Deduplicate
        result.state_reads = list(set(result.state_reads))
        result.state_writes = list(set(result.state_writes))
        result.external_calls = list(set(result.external_calls))

        # Coverage potential
        total_branches = len(constraints)
        if total_branches > 0:
            covered = result.feasible_paths
            result.branch_coverage_potential = min(1.0, covered / total_branches)

        result.analysis_time_ms = (time.time() - start) * 1000

        logger.info(
            "Symbolic execution of %s: %d paths (%d feasible, %d revert), "
            "%d inputs generated in %.1fms",
            function_name,
            result.paths_explored,
            result.feasible_paths,
            result.revert_paths,
            len(result.generated_inputs),
            result.analysis_time_ms,
        )

        return result

    def generate_targeted_seeds(
        self,
        source_code: str,
        functions: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        """Generate targeted seeds for multiple functions using symbolic execution.

        Returns seeds in the format expected by the FuzzCorpus.
        """
        all_seeds: list[dict[str, Any]] = []

        for func in functions:
            func_name = func.get("name", "")
            params = func.get("parameters", [])

            result = self.analyze(source_code, func_name, params)

            for inp in result.generated_inputs:
                model = inp.get("model", {})
                seed = {
                    "function": func_name,
                    "contract": func.get("contract", ""),
                    "values": model,
                    "source": "symbolic",
                    "path_hash": inp.get("path_hash", ""),
                    "depth": inp.get("depth", 0),
                    "targets_revert": inp.get("reverted", False),
                    "energy": 8,  # High energy for symbolic seeds
                }
                all_seeds.append(seed)

        logger.info(
            "Generated %d symbolic seeds across %d functions",
            len(all_seeds),
            len(functions),
        )
        return all_seeds
