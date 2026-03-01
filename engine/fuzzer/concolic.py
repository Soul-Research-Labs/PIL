"""Concolic (CONcrete + symbOLIC) Fuzzing Engine for Soul Protocol.

Combines concrete execution traces with symbolic constraint solving
to systematically explore new code paths. Uses the Symbolic Execution
engine for constraint collection and the Forge executor for concrete runs.

Pipeline:
  1. Run concrete execution on input → collect branch trace
  2. Symbolically map branch conditions from source
  3. Negate one branch condition at a time (generational search)
  4. Solve negated constraints → generate new inputs
  5. Execute new inputs concretely → check for bugs
  6. Repeat with coverage-guided prioritization

This is significantly more powerful than pure mutation fuzzing because
it can systematically reach deep code paths that random mutation
would take exponentially long to discover.
"""

from __future__ import annotations

import hashlib
import logging
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from engine.fuzzer.symbolic import (
    BranchCondition,
    ConstraintSolver,
    PathConstraint,
    SolverResult,
    SymbolicExecutor,
    SymbolicVM,
    SymbolicValue,
    SymType,
)

logger = logging.getLogger(__name__)


# ── Concolic Trace ───────────────────────────────────────────────────────────


class TraceEventType(Enum):
    """Types of events in a concrete execution trace."""
    BRANCH_TAKEN = "branch_taken"
    BRANCH_NOT_TAKEN = "branch_not_taken"
    REQUIRE_PASS = "require_pass"
    REQUIRE_FAIL = "require_fail"
    ASSERT_PASS = "assert_pass"
    ASSERT_FAIL = "assert_fail"
    SSTORE = "sstore"
    SLOAD = "sload"
    CALL = "call"
    DELEGATECALL = "delegatecall"
    STATICCALL = "staticcall"
    LOG = "log"
    REVERT = "revert"
    RETURN = "return"
    SELFDESTRUCT = "selfdestruct"


@dataclass
class TraceEvent:
    """A single event in the concrete execution trace."""
    event_type: TraceEventType
    pc: int = 0
    source_line: int = 0
    branch_id: str = ""
    condition_value: bool | None = None
    data: dict[str, Any] = field(default_factory=dict)
    gas_cost: int = 0
    depth: int = 0


@dataclass
class ConcreteTrace:
    """Complete trace of a concrete execution."""
    events: list[TraceEvent] = field(default_factory=list)
    branch_sequence: list[tuple[str, bool]] = field(default_factory=list)
    coverage_bitmap: set[str] = field(default_factory=set)
    gas_used: int = 0
    reverted: bool = False
    revert_reason: str = ""
    return_data: bytes = b""
    state_changes: dict[str, Any] = field(default_factory=dict)

    @property
    def path_hash(self) -> str:
        sig = ":".join(f"{bid}:{'T' if taken else 'F'}" for bid, taken in self.branch_sequence)
        return hashlib.md5(sig.encode()).hexdigest()[:16]

    def to_path_constraint(self, constraints_map: dict[str, BranchCondition]) -> PathConstraint:
        """Convert concrete trace to symbolic path constraint.

        Uses the constraints_map (from symbolic analysis) to map
        branch IDs to their symbolic conditions.
        """
        pc = PathConstraint()
        for branch_id, taken in self.branch_sequence:
            if branch_id in constraints_map:
                cond = BranchCondition(
                    condition=constraints_map[branch_id].condition,
                    taken=taken,
                    branch_id=branch_id,
                    source_line=constraints_map[branch_id].source_line,
                )
                pc.add_condition(cond)
        return pc


# ── Concolic Search Strategy ─────────────────────────────────────────────────


class SearchStrategy(Enum):
    """Search strategies for concolic exploration."""
    GENERATIONAL = "generational"  # Negate each branch condition bottom-up (SAGE-style)
    DFS = "dfs"                   # Depth-first: always negate the deepest unexplored
    BFS = "bfs"                   # Breadth-first: negate shallowest first
    RANDOM_PATH = "random_path"   # Randomly select branches to negate
    COVERAGE_OPT = "coverage_opt" # Prioritize branches near uncovered code
    HYBRID = "hybrid"             # Combine multiple strategies


@dataclass
class ConcolicTask:
    """A task for the concolic engine — a path constraint to solve and execute."""
    constraint: PathConstraint
    negated_index: int = -1
    parent_path_hash: str = ""
    priority: float = 1.0
    strategy: SearchStrategy = SearchStrategy.GENERATIONAL
    generation: int = 0

    @property
    def id(self) -> str:
        return f"task:{self.constraint.path_hash}:neg{self.negated_index}"


# ── Concolic State Machine ──────────────────────────────────────────────────


@dataclass
class ConcolicStats:
    """Statistics for a concolic fuzzing session."""
    total_executions: int = 0
    total_solver_calls: int = 0
    solver_sat: int = 0
    solver_unsat: int = 0
    solver_timeout: int = 0
    new_coverage: int = 0
    bugs_found: int = 0
    paths_explored: set[str] = field(default_factory=set)
    branches_covered: set[str] = field(default_factory=set)
    total_branches: int = 0
    execution_time_ms: float = 0.0
    solver_time_ms: float = 0.0
    # Per-generation stats
    generation_stats: list[dict[str, Any]] = field(default_factory=list)

    @property
    def branch_coverage(self) -> float:
        return len(self.branches_covered) / max(1, self.total_branches)


# ── Concolic Engine ──────────────────────────────────────────────────────────


class ConcolicEngine:
    """Concolic fuzzing engine combining concrete + symbolic execution.

    Architecture:
    - Uses SymbolicVM to extract constraints from source code
    - Uses ConstraintSolver (Z3 when available) to solve path constraints
    - Uses concrete executor (Forge or simulation) to validate inputs
    - Implements generational search (SAGE-style) for systematic exploration

    The key insight: after a concrete run, we know which branches were taken.
    We can then negate each branch condition and solve the resulting constraint
    to get an input that explores the OTHER side of that branch.
    """

    def __init__(
        self,
        source_code: str,
        executor: Any | None = None,
        strategy: SearchStrategy = SearchStrategy.HYBRID,
        max_generations: int = 20,
        max_solver_time_ms: float = 10000.0,
        max_tasks: int = 1000,
    ) -> None:
        self.source_code = source_code
        self.executor = executor
        self.strategy = strategy
        self.max_generations = max_generations
        self.max_solver_time_ms = max_solver_time_ms
        self.max_tasks = max_tasks

        # Core components
        self.sym_vm = SymbolicVM(max_depth=100)
        self.solver = ConstraintSolver(timeout_ms=max_solver_time_ms)
        self.sym_executor = SymbolicExecutor(
            max_paths=500,
            solver_timeout_ms=max_solver_time_ms,
        )

        # State
        self.stats = ConcolicStats()
        self._task_queue: list[ConcolicTask] = []
        self._explored_paths: set[str] = set()
        self._constraint_maps: dict[str, dict[str, BranchCondition]] = {}
        self._coverage: set[str] = set()
        self._known_bugs: list[dict[str, Any]] = []

    def build_constraint_map(self, function_name: str) -> dict[str, BranchCondition]:
        """Pre-analyze a function to build its constraint map.

        Returns mapping of branch_id → BranchCondition for all branches
        in the function. This is used to map concrete traces back to
        symbolic constraints.
        """
        if function_name in self._constraint_maps:
            return self._constraint_maps[function_name]

        constraints = self.sym_vm.extract_constraints(self.source_code, function_name)
        cmap: dict[str, BranchCondition] = {}
        for c in constraints:
            cmap[c.branch_id] = c
            self.stats.total_branches += 1

        self._constraint_maps[function_name] = cmap
        return cmap

    def run_concolic(
        self,
        function_name: str,
        initial_inputs: list[dict[str, Any]],
        parameters: list[dict[str, str]] | None = None,
        max_iterations: int = 100,
        timeout_sec: float = 300.0,
    ) -> ConcolicResult:
        """Run concolic fuzzing on a function.

        Args:
            function_name: Target function
            initial_inputs: Initial concrete inputs to start from
            parameters: Function parameter specs
            max_iterations: Max execution iterations
            timeout_sec: Maximum wall-clock time

        Returns:
            ConcolicResult with all discovered inputs and bugs
        """
        start = time.time()
        parameters = parameters or []

        # Build constraint map
        cmap = self.build_constraint_map(function_name)

        logger.info(
            "Starting concolic fuzzing of %s: %d branch constraints, %d initial inputs",
            function_name,
            len(cmap),
            len(initial_inputs),
        )

        # Phase 1: Symbolic pre-analysis for initial seeds
        sym_result = self.sym_executor.analyze(
            self.source_code, function_name, parameters,
        )
        symbolic_seeds = sym_result.generated_inputs

        # Phase 2: Seed with initial + symbolic inputs
        all_inputs = list(initial_inputs) + [
            s.get("model", {}) for s in symbolic_seeds
        ]

        discovered_inputs: list[dict[str, Any]] = []
        discovered_bugs: list[dict[str, Any]] = []
        generation = 0

        while generation < self.max_generations and len(discovered_inputs) < max_iterations:
            elapsed = time.time() - start
            if elapsed >= timeout_sec:
                break

            gen_start = time.time()
            gen_new_coverage = 0
            gen_new_inputs = 0

            # Execute current inputs concretely
            for inp in all_inputs:
                if self.stats.total_executions >= max_iterations:
                    break

                trace = self._execute_concrete(function_name, inp)
                self.stats.total_executions += 1

                # Check for new coverage
                if trace.path_hash not in self._explored_paths:
                    self._explored_paths.add(trace.path_hash)
                    gen_new_coverage += 1
                    self.stats.new_coverage += 1

                    # Update branch coverage
                    for bid, taken in trace.branch_sequence:
                        key = f"{bid}:{'T' if taken else 'F'}"
                        self.stats.branches_covered.add(key)

                    discovered_inputs.append({
                        "generation": generation,
                        "input": inp,
                        "path_hash": trace.path_hash,
                        "reverted": trace.reverted,
                        "new_coverage": True,
                    })

                # Check for bugs
                bugs = self._check_for_bugs(function_name, inp, trace)
                if bugs:
                    discovered_bugs.extend(bugs)
                    self.stats.bugs_found += len(bugs)

                # Generate new tasks by negating branches
                path_constraint = trace.to_path_constraint(cmap)
                new_tasks = self._generate_tasks(path_constraint, generation)
                self._task_queue.extend(new_tasks)

            # Phase 3: Process task queue — solve negated constraints
            next_inputs: list[dict[str, Any]] = []
            tasks_to_process = self._select_tasks()

            for task in tasks_to_process:
                solution = self.solver.solve(task.constraint)
                self.stats.total_solver_calls += 1
                self.stats.solver_time_ms += solution.solve_time_ms

                if solution.result == SolverResult.SAT:
                    self.stats.solver_sat += 1
                    next_inputs.append(solution.model)
                    gen_new_inputs += 1
                elif solution.result == SolverResult.UNSAT:
                    self.stats.solver_unsat += 1
                elif solution.result == SolverResult.TIMEOUT:
                    self.stats.solver_timeout += 1

            # Record generation stats
            gen_time = (time.time() - gen_start) * 1000
            self.stats.generation_stats.append({
                "generation": generation,
                "new_coverage": gen_new_coverage,
                "new_inputs": gen_new_inputs,
                "tasks_processed": len(tasks_to_process),
                "time_ms": gen_time,
                "branch_coverage": self.stats.branch_coverage,
            })

            logger.info(
                "Concolic gen %d: +%d coverage, +%d inputs, %.1f%% branch coverage (%.1fms)",
                generation,
                gen_new_coverage,
                gen_new_inputs,
                self.stats.branch_coverage * 100,
                gen_time,
            )

            # Prepare for next generation
            all_inputs = next_inputs
            if not all_inputs:
                break
            generation += 1

        self.stats.execution_time_ms = (time.time() - start) * 1000

        return ConcolicResult(
            function_name=function_name,
            stats=self.stats,
            discovered_inputs=discovered_inputs,
            discovered_bugs=discovered_bugs,
            total_generations=generation + 1,
            final_branch_coverage=self.stats.branch_coverage,
            known_bugs=self._known_bugs,
        )

    def _execute_concrete(
        self,
        function_name: str,
        inputs: dict[str, Any],
    ) -> ConcreteTrace:
        """Execute a concrete input and collect the execution trace.

        If a real executor (Forge) is available, use it.
        Otherwise, use source-level simulation.
        """
        if self.executor:
            try:
                raw = self.executor.execute(function_name, inputs)
                return self._parse_executor_trace(raw)
            except Exception as e:
                logger.debug("Concrete execution failed: %s", e)

        # Simulation mode: analyze which branches the input would take
        return self._simulate_trace(function_name, inputs)

    def _simulate_trace(
        self,
        function_name: str,
        inputs: dict[str, Any],
    ) -> ConcreteTrace:
        """Simulate concrete execution by evaluating constraints with input values.

        For each branch condition, substitute the concrete input values
        and evaluate to determine which branch would be taken.
        """
        trace = ConcreteTrace()
        cmap = self.build_constraint_map(function_name)

        for branch_id, branch_cond in cmap.items():
            # Try to evaluate the condition with concrete inputs
            concrete_val = self._evaluate_condition(branch_cond.condition, inputs)

            if concrete_val is not None:
                taken = bool(concrete_val)
                trace.branch_sequence.append((branch_id, taken))
                trace.events.append(TraceEvent(
                    event_type=TraceEventType.BRANCH_TAKEN if taken else TraceEventType.BRANCH_NOT_TAKEN,
                    branch_id=branch_id,
                    condition_value=taken,
                    source_line=branch_cond.source_line,
                ))
                trace.coverage_bitmap.add(f"{branch_id}:{'T' if taken else 'F'}")

                # Check for reverts (require conditions not met)
                if "require" in branch_id or "req:" in branch_id:
                    if not taken:
                        trace.reverted = True
                        trace.revert_reason = f"require failed at {branch_id}"
            else:
                # Can't evaluate — assume taken (optimistic)
                trace.branch_sequence.append((branch_id, True))
                trace.coverage_bitmap.add(f"{branch_id}:T")

        return trace

    def _evaluate_condition(
        self,
        sym: SymbolicValue,
        inputs: dict[str, Any],
    ) -> int | None:
        """Evaluate a symbolic condition with concrete input values."""
        if sym.is_concrete:
            return int(sym.concrete) if sym.concrete is not None else None

        if sym.is_symbolic and not sym.op:
            # Look up the variable in inputs
            val = inputs.get(sym.name)
            if val is not None:
                return int(val) if isinstance(val, (int, bool)) else None
            return None

        if sym.op and sym.left:
            left_val = self._evaluate_condition(sym.left, inputs)
            if left_val is None:
                return None

            if isinstance(sym.op, (type(None),)):
                return None

            from engine.fuzzer.symbolic import UnaryOp, BinOp, _eval_binop, _eval_unop

            if isinstance(sym.op, UnaryOp):
                return _eval_unop(sym.op, left_val)

            if sym.right:
                right_val = self._evaluate_condition(sym.right, inputs)
                if right_val is None:
                    return None
                return _eval_binop(sym.op, left_val, right_val)

        return None

    def _generate_tasks(
        self,
        path: PathConstraint,
        generation: int,
    ) -> list[ConcolicTask]:
        """Generate concolic tasks by negating branch conditions.

        Strategy depends on self.strategy:
        - GENERATIONAL: Negate each condition (SAGE paper approach)
        - COVERAGE_OPT: Prioritize negating conditions near uncovered code
        - HYBRID: Mix strategies
        """
        tasks: list[ConcolicTask] = []

        for i in range(len(path.conditions)):
            negated = path.negate_at(i)
            if negated.path_hash in self._explored_paths:
                continue

            priority = self._compute_task_priority(path, i)

            tasks.append(ConcolicTask(
                constraint=negated,
                negated_index=i,
                parent_path_hash=path.path_hash,
                priority=priority,
                strategy=self.strategy,
                generation=generation + 1,
            ))

        return tasks

    def _compute_task_priority(
        self,
        path: PathConstraint,
        negate_index: int,
    ) -> float:
        """Compute priority for a task based on search strategy."""
        base_priority = 1.0

        if self.strategy in (SearchStrategy.GENERATIONAL, SearchStrategy.HYBRID):
            # Prefer negating deeper conditions (more specific paths)
            base_priority = 1.0 + negate_index * 0.1

        if self.strategy in (SearchStrategy.COVERAGE_OPT, SearchStrategy.HYBRID):
            # Boost priority for branches near uncovered code
            cond = path.conditions[negate_index]
            complement_key = f"{cond.branch_id}:{'F' if cond.taken else 'T'}"
            if complement_key not in self.stats.branches_covered:
                base_priority *= 3.0  # Large boost for uncovered branches

        if self.strategy in (SearchStrategy.BFS, SearchStrategy.HYBRID):
            # BFS: prefer shallower negations
            base_priority *= 1.0 / (negate_index + 1)

        return base_priority

    def _select_tasks(self) -> list[ConcolicTask]:
        """Select tasks from queue, prioritized by strategy."""
        if not self._task_queue:
            return []

        # Sort by priority (descending)
        self._task_queue.sort(key=lambda t: t.priority, reverse=True)

        # Take top tasks
        batch_size = min(50, len(self._task_queue))
        selected = self._task_queue[:batch_size]
        self._task_queue = self._task_queue[batch_size:]

        # Trim queue if too large
        if len(self._task_queue) > self.max_tasks:
            self._task_queue = self._task_queue[:self.max_tasks]

        return selected

    def _check_for_bugs(
        self,
        function_name: str,
        inputs: dict[str, Any],
        trace: ConcreteTrace,
    ) -> list[dict[str, Any]]:
        """Check for bugs in the execution trace.

        Looks for:
        - Unexpected reverts (assert failures, panics)
        - State invariant violations
        - Reentrancy indicators
        - Integer overflow indicators
        """
        bugs: list[dict[str, Any]] = []

        for event in trace.events:
            if event.event_type == TraceEventType.ASSERT_FAIL:
                bugs.append({
                    "type": "assert_failure",
                    "function": function_name,
                    "input": inputs,
                    "source_line": event.source_line,
                    "details": event.data,
                })

            if event.event_type == TraceEventType.SELFDESTRUCT:
                bugs.append({
                    "type": "selfdestruct_reachable",
                    "function": function_name,
                    "input": inputs,
                    "source_line": event.source_line,
                })

            if event.event_type == TraceEventType.DELEGATECALL:
                target = event.data.get("target", "")
                if target and "msg.sender" not in str(target):
                    bugs.append({
                        "type": "unguarded_delegatecall",
                        "function": function_name,
                        "input": inputs,
                        "target": target,
                    })

        # Check for state-related bugs
        if trace.state_changes:
            # Check for unauthorized state modifications
            if not trace.reverted and "onlyOwner" not in str(trace.events):
                for key, value in trace.state_changes.items():
                    if "balance" in key.lower() and isinstance(value, (int, float)):
                        if value < 0:
                            bugs.append({
                                "type": "negative_balance",
                                "function": function_name,
                                "input": inputs,
                                "state_key": key,
                                "value": value,
                            })

        return bugs

    def _parse_executor_trace(self, raw: dict[str, Any]) -> ConcreteTrace:
        """Parse raw executor output into a ConcreteTrace."""
        trace = ConcreteTrace()
        trace.reverted = raw.get("reverted", False)
        trace.revert_reason = raw.get("revert_reason", "")
        trace.gas_used = raw.get("gas_used", 0)
        trace.return_data = raw.get("return_data", b"")
        trace.state_changes = raw.get("state_changes", {})
        trace.coverage_bitmap = set(raw.get("coverage_bitmap", []))

        # Parse structured trace events
        for ev in raw.get("trace", []):
            event_type = TraceEventType(ev.get("type", "branch_taken"))
            trace.events.append(TraceEvent(
                event_type=event_type,
                pc=ev.get("pc", 0),
                source_line=ev.get("line", 0),
                branch_id=ev.get("branch_id", ""),
                condition_value=ev.get("value"),
                data=ev.get("data", {}),
                gas_cost=ev.get("gas", 0),
                depth=ev.get("depth", 0),
            ))

            if event_type in (TraceEventType.BRANCH_TAKEN, TraceEventType.BRANCH_NOT_TAKEN):
                taken = event_type == TraceEventType.BRANCH_TAKEN
                bid = ev.get("branch_id", "")
                trace.branch_sequence.append((bid, taken))

        return trace

    def get_summary(self) -> dict[str, Any]:
        """Get a summary of concolic fuzzing results."""
        return {
            "total_executions": self.stats.total_executions,
            "total_solver_calls": self.stats.total_solver_calls,
            "solver_sat": self.stats.solver_sat,
            "solver_unsat": self.stats.solver_unsat,
            "solver_timeout": self.stats.solver_timeout,
            "new_coverage_found": self.stats.new_coverage,
            "bugs_found": self.stats.bugs_found,
            "paths_explored": len(self.stats.paths_explored),
            "branch_coverage": round(self.stats.branch_coverage * 100, 2),
            "total_branches": self.stats.total_branches,
            "execution_time_ms": round(self.stats.execution_time_ms, 1),
            "solver_time_ms": round(self.stats.solver_time_ms, 1),
            "generation_stats": self.stats.generation_stats,
        }


# ── Result Types ─────────────────────────────────────────────────────────────


@dataclass
class ConcolicResult:
    """Complete result of a concolic fuzzing session."""
    function_name: str
    stats: ConcolicStats
    discovered_inputs: list[dict[str, Any]] = field(default_factory=list)
    discovered_bugs: list[dict[str, Any]] = field(default_factory=list)
    total_generations: int = 0
    final_branch_coverage: float = 0.0
    known_bugs: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "function_name": self.function_name,
            "total_generations": self.total_generations,
            "final_branch_coverage": round(self.final_branch_coverage * 100, 2),
            "total_inputs_discovered": len(self.discovered_inputs),
            "total_bugs_found": len(self.discovered_bugs),
            "bugs": self.discovered_bugs[:20],
            "stats": {
                "executions": self.stats.total_executions,
                "solver_calls": self.stats.total_solver_calls,
                "sat": self.stats.solver_sat,
                "unsat": self.stats.solver_unsat,
                "paths": len(self.stats.paths_explored),
                "branches_covered": len(self.stats.branches_covered),
                "total_branches": self.stats.total_branches,
            },
        }

    def get_best_inputs(self, limit: int = 50) -> list[dict[str, Any]]:
        """Get the most interesting discovered inputs."""
        # Prioritize bug-triggering inputs, then new-coverage inputs
        bug_inputs = [i for i in self.discovered_inputs if i.get("reverted")]
        coverage_inputs = [i for i in self.discovered_inputs if i.get("new_coverage")]
        other_inputs = [i for i in self.discovered_inputs if not i.get("reverted") and not i.get("new_coverage")]

        result = bug_inputs[:limit // 3] + coverage_inputs[:limit // 3] + other_inputs[:limit // 3]
        return result[:limit]
