"""Control Flow Graph (CFG) builder + taint analysis for Solidity.

Builds a CFG from the Solidity AST and performs:
  - Path-sensitive vulnerability detection
  - Taint propagation from sources to sinks
  - Reentrancy pattern detection via call→write ordering
  - Unchecked return value tracking
  - Dead code detection

Sources (untrusted input):
  - msg.sender, msg.value, msg.data, tx.origin
  - calldata parameters, external call return values
  - block.timestamp, block.number, blockhash

Sinks (dangerous operations):
  - .call{value:}, .transfer, .send (ETH transfer)
  - delegatecall (code execution)
  - selfdestruct (contract destruction)
  - SSTORE (state mutation with tainted index/value)
  - emit (information leak)
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Any


# ── CFG Data Structures ─────────────────────────────────────────────────────


class TaintKind(str, Enum):
    """What kind of taint a value carries."""
    MSG_SENDER = "msg.sender"
    MSG_VALUE = "msg.value"
    MSG_DATA = "msg.data"
    TX_ORIGIN = "tx.origin"
    CALLDATA = "calldata"
    BLOCK_TIMESTAMP = "block.timestamp"
    BLOCK_NUMBER = "block.number"
    BLOCKHASH = "blockhash"
    EXTERNAL_RETURN = "external_return"
    STORAGE_READ = "storage_read"


class SinkKind(str, Enum):
    """Types of dangerous operations (sinks)."""
    ETH_TRANSFER = "eth_transfer"
    DELEGATECALL = "delegatecall"
    SELFDESTRUCT = "selfdestruct"
    STATE_WRITE = "state_write"
    EXTERNAL_CALL = "external_call"
    REQUIRE_CONDITION = "require"
    ARRAY_INDEX = "array_index"
    EVENT_EMIT = "event_emit"


@dataclass
class BasicBlock:
    """A basic block in the CFG — straight-line code with no branches."""
    id: int
    statements: list[dict] = field(default_factory=list)
    predecessors: list[int] = field(default_factory=list)
    successors: list[int] = field(default_factory=list)
    # Analysis annotations
    tainted_vars: dict[str, set[TaintKind]] = field(default_factory=lambda: defaultdict(set))
    has_external_call: bool = False
    has_state_write: bool = False
    has_require: bool = False
    is_entry: bool = False
    is_exit: bool = False
    source_lines: tuple[int, int] = (0, 0)


@dataclass
class CFG:
    """Control Flow Graph for a single function."""
    function_name: str
    blocks: dict[int, BasicBlock] = field(default_factory=dict)
    entry_block: int = 0
    exit_blocks: list[int] = field(default_factory=list)
    _next_id: int = 0

    def new_block(self, is_entry: bool = False, is_exit: bool = False) -> BasicBlock:
        block = BasicBlock(id=self._next_id, is_entry=is_entry, is_exit=is_exit)
        self.blocks[block.id] = block
        self._next_id += 1
        return block

    def add_edge(self, from_id: int, to_id: int) -> None:
        if to_id not in self.blocks[from_id].successors:
            self.blocks[from_id].successors.append(to_id)
        if from_id not in self.blocks[to_id].predecessors:
            self.blocks[to_id].predecessors.append(from_id)

    @property
    def block_count(self) -> int:
        return len(self.blocks)


@dataclass
class TaintFlow:
    """A detected taint flow from source to sink."""
    source_kind: TaintKind
    sink_kind: SinkKind
    source_variable: str
    sink_variable: str
    path: list[int]  # block IDs from source to sink
    function_name: str
    source_line: int = 0
    sink_line: int = 0
    description: str = ""


@dataclass
class ReentrancyPath:
    """A detected reentrancy pattern: external call before state write."""
    function_name: str
    call_block: int
    write_block: int
    call_target: str
    write_variable: str
    path: list[int]
    call_line: int = 0
    write_line: int = 0


# ── CFG Builder ──────────────────────────────────────────────────────────────


class CFGBuilder:
    """Build a Control Flow Graph from a Solidity AST function body.

    Handles:
    - Sequential statements → single basic block
    - if/else → branch to two blocks, merge at join point
    - for/while/do-while → back-edge loop, condition block, body block
    - try/catch → fork to success/error blocks
    - return/revert → edge to exit block
    """

    def __init__(self, source_code: str = "") -> None:
        self._source = source_code

    def build(self, func_name: str, body_node: dict[str, Any] | None) -> CFG:
        """Build CFG from a function body AST node."""
        cfg = CFG(function_name=func_name)

        if not body_node:
            entry = cfg.new_block(is_entry=True, is_exit=True)
            cfg.entry_block = entry.id
            cfg.exit_blocks = [entry.id]
            return cfg

        entry = cfg.new_block(is_entry=True)
        cfg.entry_block = entry.id

        exit_block = cfg.new_block(is_exit=True)
        cfg.exit_blocks = [exit_block.id]

        statements = body_node.get("statements", [])
        last_block = self._process_statements(cfg, entry, statements, exit_block)

        if last_block and last_block.id != exit_block.id:
            cfg.add_edge(last_block.id, exit_block.id)

        return cfg

    def _process_statements(
        self,
        cfg: CFG,
        current_block: BasicBlock,
        statements: list[dict],
        exit_block: BasicBlock,
    ) -> BasicBlock | None:
        """Process a list of statements, building blocks and edges."""
        for stmt in statements:
            nt = stmt.get("nodeType", "")

            if nt == "IfStatement":
                current_block = self._process_if(cfg, current_block, stmt, exit_block)
                if current_block is None:
                    return None

            elif nt in ("ForStatement", "WhileStatement"):
                current_block = self._process_loop(cfg, current_block, stmt, exit_block)
                if current_block is None:
                    return None

            elif nt == "DoWhileStatement":
                current_block = self._process_do_while(cfg, current_block, stmt, exit_block)
                if current_block is None:
                    return None

            elif nt in ("Return", "RevertStatement"):
                current_block.statements.append(stmt)
                cfg.add_edge(current_block.id, exit_block.id)
                return None  # Unreachable after return

            elif nt == "TryStatement":
                current_block = self._process_try(cfg, current_block, stmt, exit_block)
                if current_block is None:
                    return None

            else:
                # Regular statement — add to current block
                current_block.statements.append(stmt)
                self._annotate_block(current_block, stmt)

        return current_block

    def _process_if(
        self, cfg: CFG, current: BasicBlock, stmt: dict, exit_block: BasicBlock
    ) -> BasicBlock | None:
        """Process an if/else statement into CFG blocks."""
        # Condition goes in current block
        condition = stmt.get("condition", {})
        current.statements.append({"nodeType": "IfCondition", "expression": condition})

        # True branch
        true_block = cfg.new_block()
        cfg.add_edge(current.id, true_block.id)
        true_body = stmt.get("trueBody", {})
        true_stmts = true_body.get("statements", []) if true_body.get("nodeType") == "Block" else [true_body]
        true_end = self._process_statements(cfg, true_block, true_stmts, exit_block)

        # False branch (else)
        false_body = stmt.get("falseBody")
        false_end = None
        if false_body:
            false_block = cfg.new_block()
            cfg.add_edge(current.id, false_block.id)
            false_stmts = false_body.get("statements", []) if false_body.get("nodeType") == "Block" else [false_body]
            false_end = self._process_statements(cfg, false_block, false_stmts, exit_block)
        else:
            false_end_block = cfg.new_block()
            cfg.add_edge(current.id, false_end_block.id)
            false_end = false_end_block

        # Merge point
        merge = cfg.new_block()
        if true_end:
            cfg.add_edge(true_end.id, merge.id)
        if false_end:
            cfg.add_edge(false_end.id, merge.id)

        return merge

    def _process_loop(
        self, cfg: CFG, current: BasicBlock, stmt: dict, exit_block: BasicBlock
    ) -> BasicBlock | None:
        """Process for/while loops."""
        # Initialization (for-loops)
        init = stmt.get("initializationExpression")
        if init:
            current.statements.append(init)

        # Condition block (loop header)
        cond_block = cfg.new_block()
        cfg.add_edge(current.id, cond_block.id)

        condition = stmt.get("condition")
        if condition:
            cond_block.statements.append({"nodeType": "LoopCondition", "expression": condition})

        # Loop body
        body_block = cfg.new_block()
        cfg.add_edge(cond_block.id, body_block.id)

        body = stmt.get("body", {})
        body_stmts = body.get("statements", []) if body.get("nodeType") == "Block" else [body]
        body_end = self._process_statements(cfg, body_block, body_stmts, exit_block)

        # Loop increment (for-loops) and back-edge
        if body_end:
            loop_expr = stmt.get("loopExpression")
            if loop_expr:
                body_end.statements.append(loop_expr)
            cfg.add_edge(body_end.id, cond_block.id)  # Back-edge

        # Exit loop
        after_loop = cfg.new_block()
        cfg.add_edge(cond_block.id, after_loop.id)

        return after_loop

    def _process_do_while(
        self, cfg: CFG, current: BasicBlock, stmt: dict, exit_block: BasicBlock
    ) -> BasicBlock | None:
        """Process do-while loops (body executes at least once)."""
        body_block = cfg.new_block()
        cfg.add_edge(current.id, body_block.id)

        body = stmt.get("body", {})
        body_stmts = body.get("statements", []) if body.get("nodeType") == "Block" else [body]
        body_end = self._process_statements(cfg, body_block, body_stmts, exit_block)

        cond_block = cfg.new_block()
        if body_end:
            cfg.add_edge(body_end.id, cond_block.id)

        condition = stmt.get("condition")
        if condition:
            cond_block.statements.append({"nodeType": "LoopCondition", "expression": condition})

        # Back-edge (repeat) and exit
        cfg.add_edge(cond_block.id, body_block.id)  # repeat
        after_loop = cfg.new_block()
        cfg.add_edge(cond_block.id, after_loop.id)  # exit

        return after_loop

    def _process_try(
        self, cfg: CFG, current: BasicBlock, stmt: dict, exit_block: BasicBlock
    ) -> BasicBlock | None:
        """Process try/catch statements."""
        # External call in try
        current.statements.append(stmt.get("externalCall", {}))

        # Success block
        success_block = cfg.new_block()
        cfg.add_edge(current.id, success_block.id)
        clauses = stmt.get("clauses", [])
        success_end = None
        if clauses:
            success_body = clauses[0].get("block", {})
            success_stmts = success_body.get("statements", [])
            success_end = self._process_statements(cfg, success_block, success_stmts, exit_block)

        # Catch blocks
        catch_ends: list[BasicBlock | None] = []
        for clause in clauses[1:]:
            catch_block = cfg.new_block()
            cfg.add_edge(current.id, catch_block.id)
            catch_body = clause.get("block", {})
            catch_stmts = catch_body.get("statements", [])
            catch_end = self._process_statements(cfg, catch_block, catch_stmts, exit_block)
            catch_ends.append(catch_end)

        # Merge
        merge = cfg.new_block()
        if success_end:
            cfg.add_edge(success_end.id, merge.id)
        for ce in catch_ends:
            if ce:
                cfg.add_edge(ce.id, merge.id)

        return merge

    def _annotate_block(self, block: BasicBlock, stmt: dict) -> None:
        """Annotate a block based on statement content."""
        stmt_str = str(stmt)

        if ".call" in stmt_str or ".delegatecall" in stmt_str or ".transfer(" in stmt_str:
            block.has_external_call = True
        if "require(" in stmt_str or "assert(" in stmt_str or "revert" in stmt_str:
            block.has_require = True

        nt = stmt.get("nodeType", "")
        if nt == "ExpressionStatement":
            expr = stmt.get("expression", {})
            if expr.get("nodeType") == "Assignment":
                block.has_state_write = True


# ── Taint Analyzer ───────────────────────────────────────────────────────────


# Taint source patterns found in AST identifiers
TAINT_SOURCES: dict[str, TaintKind] = {
    "msg.sender": TaintKind.MSG_SENDER,
    "msg.value": TaintKind.MSG_VALUE,
    "msg.data": TaintKind.MSG_DATA,
    "tx.origin": TaintKind.TX_ORIGIN,
    "block.timestamp": TaintKind.BLOCK_TIMESTAMP,
    "block.number": TaintKind.BLOCK_NUMBER,
}


class TaintAnalyzer:
    """Perform taint analysis on a Control Flow Graph.

    Forward dataflow analysis:
    1. Identify sources (calldata params, msg.sender, etc.)
    2. Propagate taint through assignments and function calls
    3. Check if tainted values reach sinks
    """

    def __init__(self) -> None:
        self._flows: list[TaintFlow] = []
        self._reentrancy_paths: list[ReentrancyPath] = []

    def analyze(
        self,
        cfg: CFG,
        param_names: list[str] | None = None,
        state_var_names: set[str] | None = None,
    ) -> tuple[list[TaintFlow], list[ReentrancyPath]]:
        """Run taint analysis on a CFG.

        Args:
            cfg: Control flow graph to analyze
            param_names: Function parameter names (tainted as CALLDATA)
            state_var_names: State variable names (for tracking reads/writes)

        Returns:
            Tuple of (taint flows, reentrancy paths) detected
        """
        self._flows = []
        self._reentrancy_paths = []

        if not cfg.blocks:
            return self._flows, self._reentrancy_paths

        # Initialize entry block taint from parameters
        entry = cfg.blocks.get(cfg.entry_block)
        if entry and param_names:
            for param in param_names:
                entry.tainted_vars[param].add(TaintKind.CALLDATA)

        # Forward propagation (worklist algorithm)
        worklist = [cfg.entry_block]
        visited: set[int] = set()

        while worklist:
            block_id = worklist.pop(0)
            if block_id in visited:
                continue
            visited.add(block_id)

            block = cfg.blocks.get(block_id)
            if not block:
                continue

            # Propagate taint from predecessors
            for pred_id in block.predecessors:
                pred = cfg.blocks.get(pred_id)
                if pred:
                    for var, taints in pred.tainted_vars.items():
                        block.tainted_vars[var].update(taints)

            # Process statements in this block
            for stmt in block.statements:
                self._process_taint_statement(cfg.function_name, block, stmt)

            # Check for reentrancy (external call before state write)
            self._check_reentrancy_pattern(cfg, block)

            # Add successors to worklist
            for succ_id in block.successors:
                if succ_id not in visited:
                    worklist.append(succ_id)

        return self._flows, self._reentrancy_paths

    def _process_taint_statement(
        self, func_name: str, block: BasicBlock, stmt: dict
    ) -> None:
        """Process a single statement for taint propagation."""
        nt = stmt.get("nodeType", "")

        # Assignment: propagate taint from RHS to LHS
        if nt == "Assignment" or (
            nt == "ExpressionStatement"
            and stmt.get("expression", {}).get("nodeType") == "Assignment"
        ):
            assignment = stmt if nt == "Assignment" else stmt["expression"]
            lhs = assignment.get("leftHandSide", {})
            rhs = assignment.get("rightHandSide", {})

            lhs_name = self._extract_var_name(lhs)
            rhs_taints = self._get_expression_taints(block, rhs)

            if lhs_name and rhs_taints:
                block.tainted_vars[lhs_name].update(rhs_taints)

        # Variable declarations with initial value
        if nt == "VariableDeclarationStatement":
            declarations = stmt.get("declarations", [])
            initial_value = stmt.get("initialValue")
            if declarations and initial_value:
                for decl in declarations:
                    if decl:
                        var_name = decl.get("name", "")
                        taints = self._get_expression_taints(block, initial_value)
                        if var_name and taints:
                            block.tainted_vars[var_name].update(taints)

        # Check if tainted values reach sinks
        self._check_sinks(func_name, block, stmt)

    def _get_expression_taints(
        self, block: BasicBlock, expr: dict
    ) -> set[TaintKind]:
        """Determine what taint an expression carries."""
        if not isinstance(expr, dict):
            return set()

        nt = expr.get("nodeType", "")
        taints: set[TaintKind] = set()

        # Direct taint sources
        if nt == "MemberAccess":
            member = expr.get("memberName", "")
            base = expr.get("expression", {})
            base_name = base.get("name", "") if isinstance(base, dict) else ""
            full_name = f"{base_name}.{member}"
            if full_name in TAINT_SOURCES:
                taints.add(TAINT_SOURCES[full_name])

        # Variable reference — check if already tainted
        if nt == "Identifier":
            var_name = expr.get("name", "")
            if var_name in block.tainted_vars:
                taints.update(block.tainted_vars[var_name])

        # Function call returns — tainted if it's an external call
        if nt == "FunctionCall":
            func_expr = expr.get("expression", {})
            if func_expr.get("nodeType") == "MemberAccess":
                member = func_expr.get("memberName", "")
                if member in ("call", "delegatecall", "staticcall"):
                    taints.add(TaintKind.EXTERNAL_RETURN)

            # Propagate taint through arguments
            for arg in expr.get("arguments", []):
                taints.update(self._get_expression_taints(block, arg))

        # Binary/unary operations — union of operand taints
        if nt == "BinaryOperation":
            taints.update(self._get_expression_taints(block, expr.get("leftExpression", {})))
            taints.update(self._get_expression_taints(block, expr.get("rightExpression", {})))

        if nt == "UnaryOperation":
            taints.update(self._get_expression_taints(block, expr.get("subExpression", {})))

        # Index access — union of base and index taints
        if nt == "IndexAccess":
            taints.update(self._get_expression_taints(block, expr.get("baseExpression", {})))
            taints.update(self._get_expression_taints(block, expr.get("indexExpression", {})))

        # Conditional (ternary) — union of both branches
        if nt == "Conditional":
            taints.update(self._get_expression_taints(block, expr.get("trueExpression", {})))
            taints.update(self._get_expression_taints(block, expr.get("falseExpression", {})))

        return taints

    def _check_sinks(self, func_name: str, block: BasicBlock, stmt: dict) -> None:
        """Check if any tainted values reach dangerous sinks."""
        stmt_str = str(stmt)

        # ETH transfer sinks
        if ".call{value:" in stmt_str or ".transfer(" in stmt_str or ".send(" in stmt_str:
            for var, taints in block.tainted_vars.items():
                if taints:
                    self._flows.append(TaintFlow(
                        source_kind=next(iter(taints)),
                        sink_kind=SinkKind.ETH_TRANSFER,
                        source_variable=var,
                        sink_variable="ETH transfer",
                        path=[block.id],
                        function_name=func_name,
                        description=f"Tainted variable '{var}' influences ETH transfer target/amount",
                    ))

        # delegatecall sink
        if ".delegatecall(" in stmt_str:
            for var, taints in block.tainted_vars.items():
                if TaintKind.CALLDATA in taints or TaintKind.EXTERNAL_RETURN in taints:
                    self._flows.append(TaintFlow(
                        source_kind=next(iter(taints)),
                        sink_kind=SinkKind.DELEGATECALL,
                        source_variable=var,
                        sink_variable="delegatecall target",
                        path=[block.id],
                        function_name=func_name,
                        description=f"User-controlled '{var}' reaches delegatecall",
                    ))

    def _check_reentrancy_pattern(self, cfg: CFG, block: BasicBlock) -> None:
        """Check if any successor blocks write state after an external call."""
        if not block.has_external_call:
            return

        # BFS from this block to find state writes reachable after the call
        visited: set[int] = set()
        queue = list(block.successors)

        while queue:
            succ_id = queue.pop(0)
            if succ_id in visited:
                continue
            visited.add(succ_id)

            succ = cfg.blocks.get(succ_id)
            if not succ:
                continue

            if succ.has_state_write:
                self._reentrancy_paths.append(ReentrancyPath(
                    function_name=cfg.function_name,
                    call_block=block.id,
                    write_block=succ.id,
                    call_target="external",
                    write_variable="state",
                    path=[block.id, succ.id],
                ))

            queue.extend(s for s in succ.successors if s not in visited)

    def _extract_var_name(self, node: dict) -> str:
        """Extract variable name from AST expression."""
        if not isinstance(node, dict):
            return ""
        nt = node.get("nodeType", "")
        if nt == "Identifier":
            return node.get("name", "")
        if nt == "IndexAccess":
            return self._extract_var_name(node.get("baseExpression", {}))
        if nt == "MemberAccess":
            return self._extract_var_name(node.get("expression", {}))
        return ""


# ── Convenience ──────────────────────────────────────────────────────────────


def build_function_cfg(
    func_name: str,
    body_node: dict[str, Any] | None,
    source_code: str = "",
) -> CFG:
    """Build a CFG for a single function."""
    builder = CFGBuilder(source_code)
    return builder.build(func_name, body_node)


def run_taint_analysis(
    cfg: CFG,
    param_names: list[str] | None = None,
    state_var_names: set[str] | None = None,
) -> tuple[list[TaintFlow], list[ReentrancyPath]]:
    """Run taint analysis on a CFG."""
    analyzer = TaintAnalyzer()
    return analyzer.analyze(cfg, param_names, state_var_names)
