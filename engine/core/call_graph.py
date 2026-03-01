"""Cross-function and cross-contract call graph analysis.

Builds a directed graph of function calls within and across contracts,
enabling analysis of:
  - Attack surface (externally-reachable functions)
  - Privilege escalation paths (external → privileged functions)
  - Cross-contract reentrancy vectors
  - Dead / unreachable code
  - Function dependency chains for impact analysis
"""

from __future__ import annotations

from collections import defaultdict, deque
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Any

from engine.core.ast_analyzer import ContractDef, FunctionDef, Visibility


# ── Data Structures ──────────────────────────────────────────────────────────


class CallType(str, Enum):
    """How a function call is made."""
    INTERNAL = "internal"         # Same contract, direct call
    EXTERNAL = "external"         # Cross-contract via interface
    DELEGATECALL = "delegatecall"
    STATICCALL = "staticcall"
    LOW_LEVEL = "low_level"       # .call()
    LIBRARY = "library"
    SUPER = "super"
    MODIFIER = "modifier"


@dataclass
class CallEdge:
    """A directed edge in the call graph."""
    caller_contract: str
    caller_function: str
    callee_contract: str
    callee_function: str
    call_type: CallType
    line: int = 0
    has_value: bool = False       # Sends ETH
    has_gas_limit: bool = False
    arguments: list[str] = field(default_factory=list)


@dataclass
class CallNode:
    """A node in the call graph (one function)."""
    contract: str
    function: str
    visibility: Visibility = Visibility.INTERNAL
    is_payable: bool = False
    is_view: bool = False
    modifiers: list[str] = field(default_factory=list)
    state_reads: list[str] = field(default_factory=list)
    state_writes: list[str] = field(default_factory=list)
    cyclomatic_complexity: int = 1

    @property
    def key(self) -> str:
        return f"{self.contract}.{self.function}"


@dataclass
class CallGraph:
    """Directed graph of function calls."""
    nodes: dict[str, CallNode] = field(default_factory=dict)
    edges: list[CallEdge] = field(default_factory=list)
    # Adjacency lists
    _outgoing: dict[str, list[CallEdge]] = field(default_factory=lambda: defaultdict(list))
    _incoming: dict[str, list[CallEdge]] = field(default_factory=lambda: defaultdict(list))

    def add_node(self, node: CallNode) -> None:
        self.nodes[node.key] = node

    def add_edge(self, edge: CallEdge) -> None:
        self.edges.append(edge)
        caller_key = f"{edge.caller_contract}.{edge.caller_function}"
        callee_key = f"{edge.callee_contract}.{edge.callee_function}"
        self._outgoing[caller_key].append(edge)
        self._incoming[callee_key].append(edge)

    def callers_of(self, contract: str, function: str) -> list[CallEdge]:
        """Get all edges calling into this function."""
        return self._incoming.get(f"{contract}.{function}", [])

    def callees_of(self, contract: str, function: str) -> list[CallEdge]:
        """Get all edges from this function to others."""
        return self._outgoing.get(f"{contract}.{function}", [])

    @property
    def entry_points(self) -> list[CallNode]:
        """Functions reachable from the outside (external/public)."""
        return [
            n for n in self.nodes.values()
            if n.visibility in (Visibility.EXTERNAL, Visibility.PUBLIC)
        ]

    @property
    def unreachable_functions(self) -> list[CallNode]:
        """Internal/private functions never called by anyone."""
        called_keys = {
            f"{e.callee_contract}.{e.callee_function}" for e in self.edges
        }
        return [
            n for n in self.nodes.values()
            if n.visibility in (Visibility.INTERNAL, Visibility.PRIVATE)
            and n.key not in called_keys
            and n.function not in ("constructor", "receive", "fallback")
        ]


@dataclass
class AttackPath:
    """A path from an entry point to a sensitive operation."""
    entry: str           # entry point function key
    target: str          # target function key
    path: list[str]      # function keys
    risk_factors: list[str] = field(default_factory=list)
    max_depth: int = 0


# ── Call Graph Builder ───────────────────────────────────────────────────────


class CallGraphBuilder:
    """Build a call graph from AST-analyzed contract definitions."""

    def build(self, contracts: list[ContractDef]) -> CallGraph:
        """Build call graph from analyzed contracts."""
        graph = CallGraph()
        contract_map = {c.name: c for c in contracts}

        # 1. Add all function nodes
        for contract in contracts:
            for func in contract.functions:
                node = CallNode(
                    contract=contract.name,
                    function=func.name,
                    visibility=func.visibility,
                    is_payable=func.is_payable,
                    is_view=func.is_view,
                    modifiers=[m.name for m in func.modifiers],
                    state_reads=[r.variable for r in func.state_reads],
                    state_writes=[w.variable for w in func.state_writes],
                    cyclomatic_complexity=func.complexity,
                )
                graph.add_node(node)

        # 2. Add call edges
        for contract in contracts:
            for func in contract.functions:
                self._extract_call_edges(graph, contract, func, contract_map)

        return graph

    def _extract_call_edges(
        self,
        graph: CallGraph,
        contract: ContractDef,
        func: FunctionDef,
        contract_map: dict[str, ContractDef],
    ) -> None:
        """Extract call edges from a function's external calls and body."""

        # External calls (from AST analyzer)
        for ext_call in func.external_calls:
            # Determine call type
            if ext_call.kind in ("call", "transfer", "send"):
                call_type = CallType.EXTERNAL if ext_call.kind == "call" else CallType.LOW_LEVEL
            elif ext_call.kind == "delegatecall":
                call_type = CallType.DELEGATECALL
            elif ext_call.kind == "staticcall":
                call_type = CallType.STATICCALL
            else:
                call_type = CallType.EXTERNAL

            edge = CallEdge(
                caller_contract=contract.name,
                caller_function=func.name,
                callee_contract=ext_call.target,
                callee_function=ext_call.function_name or ext_call.kind,
                call_type=call_type,
                line=ext_call.line,
                has_value=ext_call.sends_value,
            )
            graph.add_edge(edge)

        # Internal calls (walk the function body)
        if func.body_node:
            self._walk_for_internal_calls(
                graph, contract.name, func.name, func.body_node, contract_map
            )

        # Modifier calls
        for mod in func.modifiers:
            edge = CallEdge(
                caller_contract=contract.name,
                caller_function=func.name,
                callee_contract=contract.name,
                callee_function=mod.name,
                call_type=CallType.MODIFIER,
            )
            graph.add_edge(edge)

    def _walk_for_internal_calls(
        self,
        graph: CallGraph,
        contract_name: str,
        func_name: str,
        node: dict[str, Any],
        contract_map: dict[str, ContractDef],
    ) -> None:
        """Walk AST node tree to find internal function calls."""
        if not isinstance(node, dict):
            return

        nt = node.get("nodeType", "")

        if nt == "FunctionCall":
            expr = node.get("expression", {})
            expr_nt = expr.get("nodeType", "")

            # Direct internal call: foo(x)
            if expr_nt == "Identifier":
                callee_name = expr.get("name", "")
                # Check if it's a function in the same contract
                if callee_name and f"{contract_name}.{callee_name}" in graph.nodes:
                    edge = CallEdge(
                        caller_contract=contract_name,
                        caller_function=func_name,
                        callee_contract=contract_name,
                        callee_function=callee_name,
                        call_type=CallType.INTERNAL,
                    )
                    graph.add_edge(edge)

            # Super call: super.foo(x)
            elif expr_nt == "MemberAccess":
                base = expr.get("expression", {})
                member = expr.get("memberName", "")
                if base.get("name") == "super":
                    edge = CallEdge(
                        caller_contract=contract_name,
                        caller_function=func_name,
                        callee_contract=contract_name,
                        callee_function=member,
                        call_type=CallType.SUPER,
                    )
                    graph.add_edge(edge)

        # Recurse into children
        for key, value in node.items():
            if isinstance(value, dict):
                self._walk_for_internal_calls(graph, contract_name, func_name, value, contract_map)
            elif isinstance(value, list):
                for item in value:
                    if isinstance(item, dict):
                        self._walk_for_internal_calls(graph, contract_name, func_name, item, contract_map)


# ── Attack Surface Analysis ─────────────────────────────────────────────────


class AttackSurfaceAnalyzer:
    """Analyze attack surface from a call graph."""

    def analyze(self, graph: CallGraph) -> dict[str, Any]:
        """Full attack surface analysis."""
        return {
            "entry_points": self._analyze_entry_points(graph),
            "attack_paths": self._find_attack_paths(graph),
            "privilege_escalation": self._find_privilege_escalation(graph),
            "unreachable_code": [n.key for n in graph.unreachable_functions],
            "stats": self._compute_stats(graph),
        }

    def _analyze_entry_points(self, graph: CallGraph) -> list[dict[str, Any]]:
        """Classify entry points by risk."""
        results = []
        for node in graph.entry_points:
            risk_factors = []
            if node.is_payable:
                risk_factors.append("payable")
            if not node.modifiers:
                risk_factors.append("no_access_control")
            if node.state_writes:
                risk_factors.append("state_mutating")

            # Check what this function can reach
            reachable = self._reachable_from(graph, node.key)
            has_delegatecall = any(
                e.call_type == CallType.DELEGATECALL
                for key in reachable
                for e in graph.callees_of(*key.split(".", 1)) if "." in key
            )
            has_eth_send = any(
                e.has_value
                for key in reachable
                for e in graph.callees_of(*key.split(".", 1)) if "." in key
            )

            if has_delegatecall:
                risk_factors.append("reaches_delegatecall")
            if has_eth_send:
                risk_factors.append("reaches_eth_transfer")

            risk_score = len(risk_factors) / 5.0  # Normalize to 0–1

            results.append({
                "function": node.key,
                "visibility": node.visibility.value,
                "is_payable": node.is_payable,
                "modifiers": node.modifiers,
                "risk_factors": risk_factors,
                "risk_score": round(risk_score, 2),
                "reachable_count": len(reachable),
                "complexity": node.cyclomatic_complexity,
            })

        # Sort by risk score descending
        results.sort(key=lambda r: r["risk_score"], reverse=True)
        return results

    def _find_attack_paths(self, graph: CallGraph) -> list[AttackPath]:
        """Find paths from external entry points to dangerous operations."""
        paths: list[AttackPath] = []

        # Identify sensitive targets (delegatecall, selfdestruct, state writes with no guard)
        sensitive: set[str] = set()
        for node in graph.nodes.values():
            is_sensitive = False
            for edge in graph.callees_of(node.contract, node.function):
                if edge.call_type == CallType.DELEGATECALL:
                    is_sensitive = True
                if edge.has_value:
                    is_sensitive = True
            if node.state_writes and not node.modifiers:
                is_sensitive = True
            if is_sensitive:
                sensitive.add(node.key)

        # BFS from each entry point
        for entry in graph.entry_points:
            for target_key in sensitive:
                path = self._find_path(graph, entry.key, target_key)
                if path:
                    risk_factors = []
                    entry_node = graph.nodes.get(entry.key)
                    target_node = graph.nodes.get(target_key)
                    if entry_node and entry_node.is_payable:
                        risk_factors.append("payable_entry")
                    if entry_node and not entry_node.modifiers:
                        risk_factors.append("unrestricted_entry")
                    if target_node and not target_node.modifiers:
                        risk_factors.append("unprotected_target")

                    paths.append(AttackPath(
                        entry=entry.key,
                        target=target_key,
                        path=path,
                        risk_factors=risk_factors,
                        max_depth=len(path),
                    ))

        return paths

    def _find_privilege_escalation(self, graph: CallGraph) -> list[dict[str, Any]]:
        """Find paths from unprivileged to privileged functions."""
        results = []

        # Privileged = functions with access control modifiers
        privileged_keywords = {"onlyOwner", "onlyAdmin", "onlyRole", "whenNotPaused", "initializer"}

        for entry in graph.entry_points:
            if entry.modifiers:
                continue  # Already guarded, not an entry for escalation

            reachable = self._reachable_from(graph, entry.key)
            for key in reachable:
                node = graph.nodes.get(key)
                if node and any(m in privileged_keywords for m in node.modifiers):
                    path = self._find_path(graph, entry.key, key)
                    if path:
                        results.append({
                            "entry": entry.key,
                            "target": key,
                            "target_modifiers": node.modifiers,
                            "path": path,
                        })

        return results

    def _reachable_from(self, graph: CallGraph, start_key: str) -> set[str]:
        """BFS to find all functions reachable from a starting function."""
        visited: set[str] = set()
        queue = deque([start_key])

        while queue:
            current = queue.popleft()
            if current in visited:
                continue
            visited.add(current)

            parts = current.split(".", 1)
            if len(parts) != 2:
                continue
            for edge in graph.callees_of(parts[0], parts[1]):
                callee_key = f"{edge.callee_contract}.{edge.callee_function}"
                if callee_key not in visited and callee_key in graph.nodes:
                    queue.append(callee_key)

        visited.discard(start_key)
        return visited

    def _find_path(
        self, graph: CallGraph, start: str, target: str, max_depth: int = 10
    ) -> list[str] | None:
        """BFS shortest path between two nodes."""
        if start == target:
            return [start]

        visited: set[str] = set()
        queue: deque[list[str]] = deque([[start]])

        while queue:
            path = queue.popleft()
            if len(path) > max_depth:
                continue

            current = path[-1]
            if current in visited:
                continue
            visited.add(current)

            parts = current.split(".", 1)
            if len(parts) != 2:
                continue

            for edge in graph.callees_of(parts[0], parts[1]):
                callee_key = f"{edge.callee_contract}.{edge.callee_function}"
                if callee_key == target:
                    return path + [callee_key]
                if callee_key not in visited and callee_key in graph.nodes:
                    queue.append(path + [callee_key])

        return None

    def _compute_stats(self, graph: CallGraph) -> dict[str, Any]:
        """Compute call graph statistics."""
        return {
            "total_functions": len(graph.nodes),
            "total_call_edges": len(graph.edges),
            "entry_points": len(graph.entry_points),
            "unreachable_functions": len(graph.unreachable_functions),
            "external_calls": sum(
                1 for e in graph.edges if e.call_type in (CallType.EXTERNAL, CallType.LOW_LEVEL)
            ),
            "delegatecalls": sum(1 for e in graph.edges if e.call_type == CallType.DELEGATECALL),
            "internal_calls": sum(1 for e in graph.edges if e.call_type == CallType.INTERNAL),
            "eth_transfers": sum(1 for e in graph.edges if e.has_value),
            "avg_complexity": round(
                sum(n.cyclomatic_complexity for n in graph.nodes.values()) / max(len(graph.nodes), 1),
                1,
            ),
        }


# ── Convenience ──────────────────────────────────────────────────────────────


def build_call_graph(contracts: list[ContractDef]) -> CallGraph:
    """Build a call graph from AST-analyzed contracts."""
    return CallGraphBuilder().build(contracts)


def analyze_attack_surface(contracts: list[ContractDef]) -> dict[str, Any]:
    """Build call graph and analyze the attack surface."""
    graph = build_call_graph(contracts)
    return AttackSurfaceAnalyzer().analyze(graph)
