"""Cross-contract taint analysis for proxy/implementation patterns.

Extends the single-function TaintAnalyzer (engine.core.cfg) with:

  1. **Inter-contract flow tracking** — when a proxy delegates to an
     implementation, taint from the proxy caller propagates through the
     delegatecall into the implementation's storage context.

  2. **Proxy-implementation pair resolution** — given an AST result with
     multiple contracts, identifies proxy → impl relationships via
     known proxy patterns (ERC-1967, Transparent, UUPS, Beacon, Diamond).

  3. **Cross-contract call graph taint** — uses CallGraph edges to
     propagate taint across contract boundaries (external calls, library
     calls, super calls).

  4. **Aggregate report** — produces `CrossContractTaintReport` listing
     all cross-boundary taint flows with source/sink contracts.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from engine.core.ast_analyzer import ASTAnalysisResult, ContractDef, FunctionDef
from engine.core.call_graph import CallGraph, CallGraphBuilder, CallType
from engine.core.cfg import (
    CFGBuilder,
    TaintAnalyzer,
    TaintFlow,
    TaintKind,
    ReentrancyPath,
    SinkKind,
)


# ── Data Models ──────────────────────────────────────────────────────────────


class ProxyPattern(str, Enum):
    """Known proxy patterns."""
    ERC1967 = "ERC-1967"
    TRANSPARENT = "TransparentProxy"
    UUPS = "UUPS"
    BEACON = "Beacon"
    DIAMOND = "Diamond (EIP-2535)"
    MINIMAL_PROXY = "EIP-1167 Clone"
    CUSTOM = "custom-delegatecall"


@dataclass
class ProxyPair:
    """A resolved proxy → implementation relationship."""
    proxy_contract: str
    impl_contract: str
    pattern: ProxyPattern
    delegatecall_functions: list[str] = field(default_factory=list)
    storage_slot: str = ""  # ERC-1967 slot if applicable


@dataclass
class CrossContractFlow:
    """A taint flow that crosses contract boundaries."""
    source_contract: str
    source_function: str
    source_kind: TaintKind
    source_variable: str

    sink_contract: str
    sink_function: str
    sink_kind: SinkKind
    sink_variable: str

    call_chain: list[str]  # contract.function path
    proxy_pair: ProxyPair | None = None
    description: str = ""


@dataclass
class CrossContractTaintReport:
    """Full cross-contract taint analysis report."""
    proxy_pairs: list[ProxyPair] = field(default_factory=list)
    cross_flows: list[CrossContractFlow] = field(default_factory=list)
    reentrancy_across_contracts: list[dict[str, Any]] = field(default_factory=list)
    summary: dict[str, Any] = field(default_factory=dict)


# ── Proxy Pattern Detection ─────────────────────────────────────────────────

# ERC-1967 implementation slot: keccak256("eip1967.proxy.implementation") - 1
ERC1967_IMPL_SLOT = "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc"
ERC1967_ADMIN_SLOT = "0xb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103"
ERC1967_BEACON_SLOT = "0xa3f0ad74e5423aebfd80d3ef4346578335a9a72aeaee59ff6cb3582b35133d50"


def _detect_proxy_pattern(contract: ContractDef, source_code: str) -> ProxyPattern | None:
    """Identify which proxy pattern a contract uses."""
    code = source_code

    # Check inheritance
    parent_names = {inh.base_name for inh in contract.inheritance}
    if "UUPSUpgradeable" in parent_names:
        return ProxyPattern.UUPS
    if "TransparentUpgradeableProxy" in parent_names:
        return ProxyPattern.TRANSPARENT
    if "BeaconProxy" in parent_names:
        return ProxyPattern.BEACON
    if any("Diamond" in p for p in parent_names):
        return ProxyPattern.DIAMOND

    # Check for ERC-1967 slot references
    if ERC1967_IMPL_SLOT in code:
        return ProxyPattern.ERC1967

    # Check for EIP-1167 minimal proxy (clone)
    if "363d3d373d3d3d363d73" in code.lower():
        return ProxyPattern.MINIMAL_PROXY

    # Generic delegatecall fallback
    has_delegatecall = any(
        ".delegatecall(" in (f.body_source if hasattr(f, "body_source") else "")
        or any(c.call_type == "delegatecall" for c in f.external_calls)
        for f in contract.functions
    )
    if has_delegatecall:
        return ProxyPattern.CUSTOM

    return None


def _identify_proxy_pairs(
    contracts: list[ContractDef],
    source_code: str,
) -> list[ProxyPair]:
    """Find proxy → implementation pairs in a set of contracts."""
    pairs: list[ProxyPair] = []
    proxy_contracts: list[tuple[ContractDef, ProxyPattern]] = []

    for contract in contracts:
        pattern = _detect_proxy_pattern(contract, source_code)
        if pattern:
            proxy_contracts.append((contract, pattern))

    for proxy, pattern in proxy_contracts:
        # Heuristic: non-proxy contracts with Initializable or that lack
        # a constructor are likely implementations
        delegatecall_funcs = [
            f.name for f in proxy.functions
            if any(c.call_type == "delegatecall" for c in f.external_calls)
        ]

        for impl_candidate in contracts:
            if impl_candidate.name == proxy.name:
                continue
            # Implementation contracts typically inherit Initializable or
            # have an `initialize` function
            has_initialize = any(f.name == "initialize" for f in impl_candidate.functions)
            has_initializable = any(
                inh.base_name in ("Initializable", "OwnableUpgradeable", "UUPSUpgradeable")
                for inh in impl_candidate.inheritance
            )
            if has_initialize or has_initializable:
                pairs.append(ProxyPair(
                    proxy_contract=proxy.name,
                    impl_contract=impl_candidate.name,
                    pattern=pattern,
                    delegatecall_functions=delegatecall_funcs,
                    storage_slot=ERC1967_IMPL_SLOT if pattern in (
                        ProxyPattern.ERC1967, ProxyPattern.TRANSPARENT, ProxyPattern.UUPS
                    ) else "",
                ))

    return pairs


# ── Cross-Contract Taint Engine ──────────────────────────────────────────────


class CrossContractTaintAnalyzer:
    """Propagate taint across contract boundaries.

    Works in three passes:

    1. **Intra-contract** — run TaintAnalyzer on every function's CFG
       (already in engine.core.cfg).
    2. **Proxy delegation** — for identified proxy pairs, propagate
       caller taint through the proxy's fallback/delegatecall into the
       implementation's function namespace.
    3. **Call-graph propagation** — follow external call edges in the
       CallGraph and merge taint sets across boundaries.
    """

    def __init__(self) -> None:
        self._intra_results: dict[str, list[TaintFlow]] = {}  # contract.func -> flows
        self._reentrancy: dict[str, list[ReentrancyPath]] = {}

    def analyze(
        self,
        ast_result: ASTAnalysisResult,
        source_code: str = "",
    ) -> CrossContractTaintReport:
        """Run full cross-contract taint analysis."""
        contracts = ast_result.contracts
        report = CrossContractTaintReport()

        if not contracts:
            return report

        # ── Phase 1: Identify proxy pairs ────────────────────────────
        report.proxy_pairs = _identify_proxy_pairs(contracts, source_code)

        # ── Phase 2: Build call graph ────────────────────────────────
        builder = CallGraphBuilder()
        call_graph = builder.build(contracts)

        # ── Phase 3: Intra-contract taint on all functions ───────────
        cfg_builder = CFGBuilder(source_code)
        taint_analyzer = TaintAnalyzer()

        function_taints: dict[str, dict[str, set[TaintKind]]] = {}
        # key = "ContractName.functionName" -> var -> taints

        for contract in contracts:
            for func in contract.functions:
                key = f"{contract.name}.{func.name}"
                cfg = cfg_builder.build(func.name, func.body_node)
                param_names = [p.name for p in func.parameters]
                flows, reent = taint_analyzer.analyze(cfg, param_names)
                self._intra_results[key] = flows
                self._reentrancy[key] = reent

                # Collect exit-block taint state
                taint_state: dict[str, set[TaintKind]] = {}
                for block in cfg.blocks.values():
                    for var, kinds in block.tainted_vars.items():
                        taint_state.setdefault(var, set()).update(kinds)
                function_taints[key] = taint_state

        # ── Phase 4: Propagate across proxy pairs ────────────────────
        for pair in report.proxy_pairs:
            # The proxy's fallback dispatches calldata to the implementation
            # So all CALLDATA taint from the proxy carries into the impl
            proxy_fallback_key = f"{pair.proxy_contract}.fallback"
            proxy_taint = function_taints.get(proxy_fallback_key, {})

            for func in self._get_contract_functions(contracts, pair.impl_contract):
                impl_key = f"{pair.impl_contract}.{func.name}"
                impl_taint = function_taints.get(impl_key, {})

                # Merge proxy caller taint into implementation params
                for param in func.parameters:
                    impl_taint.setdefault(param.name, set()).add(TaintKind.CALLDATA)

                function_taints[impl_key] = impl_taint

                # Check if merged taint reaches a sink in the impl
                for flow in self._intra_results.get(impl_key, []):
                    report.cross_flows.append(CrossContractFlow(
                        source_contract=pair.proxy_contract,
                        source_function="fallback (delegatecall)",
                        source_kind=TaintKind.CALLDATA,
                        source_variable="msg.data",
                        sink_contract=pair.impl_contract,
                        sink_function=func.name,
                        sink_kind=flow.sink_kind,
                        sink_variable=flow.sink_variable,
                        call_chain=[
                            f"{pair.proxy_contract}.fallback",
                            f"→ delegatecall",
                            f"{pair.impl_contract}.{func.name}",
                        ],
                        proxy_pair=pair,
                        description=(
                            f"Taint from proxy caller propagates through "
                            f"{pair.pattern.value} delegatecall into "
                            f"{pair.impl_contract}.{func.name}() "
                            f"reaching {flow.sink_kind.value} sink"
                        ),
                    ))

        # ── Phase 5: Propagate across external call edges ────────────
        for node_key, node in call_graph.nodes.items() if hasattr(call_graph, "nodes") else []:
            edges = call_graph.edges_from.get(node_key, []) if hasattr(call_graph, "edges_from") else []
            caller_key = f"{node.contract}.{node.function}"
            caller_taint = function_taints.get(caller_key, {})

            for edge in edges:
                if edge.call_type in (CallType.EXTERNAL, CallType.DELEGATECALL):
                    callee_key = f"{edge.callee_contract}.{edge.callee_function}"
                    callee_taint = function_taints.get(callee_key, {})

                    # Tainted args flow into callee
                    for var, kinds in caller_taint.items():
                        if kinds:
                            callee_taint.setdefault(var, set()).update(kinds)

                    function_taints[callee_key] = callee_taint

        # ── Phase 6: Cross-contract reentrancy detection ─────────────
        for pair in report.proxy_pairs:
            for func in self._get_contract_functions(contracts, pair.impl_contract):
                impl_key = f"{pair.impl_contract}.{func.name}"
                for reent in self._reentrancy.get(impl_key, []):
                    report.reentrancy_across_contracts.append({
                        "proxy": pair.proxy_contract,
                        "implementation": pair.impl_contract,
                        "function": func.name,
                        "pattern": pair.pattern.value,
                        "call_block": reent.call_block,
                        "write_block": reent.write_block,
                        "description": (
                            f"Reentrancy in {pair.impl_contract}.{func.name}() "
                            f"reachable through {pair.proxy_contract} "
                            f"({pair.pattern.value} proxy)"
                        ),
                    })

        # ── Summary ──────────────────────────────────────────────────
        report.summary = {
            "contracts_analyzed": len(contracts),
            "proxy_pairs_found": len(report.proxy_pairs),
            "cross_contract_flows": len(report.cross_flows),
            "cross_contract_reentrancy": len(report.reentrancy_across_contracts),
            "total_intra_flows": sum(len(f) for f in self._intra_results.values()),
            "proxy_patterns": list({p.pattern.value for p in report.proxy_pairs}),
        }

        return report

    @staticmethod
    def _get_contract_functions(
        contracts: list[ContractDef], name: str
    ) -> list[FunctionDef]:
        """Get all functions for a named contract."""
        for c in contracts:
            if c.name == name:
                return c.functions
        return []


# ── Convenience ──────────────────────────────────────────────────────────────


def run_cross_contract_taint(
    ast_result: ASTAnalysisResult,
    source_code: str = "",
) -> CrossContractTaintReport:
    """Run cross-contract taint analysis on an AST result."""
    analyzer = CrossContractTaintAnalyzer()
    return analyzer.analyze(ast_result, source_code)
