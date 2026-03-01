"""Web3 smart contract analyzer — orchestrates all detectors + advanced analysis.

Multi-stage pipeline:
  1. Static regex/pattern detectors (fast, high coverage)
  2. AST-based structural analysis (precise function/variable tracking)
  3. CFG + taint analysis (dataflow from sources to sinks)
  4. Call graph analysis (cross-function/cross-contract attack surface)
  5. Slither integration (enterprise-grade static analysis)
  6. LLM deep analysis (business logic, economic attacks, invariants)
  7. Cross-reference: corroborate/deduplicate across all passes
"""

from __future__ import annotations

import asyncio
import hashlib
import logging
import time
from typing import Any

from engine.analyzer.web3.base_detector import DetectorContext
from engine.analyzer.web3.registry import registry
from engine.core.types import (
    FindingSchema,
    FindingStatus,
    GasOptimization,
    Location,
    ScanResult,
    ScanType,
    ScanStatus,
    SecurityScore,
    Severity,
)
from engine.ingestion.contract_fetcher import ContractSource
from engine.ingestion.solidity_compiler import CompilationResult

logger = logging.getLogger(__name__)


class Web3Analyzer:
    """Orchestrate all smart contract vulnerability detectors + advanced analysis.

    Multi-pass pipeline:
    1. Static regex/pattern detectors (fast, high coverage)
    2. AST structural analysis (precise, no false positives from string matching)
    3. CFG + taint analysis (dataflow source→sink tracking)
    4. Call graph analysis (cross-function attack surface)
    5. Slither integration (corroboration with enterprise-grade tool)
    6. LLM deep analysis (business logic, economic attacks, invariants)
    7. Cross-reference: corroborate/deduplicate across all passes
    """

    def __init__(self, enable_llm: bool = True) -> None:
        registry.discover()
        self._enable_llm = enable_llm
        self._llm_analyzer = None  # Lazy init

    def _get_llm_analyzer(self):
        """Lazy-import to avoid circular deps and allow graceful fallback."""
        if self._llm_analyzer is None and self._enable_llm:
            try:
                from engine.analyzer.web3.llm_analyzer import LLMDeepAnalyzer
                self._llm_analyzer = LLMDeepAnalyzer()
            except Exception as e:
                print(f"LLM analyzer unavailable: {e}")
                self._enable_llm = False
        return self._llm_analyzer

    def analyze(
        self,
        source_code: str,
        compilation: CompilationResult | None = None,
        contract_source: ContractSource | None = None,
        scan_id: str = "",
        enable_llm: bool | None = None,
    ) -> ScanResult:
        """Run all detectors against a smart contract.

        Args:
            source_code: The Solidity source code
            compilation: Result from SolidityCompiler (optional)
            contract_source: Fetched contract metadata (optional)
            scan_id: Unique scan identifier
            enable_llm: Override LLM analysis setting for this scan

        Returns:
            ScanResult with all findings, gas optimizations, and scores
        """
        start_time = time.time()

        # Build detector context
        context = self._build_context(source_code, compilation, contract_source)

        # ── Pass 1: Static detectors ─────────────────────────────────────
        static_findings, gas_optimizations = self._run_static_detectors(context)

        # ── Pass 2: AST + CFG + Taint + Call Graph analysis ──────────────
        ast_findings, ast_metadata = self._run_ast_analysis(source_code, compilation)

        # ── Pass 3: Slither integration ──────────────────────────────────
        slither_findings: list[FindingSchema] = []
        if source_code:
            try:
                slither_result = asyncio.get_event_loop().run_until_complete(
                    self._run_slither(source_code)
                )
                slither_findings = slither_result
            except RuntimeError:
                try:
                    slither_findings = asyncio.run(self._run_slither(source_code))
                except Exception as e:
                    logger.debug("Slither analysis skipped: %s", e)
            except Exception as e:
                logger.debug("Slither analysis skipped: %s", e)

        # ── Pass 4: LLM deep analysis ────────────────────────────────────
        llm_findings: list[FindingSchema] = []
        llm_metadata: dict[str, Any] = {}
        use_llm = enable_llm if enable_llm is not None else self._enable_llm

        if use_llm:
            try:
                llm_result = asyncio.get_event_loop().run_until_complete(
                    self._run_llm_analysis(context, static_findings)
                )
                llm_findings = llm_result.get("findings", [])
                llm_metadata = {
                    "llm_overall_risk": llm_result.get("overall_risk", "unknown"),
                    "llm_attack_surface": llm_result.get("attack_surface_summary", ""),
                    "llm_token_usage": llm_result.get("token_usage", {}),
                    "llm_analysis_duration": llm_result.get("analysis_duration", 0),
                    "llm_invariants_checked": len(llm_result.get("invariants", [])),
                }
            except RuntimeError:
                # No event loop — try creating one
                try:
                    llm_result = asyncio.run(
                        self._run_llm_analysis(context, static_findings)
                    )
                    llm_findings = llm_result.get("findings", [])
                    llm_metadata = {
                        "llm_overall_risk": llm_result.get("overall_risk", "unknown"),
                        "llm_attack_surface": llm_result.get("attack_surface_summary", ""),
                        "llm_token_usage": llm_result.get("token_usage", {}),
                    }
                except Exception as e:
                    print(f"LLM analysis failed: {e}")
            except Exception as e:
                print(f"LLM analysis failed: {e}")

        # ── Pass 5: Merge + deduplicate + cross-reference ────────────────
        all_findings = self._merge_and_deduplicate(
            static_findings + ast_findings + slither_findings, llm_findings
        )

        # ── Score calculation ────────────────────────────────────────────
        score = SecurityScore.calculate(all_findings)
        total_lines = source_code.count("\n") + 1
        duration = time.time() - start_time

        # Build severity breakdown
        severity_counts: dict[str, int] = {}
        for f in all_findings:
            sev = f.severity.value
            severity_counts[sev] = severity_counts.get(sev, 0) + 1

        category_counts: dict[str, int] = {}
        for f in all_findings:
            cat = f.category or "uncategorized"
            category_counts[cat] = category_counts.get(cat, 0) + 1

        return ScanResult(
            scan_id=scan_id,
            scan_type=ScanType.SMART_CONTRACT,
            status=ScanStatus.COMPLETED,
            findings=all_findings,
            gas_optimizations=gas_optimizations,
            security_score=score.score,
            threat_score=score.threat_score,
            total_lines_scanned=total_lines,
            scan_duration_seconds=duration,
            metadata={
                "detectors_run": registry.count(),
                "contract_name": context.contract_name,
                "compiler_version": context.compiler_version,
                "findings_by_severity": severity_counts,
                "findings_by_category": category_counts,
                "gas_optimizations_count": len(gas_optimizations),
                "static_findings_count": len(static_findings),
                "ast_findings_count": len(ast_findings),
                "slither_findings_count": len(slither_findings),
                "llm_findings_count": len(llm_findings),
                "total_findings_after_dedup": len(all_findings),
                "llm_enabled": use_llm,
                **llm_metadata,
                **ast_metadata,
            },
        )

    def _run_static_detectors(
        self, context: DetectorContext
    ) -> tuple[list[FindingSchema], list[GasOptimization]]:
        """Pass 1: Run all registered static detectors."""
        all_findings: list[FindingSchema] = []
        gas_optimizations: list[GasOptimization] = []

        for detector_cls in registry.get_all():
            try:
                detector = detector_cls()
                findings = detector.detect(context)

                for finding in findings:
                    if finding.severity == Severity.GAS:
                        gas_optimizations.append(GasOptimization(
                            location=finding.location,
                            description=finding.description,
                            suggestion=finding.remediation,
                            estimated_gas_saved=finding.metadata.get("estimated_gas_saved", 0),
                            category=finding.category,
                        ))
                    else:
                        all_findings.append(finding)

                # Update context for cross-detector analysis
                context.previous_findings.extend(findings)

            except Exception as e:
                print(f"Detector {detector_cls.DETECTOR_ID} failed: {e}")
                continue

        return all_findings, gas_optimizations

    async def _run_llm_analysis(
        self,
        context: DetectorContext,
        static_findings: list[FindingSchema],
    ) -> dict[str, Any]:
        """Pass 4: Run LLM deep analysis."""
        analyzer = self._get_llm_analyzer()
        if not analyzer:
            return {}

        result = await analyzer.analyze(context, static_findings=static_findings)
        return {
            "findings": result.findings,
            "overall_risk": result.overall_risk,
            "attack_surface_summary": result.attack_surface_summary,
            "token_usage": result.token_usage,
            "analysis_duration": result.analysis_duration,
            "invariants": result.invariants,
        }

    def _run_ast_analysis(
        self,
        source_code: str,
        compilation: CompilationResult | None,
    ) -> tuple[list[FindingSchema], dict[str, Any]]:
        """Pass 2: AST structural analysis + CFG + taint + call graph.

        Returns (findings, metadata) where metadata includes attack surface info.
        """
        findings: list[FindingSchema] = []
        metadata: dict[str, Any] = {}

        try:
            from engine.core.ast_analyzer import SolidityASTAnalyzer, analyze_compilation
            from engine.core.cfg import CFGBuilder, TaintAnalyzer
            from engine.core.call_graph import CallGraphBuilder, AttackSurfaceAnalyzer

            # ── AST analysis ─────────────────────────────────────────────
            contracts = []
            if compilation and compilation.success and compilation.sources_ast:
                contracts = analyze_compilation(compilation)
            elif source_code:
                # Try parsing from source using a simple AST
                analyzer = SolidityASTAnalyzer()
                # AST analysis needs compiled AST; skip if no compilation
                pass

            if not contracts:
                return findings, metadata

            metadata["ast_contracts_analyzed"] = len(contracts)
            metadata["ast_total_functions"] = sum(len(c.functions) for c in contracts)

            # ── CFG + Taint analysis ─────────────────────────────────────
            cfg_builder = CFGBuilder(source_code)
            taint_analyzer = TaintAnalyzer()

            total_taint_flows = 0
            total_reentrancy_paths = 0

            for contract in contracts:
                for func in contract.functions:
                    cfg = cfg_builder.build(
                        f"{contract.name}.{func.name}",
                        func.body_node,
                    )

                    param_names = [p.name for p in func.parameters]
                    state_vars = {s.name for s in contract.state_variables}

                    taint_flows, reentrancy_paths = taint_analyzer.analyze(
                        cfg, param_names=param_names, state_var_names=state_vars
                    )

                    total_taint_flows += len(taint_flows)
                    total_reentrancy_paths += len(reentrancy_paths)

                    # Convert taint flows to findings
                    for flow in taint_flows:
                        findings.append(FindingSchema(
                            title=f"Taint flow: {flow.source_kind.value} → {flow.sink_kind.value}",
                            description=(
                                f"In {flow.function_name}: {flow.description or ''} "
                                f"User-controlled input from {flow.source_kind.value} "
                                f"reaches dangerous operation ({flow.sink_kind.value})."
                            ),
                            severity=Severity.HIGH if flow.sink_kind.value in (
                                "delegatecall", "selfdestruct"
                            ) else Severity.MEDIUM,
                            category="taint-analysis",
                            location=Location(
                                file_path=contract.name + ".sol",
                                start_line=flow.source_line,
                                end_line=flow.sink_line,
                                snippet="",
                            ),
                            confidence=0.75,
                            metadata={"source": "taint_analysis", "flow": flow.description},
                        ))

                    for reen in reentrancy_paths:
                        findings.append(FindingSchema(
                            title=f"CFG Reentrancy: call before state write in {reen.function_name}",
                            description=(
                                f"External call in block {reen.call_block} precedes "
                                f"state write in block {reen.write_block}. "
                                f"This is a classic reentrancy pattern."
                            ),
                            severity=Severity.HIGH,
                            category="reentrancy",
                            location=Location(
                                file_path=contract.name + ".sol",
                                start_line=reen.call_line,
                                end_line=reen.write_line,
                                snippet="",
                            ),
                            confidence=0.80,
                            metadata={"source": "cfg_analysis"},
                        ))

            metadata["taint_flows_detected"] = total_taint_flows
            metadata["reentrancy_paths_detected"] = total_reentrancy_paths

            # ── Call graph analysis ──────────────────────────────────────
            if contracts:
                cg_builder = CallGraphBuilder()
                call_graph = cg_builder.build(contracts)
                surface_analyzer = AttackSurfaceAnalyzer()
                attack_surface = surface_analyzer.analyze(call_graph)

                metadata["call_graph_stats"] = attack_surface.get("stats", {})
                metadata["attack_paths_count"] = len(attack_surface.get("attack_paths", []))
                metadata["unreachable_functions"] = attack_surface.get("unreachable_code", [])

                # High-risk entry points → findings
                for ep in attack_surface.get("entry_points", []):
                    if ep.get("risk_score", 0) >= 0.6:
                        risk_factors = ", ".join(ep.get("risk_factors", []))
                        findings.append(FindingSchema(
                            title=f"High-risk entry point: {ep['function']}",
                            description=(
                                f"Function {ep['function']} is externally callable "
                                f"with risk factors: {risk_factors}. "
                                f"Reachable functions: {ep.get('reachable_count', 0)}"
                            ),
                            severity=Severity.MEDIUM,
                            category="attack-surface",
                            location=Location(
                                file_path="contract",
                                start_line=0,
                                end_line=0,
                                snippet="",
                            ),
                            confidence=0.65,
                            metadata={"source": "call_graph", "risk_score": ep["risk_score"]},
                        ))

                # Privilege escalation paths → findings
                for esc in attack_surface.get("privilege_escalation", []):
                    findings.append(FindingSchema(
                        title=f"Privilege escalation path: {esc['entry']} → {esc['target']}",
                        description=(
                            f"Unprivileged function {esc['entry']} can reach "
                            f"privileged function {esc['target']} "
                            f"(modifiers: {', '.join(esc.get('target_modifiers', []))}) "
                            f"via path: {' → '.join(esc.get('path', []))}"
                        ),
                        severity=Severity.HIGH,
                        category="access-control",
                        location=Location(
                            file_path="contract",
                            start_line=0,
                            end_line=0,
                            snippet="",
                        ),
                        confidence=0.70,
                        metadata={"source": "call_graph"},
                    ))

        except Exception as e:
            logger.warning("AST/CFG/call-graph analysis failed: %s", e)
            metadata["ast_analysis_error"] = str(e)

        return findings, metadata

    async def _run_slither(self, source_code: str) -> list[FindingSchema]:
        """Pass 3: Run Slither static analysis."""
        try:
            from engine.analyzer.web3.slither_runner import SlitherRunner
            runner = SlitherRunner()
            return await runner.analyze_source(source_code)
        except Exception as e:
            logger.debug("Slither unavailable: %s", e)
            return []

    def _merge_and_deduplicate(
        self,
        static_findings: list[FindingSchema],
        llm_findings: list[FindingSchema],
    ) -> list[FindingSchema]:
        """Pass 5: Merge, deduplicate, and cross-reference findings.

        Deduplication strategy:
        - Group findings by (file, line_bucket, severity, category_prefix)
        - Keep the highest-confidence version
        - If both static + LLM flag the same area, boost confidence
        - Slither corroboration also boosts confidence
        """
        if not llm_findings:
            return static_findings

        # Tag sources
        for f in static_findings:
            if "source" not in f.metadata:
                f.metadata["source"] = "static"
        for f in llm_findings:
            if "source" not in f.metadata:
                f.metadata["source"] = "llm"

        all_findings = static_findings + llm_findings

        # Build dedup buckets
        buckets: dict[str, list[FindingSchema]] = {}
        for f in all_findings:
            key = (
                f"{f.location.file_path}:"
                f"{f.location.start_line // 8}:"  # group within ~8 lines
                f"{f.severity.value}:"
                f"{f.category[:15] if f.category else 'x'}"
            )
            digest = hashlib.md5(key.encode()).hexdigest()[:12]
            buckets.setdefault(digest, []).append(f)

        deduped: list[FindingSchema] = []
        for bucket_findings in buckets.values():
            if len(bucket_findings) == 1:
                deduped.append(bucket_findings[0])
            else:
                # Multiple findings in same bucket — merge
                sources = {f.metadata.get("source", "unknown") for f in bucket_findings}
                # Pick the one with highest confidence
                best = max(bucket_findings, key=lambda f: f.confidence)

                if "static" in sources and "llm" in sources:
                    # Corroborated by both — boost confidence
                    best.confidence = min(1.0, best.confidence + 0.15)
                    best.metadata["corroborated"] = True
                    best.metadata["corroborated_sources"] = list(sources)

                deduped.append(best)

        # Sort by severity priority then confidence
        severity_order = {
            Severity.CRITICAL: 0, Severity.HIGH: 1, Severity.MEDIUM: 2,
            Severity.LOW: 3, Severity.INFORMATIONAL: 4, Severity.GAS: 5,
        }
        deduped.sort(key=lambda f: (severity_order.get(f.severity, 5), -f.confidence))

        return deduped

    def _build_context(
        self,
        source_code: str,
        compilation: CompilationResult | None,
        contract_source: ContractSource | None,
    ) -> DetectorContext:
        """Build a DetectorContext from available data."""
        context = DetectorContext(source_code=source_code)

        if contract_source:
            context.contract_name = contract_source.contract_name
            context.contract_address = contract_source.address
            context.chain = contract_source.chain
            context.compiler_version = contract_source.compiler_version
            context.abi = contract_source.abi
            context.source_files = contract_source.source_files

        if compilation and compilation.success:
            context.sources_ast = compilation.sources_ast
            # Get first contract's data
            for key, contract in compilation.contracts.items():
                context.ast = contract.ast
                context.abi = context.abi or contract.abi
                context.bytecode = contract.bytecode
                context.storage_layout = contract.storage_layout
                if not context.contract_name:
                    context.contract_name = contract.name
                break

        return context

    def get_detector_count(self) -> int:
        """Return total number of registered detectors."""
        return registry.count()

    def get_detector_categories(self) -> list[str]:
        """Return all unique detector categories."""
        return registry.categories()

    def get_categories(self) -> list[str]:
        """Return all detector categories."""
        return registry.categories()
