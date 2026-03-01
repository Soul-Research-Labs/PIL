"""LLM-powered deep analysis — multi-pass AI vulnerability detection.

Goes beyond regex/pattern detectors with Claude/GPT-4o to find:
  - Business logic vulnerabilities
  - Cross-contract interaction flaws
  - Complex economic attack vectors
  - Subtle reentrancy & state corruption
  - DeFi composability exploits
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import time
from dataclasses import dataclass, field
from typing import Any

from engine.core.llm_client import LLMClient
from engine.core.types import (
    FindingSchema,
    FindingStatus,
    GasOptimization,
    Location,
    Severity,
)
from engine.analyzer.web3.base_detector import DetectorContext


# ── Prompt templates ─────────────────────────────────────────────────────────

_SUMMARIZE_SYSTEM = """\
You are an expert Solidity auditor. Produce a structured summary of the \
smart contract source code provided. Identify:
- Contract purpose and functionality
- Inheritance chain and library usage
- State variables and their visibility
- External/public function signatures with access control
- Token standard conformance (ERC-20/721/1155/4626)
- External protocol integrations (Uniswap, Aave, Chainlink, etc.)
- Upgrade mechanism (proxy pattern, UUPS, transparent, beacon)

Return JSON:
{
  "contract_name": "...",
  "purpose": "...",
  "standards": ["ERC-20", ...],
  "inheritance": ["Ownable", ...],
  "state_variables": [{"name": "...", "type": "...", "visibility": "..."}],
  "functions": [{"name": "...", "visibility": "...", "modifiers": [...], "state_mutability": "...", "has_external_call": true}],
  "integrations": ["Uniswap V3", ...],
  "upgrade_pattern": "none|UUPS|transparent|beacon|diamond",
  "key_observations": ["...", "..."]
}"""

_VULN_DEEP_SYSTEM = """\
You are a world-class smart contract security auditor performing a deep \
vulnerability analysis. You have already reviewed a contract summary and \
now must analyze the FULL source code for sophisticated vulnerabilities \
that regex-based detectors would miss.

Focus on:
1. Business logic flaws (incorrect accounting, edge cases, rounding errors)
2. Cross-function state inconsistencies
3. Flash-loan attack surfaces
4. Price manipulation vectors
5. Access control gaps (missing checks, privilege escalation)
6. Reentrancy beyond simple ETH transfers (cross-contract, read-only)
7. Integer overflow/underflow in complex math (even with Solidity 0.8+; unchecked blocks)
8. Subtle storage corruption (delegatecall, proxy patterns)
9. Denial of Service vectors (gas griefing, block stuffing, returnbomb)
10. Token handling errors (fee-on-transfer, rebasing, ERC-777 hooks)
11. MEV/sandwich attack opportunities
12. Governance manipulation vectors
13. Signature replay / EIP-712 issues
14. Timestamp dependence for critical logic
15. Composability risks with external protocols

For each vulnerability found, assign a confidence score (0.0-1.0) based on \
how certain you are that the issue is exploitable.

Return JSON:
{
  "findings": [
    {
      "title": "...",
      "description": "Detailed explanation of the vulnerability and attack scenario",
      "severity": "critical|high|medium|low|informational",
      "confidence": 0.85,
      "category": "business_logic|reentrancy|access_control|oracle|flash_loan|...",
      "file_path": "Contract.sol",
      "start_line": 42,
      "end_line": 55,
      "snippet": "vulnerable code...",
      "attack_scenario": "Step-by-step exploitation path",
      "remediation": "How to fix",
      "references": ["SWC-107", "..."]
    }
  ],
  "overall_risk": "critical|high|medium|low",
  "attack_surface_summary": "..."
}"""

_CROSS_CONTRACT_SYSTEM = """\
You are an expert in cross-contract interaction security. Analyze the \
following smart contract for vulnerabilities that arise from interactions \
with external contracts and protocols.

Focus specifically on:
1. Untrusted external call return values
2. Callback attacks (ERC-777, ERC-1155, flash loan callbacks)
3. Reentrancy through external protocol hooks
4. Composability risks (e.g., interacting with fee-on-transfer tokens)
5. Oracle manipulation through external AMM interactions
6. Proxy/implementation storage collisions
7. Cross-chain message validation
8. Reliance on external contract state that can change atomically

Return JSON:
{
  "cross_contract_findings": [
    {
      "title": "...",
      "description": "...",
      "severity": "critical|high|medium|low|informational",
      "confidence": 0.8,
      "category": "cross_contract",
      "interaction_type": "external_call|callback|proxy|oracle|bridge",
      "target_protocol": "Uniswap V3|Aave V3|...",
      "file_path": "...",
      "start_line": 0,
      "end_line": 0,
      "snippet": "...",
      "attack_scenario": "...",
      "remediation": "..."
    }
  ]
}"""

_ECONOMIC_SYSTEM = """\
You are a DeFi security researcher specializing in economic attacks. \
Analyze this smart contract for economic and game-theoretic vulnerabilities.

Focus on:
1. Flash loan attack vectors (can any state be manipulated in one tx?)
2. Arbitrage opportunities that drain protocol value
3. Sandwich attack surfaces (large swaps, liquidity additions)
4. Liquidation manipulation
5. Interest rate manipulation
6. Governance token vote buying / flash-loan governance
7. Front-running sensitive operations
8. Value extraction via MEV
9. Rounding errors that compound over time
10. First-depositor / inflation attacks on vaults (ERC-4626)

Return JSON:
{
  "economic_findings": [
    {
      "title": "...",
      "description": "...",
      "severity": "critical|high|medium|low|informational",
      "confidence": 0.7,
      "category": "economic",
      "attack_type": "flash_loan|sandwich|governance|liquidation|arbitrage|inflation",
      "estimated_impact": "high|medium|low",
      "file_path": "...",
      "start_line": 0,
      "end_line": 0,
      "snippet": "...",
      "attack_scenario": "...",
      "remediation": "..."
    }
  ]
}"""

_INVARIANT_SYSTEM = """\
You are a formal verification expert. Analyze this smart contract and \
identify the key invariants, then determine which ones can be violated.

Tasks:
1. List all critical state invariants (e.g., "totalSupply == sum of all balances")
2. For each invariant, determine if the contract enforces it correctly
3. Identify any code paths that could violate an invariant
4. Flag invariants that are only softly enforced (via requires that could be bypassed)

Return JSON:
{
  "invariants": [
    {
      "description": "totalSupply == sum(balances[addr] for all addr)",
      "enforced": true,
      "violation_paths": [],
      "confidence": 0.95
    }
  ],
  "violated_invariants": [
    {
      "invariant": "...",
      "violation_description": "...",
      "severity": "critical|high|medium|low",
      "confidence": 0.8,
      "file_path": "...",
      "start_line": 0,
      "end_line": 0,
      "snippet": "...",
      "remediation": "..."
    }
  ]
}"""


# ── Data types ───────────────────────────────────────────────────────────────

@dataclass
class LLMAnalysisResult:
    """Aggregated result from all LLM analysis passes."""
    findings: list[FindingSchema] = field(default_factory=list)
    gas_optimizations: list[GasOptimization] = field(default_factory=list)
    contract_summary: dict[str, Any] = field(default_factory=dict)
    invariants: list[dict[str, Any]] = field(default_factory=list)
    overall_risk: str = "unknown"
    attack_surface_summary: str = ""
    analysis_duration: float = 0.0
    token_usage: dict[str, int] = field(default_factory=dict)


SEVERITY_MAP = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "low": Severity.LOW,
    "informational": Severity.INFORMATIONAL,
    "gas": Severity.GAS,
}


# ── LLM Deep Analyzer ───────────────────────────────────────────────────────

class LLMDeepAnalyzer:
    """Multi-pass LLM vulnerability analysis for smart contracts.

    Analysis passes (run concurrently where possible):
      Pass 0 — Summarize: Understand contract purpose, structure, integrations
      Pass 1 — Deep Vuln Scan: Business logic, access control, state bugs
      Pass 2 — Cross-Contract: External interaction & composability risks
      Pass 3 — Economic Attacks: Flash loans, MEV, governance, oracle exploits
      Pass 4 — Invariant Analysis: State invariant identification & violation
    """

    def __init__(self) -> None:
        self._client = LLMClient()

    async def analyze(
        self,
        context: DetectorContext,
        static_findings: list[FindingSchema] | None = None,
        skip_passes: set[int] | None = None,
    ) -> LLMAnalysisResult:
        """Run all LLM analysis passes and return aggregated results.

        Args:
            context: DetectorContext with source code, AST, ABI
            static_findings: Findings from static detectors (for context)
            skip_passes: Set of pass indices to skip (0-4)
        """
        start = time.time()
        skip = skip_passes or set()
        source = context.source_code

        # Truncate very large contracts to stay within context window
        if len(source) > 100_000:
            source = source[:100_000] + "\n// ... truncated for analysis ..."

        contract_name = context.contract_name or "Contract.sol"

        # ── Pass 0: Summarize ────────────────────────────────────────────
        summary: dict[str, Any] = {}
        if 0 not in skip:
            summary = await self._summarize(source)

        summary_context = json.dumps(summary, indent=2) if summary else "N/A"

        # Build context block with static findings (if any)
        static_ctx = ""
        if static_findings:
            static_ctx = f"\n\n## Existing Static Analysis Findings ({len(static_findings)} total)\n"
            for f in static_findings[:20]:  # Cap at 20 to save tokens
                static_ctx += (
                    f"- [{f.severity.value.upper()}] {f.title} "
                    f"(line {f.location.start_line}): {f.description[:120]}\n"
                )

        user_prompt = (
            f"## Contract Summary\n```json\n{summary_context}\n```\n\n"
            f"## Full Source Code\n```solidity\n{source}\n```"
            f"{static_ctx}"
        )

        # ── Passes 1-4: Run concurrently ────────────────────────────────
        tasks: dict[int, Any] = {}
        if 1 not in skip:
            tasks[1] = self._client.analyze(
                system_prompt=_VULN_DEEP_SYSTEM,
                user_prompt=user_prompt,
                max_tokens=8192,
            )
        if 2 not in skip:
            tasks[2] = self._client.analyze(
                system_prompt=_CROSS_CONTRACT_SYSTEM,
                user_prompt=user_prompt,
                max_tokens=6144,
            )
        if 3 not in skip:
            tasks[3] = self._client.analyze(
                system_prompt=_ECONOMIC_SYSTEM,
                user_prompt=user_prompt,
                max_tokens=6144,
            )
        if 4 not in skip:
            tasks[4] = self._client.analyze(
                system_prompt=_INVARIANT_SYSTEM,
                user_prompt=user_prompt,
                max_tokens=6144,
            )

        # Execute all in parallel
        keys = list(tasks.keys())
        results_raw = await asyncio.gather(
            *tasks.values(), return_exceptions=True,
        )
        results: dict[int, dict] = {}
        for k, r in zip(keys, results_raw):
            if isinstance(r, Exception):
                print(f"LLM pass {k} failed: {r}")
                results[k] = {}
            else:
                results[k] = r

        # ── Aggregate findings ───────────────────────────────────────────
        all_findings: list[FindingSchema] = []

        # Pass 1 — Deep vuln findings
        if 1 in results:
            all_findings.extend(
                self._parse_findings(results[1].get("findings", []), contract_name, "llm_deep")
            )

        # Pass 2 — Cross-contract findings
        if 2 in results:
            all_findings.extend(
                self._parse_findings(
                    results[2].get("cross_contract_findings", []), contract_name, "llm_cross_contract"
                )
            )

        # Pass 3 — Economic findings
        if 3 in results:
            all_findings.extend(
                self._parse_findings(
                    results[3].get("economic_findings", []), contract_name, "llm_economic"
                )
            )

        # Pass 4 — Invariant violations become findings
        if 4 in results:
            all_findings.extend(
                self._parse_invariant_violations(
                    results[4].get("violated_invariants", []), contract_name
                )
            )

        # Deduplicate findings with similar descriptions
        all_findings = self._deduplicate(all_findings)

        # Cross-reference with static findings to boost or lower confidence
        if static_findings:
            all_findings = self._cross_reference(all_findings, static_findings)

        duration = time.time() - start

        return LLMAnalysisResult(
            findings=all_findings,
            contract_summary=summary,
            invariants=results.get(4, {}).get("invariants", []),
            overall_risk=results.get(1, {}).get("overall_risk", "unknown"),
            attack_surface_summary=results.get(1, {}).get("attack_surface_summary", ""),
            analysis_duration=duration,
            token_usage=self._client.token_usage,
        )

    async def quick_triage(
        self,
        source_code: str,
        contract_name: str = "Contract.sol",
    ) -> list[FindingSchema]:
        """Fast single-pass triage using the fast model tier.

        Good for quick scans where full multi-pass is too costly.
        """
        if len(source_code) > 60_000:
            source_code = source_code[:60_000] + "\n// ... truncated ..."

        result = await self._client.analyze(
            system_prompt=_VULN_DEEP_SYSTEM,
            user_prompt=f"## Source Code\n```solidity\n{source_code}\n```",
            max_tokens=4096,
            fast=True,
        )
        return self._parse_findings(result.get("findings", []), contract_name, "llm_triage")

    # ── Internal helpers ─────────────────────────────────────────────────

    async def _summarize(self, source: str) -> dict[str, Any]:
        """Pass 0: Contract summarization."""
        result = await self._client.analyze(
            system_prompt=_SUMMARIZE_SYSTEM,
            user_prompt=f"```solidity\n{source}\n```",
            max_tokens=4096,
            fast=True,  # Summarization can use the fast tier
        )
        return result

    def _parse_findings(
        self,
        raw_findings: list[dict],
        contract_name: str,
        source_tag: str,
    ) -> list[FindingSchema]:
        """Parse LLM output into FindingSchema objects."""
        findings: list[FindingSchema] = []
        for item in raw_findings:
            if not isinstance(item, dict):
                continue
            try:
                sev_str = item.get("severity", "medium").lower()
                severity = SEVERITY_MAP.get(sev_str, Severity.MEDIUM)
                confidence = float(item.get("confidence", 0.6))
                confidence = max(0.0, min(1.0, confidence))

                finding = FindingSchema(
                    title=item.get("title", "LLM-detected issue"),
                    description=item.get("description", ""),
                    severity=severity,
                    status=FindingStatus.DETECTED,
                    confidence=confidence,
                    category=item.get("category", "llm_analysis"),
                    location=Location(
                        file_path=item.get("file_path", contract_name),
                        start_line=int(item.get("start_line", 0)),
                        end_line=int(item.get("end_line", 0)),
                        snippet=item.get("snippet", ""),
                    ),
                    remediation=item.get("remediation", ""),
                    metadata={
                        "source": source_tag,
                        "attack_scenario": item.get("attack_scenario", ""),
                        "references": item.get("references", []),
                        "interaction_type": item.get("interaction_type", ""),
                        "target_protocol": item.get("target_protocol", ""),
                        "attack_type": item.get("attack_type", ""),
                        "estimated_impact": item.get("estimated_impact", ""),
                    },
                )
                findings.append(finding)
            except Exception as e:
                print(f"Failed to parse LLM finding: {e}")
                continue
        return findings

    def _parse_invariant_violations(
        self,
        violations: list[dict],
        contract_name: str,
    ) -> list[FindingSchema]:
        """Convert invariant violations to findings."""
        findings: list[FindingSchema] = []
        for v in violations:
            if not isinstance(v, dict):
                continue
            try:
                sev_str = v.get("severity", "high").lower()
                severity = SEVERITY_MAP.get(sev_str, Severity.HIGH)

                finding = FindingSchema(
                    title=f"Invariant Violation: {v.get('invariant', 'Unknown')[:80]}",
                    description=v.get("violation_description", ""),
                    severity=severity,
                    status=FindingStatus.DETECTED,
                    confidence=float(v.get("confidence", 0.6)),
                    category="invariant_violation",
                    location=Location(
                        file_path=v.get("file_path", contract_name),
                        start_line=int(v.get("start_line", 0)),
                        end_line=int(v.get("end_line", 0)),
                        snippet=v.get("snippet", ""),
                    ),
                    remediation=v.get("remediation", ""),
                    metadata={
                        "source": "llm_invariant",
                        "invariant": v.get("invariant", ""),
                    },
                )
                findings.append(finding)
            except Exception:
                continue
        return findings

    def _deduplicate(self, findings: list[FindingSchema]) -> list[FindingSchema]:
        """Remove near-duplicate findings based on location and title similarity."""
        if not findings:
            return findings

        seen: dict[str, FindingSchema] = {}
        for f in findings:
            # Hash key: severity + approximate location + title prefix
            key = (
                f"{f.severity.value}:"
                f"{f.location.file_path}:"
                f"{f.location.start_line // 5}:"  # group nearby lines
                f"{f.title[:40].lower()}"
            )
            digest = hashlib.md5(key.encode()).hexdigest()

            if digest in seen:
                # Keep the one with higher confidence
                if f.confidence > seen[digest].confidence:
                    seen[digest] = f
            else:
                seen[digest] = f

        return list(seen.values())

    def _cross_reference(
        self,
        llm_findings: list[FindingSchema],
        static_findings: list[FindingSchema],
    ) -> list[FindingSchema]:
        """Cross-reference LLM findings with static findings.

        If both static + LLM agree on a location, boost confidence.
        If LLM found something static missed, slightly lower confidence.
        """
        # Build a set of (file, line_bucket) from static findings
        static_locations: set[tuple[str, int]] = set()
        for sf in static_findings:
            bucket = sf.location.start_line // 10
            static_locations.add((sf.location.file_path, bucket))

        for f in llm_findings:
            bucket = f.location.start_line // 10
            key = (f.location.file_path, bucket)
            if key in static_locations:
                # Corroborated — boost confidence
                f.confidence = min(1.0, f.confidence + 0.15)
                f.metadata["corroborated_by_static"] = True
            else:
                # Novel LLM-only finding — reduce confidence slightly
                f.confidence = max(0.1, f.confidence - 0.05)
                f.metadata["novel_llm_finding"] = True

        return llm_findings
