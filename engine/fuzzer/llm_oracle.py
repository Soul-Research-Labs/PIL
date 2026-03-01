"""LLM-Guided Mutation Oracle for Soul Protocol Fuzzing.

Uses Large Language Models to intelligently guide the fuzzing strategy:
  1. Analyze source code to identify likely vulnerability patterns
  2. Generate targeted mutation strategies based on code semantics
  3. Explain violations found and suggest exploit chains
  4. Predict which mutations are most likely to find bugs
  5. Generate sophisticated attack hypotheses (flash loans, reentrancy, etc.)
  6. Prioritize unexplored code paths based on semantic understanding

Supported LLMs:
  - Anthropic Claude (primary)
  - OpenAI GPT-4o (fallback)
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

logger = logging.getLogger(__name__)


# ── Configuration ────────────────────────────────────────────────────────────


class OracleMode(Enum):
    """LLM oracle operating modes."""
    STRATEGY = "strategy"        # Generate mutation strategies
    ANALYSIS = "analysis"        # Analyze code for vulnerabilities
    EXPLAIN = "explain"          # Explain violations
    HYPOTHESIS = "hypothesis"    # Generate attack hypotheses
    PRIORITIZE = "prioritize"    # Prioritize targets
    FULL = "full"                # All of the above


@dataclass
class OracleConfig:
    """Configuration for the LLM oracle."""
    mode: OracleMode = OracleMode.FULL
    # LLM settings
    anthropic_model: str = "claude-sonnet-4-20250514"
    openai_model: str = "gpt-4o"
    max_tokens: int = 4096
    temperature: float = 0.3
    # Rate limiting
    max_calls_per_minute: int = 20
    max_calls_per_campaign: int = 50
    # Caching
    cache_responses: bool = True
    cache_ttl_seconds: int = 3600
    # Budget
    max_input_tokens: int = 8000
    # Fallback
    fallback_to_heuristic: bool = True


# ── Oracle Results ───────────────────────────────────────────────────────────


@dataclass
class MutationStrategy:
    """LLM-suggested mutation strategy."""
    target_function: str
    mutation_types: list[str]
    rationale: str
    priority: float = 1.0
    input_template: dict[str, Any] = field(default_factory=dict)
    attack_class: str = ""  # e.g., "reentrancy", "flash_loan", "oracle_manipulation"
    confidence: float = 0.0


@dataclass
class AttackHypothesis:
    """LLM-generated attack hypothesis."""
    title: str
    description: str
    attack_class: str
    target_functions: list[str]
    prerequisites: list[str]
    steps: list[str]
    expected_impact: str
    mutation_sequence: list[str]
    confidence: float = 0.0
    severity: str = "medium"


@dataclass
class ViolationExplanation:
    """LLM explanation of a found violation."""
    invariant_id: str
    explanation: str
    root_cause: str
    exploitability: str
    suggested_fix: str
    severity_assessment: str
    related_bugs: list[str] = field(default_factory=list)
    exploit_scenario: str = ""


@dataclass
class CodeInsight:
    """LLM insight about the contract code."""
    category: str  # "vulnerability", "pattern", "optimization", "risk"
    title: str
    description: str
    affected_functions: list[str]
    severity: str
    confidence: float = 0.0
    suggested_mutations: list[str] = field(default_factory=list)


@dataclass
class OracleResult:
    """Complete result from the LLM oracle."""
    strategies: list[MutationStrategy] = field(default_factory=list)
    hypotheses: list[AttackHypothesis] = field(default_factory=list)
    explanations: list[ViolationExplanation] = field(default_factory=list)
    insights: list[CodeInsight] = field(default_factory=list)
    priority_targets: list[dict[str, Any]] = field(default_factory=list)
    total_llm_calls: int = 0
    total_tokens_used: int = 0
    total_time_ms: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "strategies": [
                {
                    "function": s.target_function,
                    "mutations": s.mutation_types,
                    "rationale": s.rationale,
                    "priority": s.priority,
                    "attack_class": s.attack_class,
                    "confidence": s.confidence,
                }
                for s in self.strategies
            ],
            "hypotheses": [
                {
                    "title": h.title,
                    "attack_class": h.attack_class,
                    "targets": h.target_functions,
                    "steps": h.steps,
                    "confidence": h.confidence,
                    "severity": h.severity,
                }
                for h in self.hypotheses
            ],
            "insights": [
                {
                    "category": i.category,
                    "title": i.title,
                    "severity": i.severity,
                    "affected": i.affected_functions,
                }
                for i in self.insights
            ],
            "llm_calls": self.total_llm_calls,
            "tokens_used": self.total_tokens_used,
            "time_ms": round(self.total_time_ms, 1),
        }


# ── LLM Oracle Engine ───────────────────────────────────────────────────────


class LLMOracle:
    """LLM-guided mutation oracle for intelligent fuzzing strategy.

    Uses Claude/GPT-4o to:
    1. Analyze contract source for vulnerability patterns
    2. Generate targeted mutation strategies
    3. Create attack hypotheses
    4. Explain found violations
    5. Prioritize fuzz targets

    The oracle acts as an advisor — its suggestions are fed back into
    the mutation engine to bias mutation selection towards high-value
    areas identified by the LLM.
    """

    def __init__(self, config: OracleConfig | None = None) -> None:
        self.config = config or OracleConfig()
        self._anthropic_client: Any = None
        self._openai_client: Any = None
        self._cache: dict[str, Any] = {}
        self._call_count = 0
        self._call_timestamps: list[float] = []

    async def _get_anthropic_client(self) -> Any:
        """Get or create Anthropic client."""
        if self._anthropic_client is None:
            try:
                from anthropic import AsyncAnthropic
                self._anthropic_client = AsyncAnthropic()
            except ImportError:
                logger.warning("anthropic package not installed")
                return None
        return self._anthropic_client

    async def _get_openai_client(self) -> Any:
        """Get or create OpenAI client."""
        if self._openai_client is None:
            try:
                from openai import AsyncOpenAI
                self._openai_client = AsyncOpenAI()
            except ImportError:
                logger.warning("openai package not installed")
                return None
        return self._openai_client

    async def analyze_contract(
        self,
        source_code: str,
        contract_name: str,
        known_findings: list[dict[str, Any]] | None = None,
        coverage_info: dict[str, Any] | None = None,
    ) -> OracleResult:
        """Full LLM analysis of a contract for fuzzing guidance.

        Args:
            source_code: Solidity source code
            contract_name: Contract name
            known_findings: Findings already discovered by static analysis
            coverage_info: Current coverage information

        Returns:
            OracleResult with strategies, hypotheses, and insights
        """
        start = time.time()
        result = OracleResult()

        # Phase 1: Code analysis for vulnerability patterns
        if self.config.mode in (OracleMode.ANALYSIS, OracleMode.FULL):
            insights = await self._analyze_code(source_code, contract_name)
            result.insights = insights

        # Phase 2: Generate mutation strategies
        if self.config.mode in (OracleMode.STRATEGY, OracleMode.FULL):
            strategies = await self._generate_strategies(
                source_code, contract_name, known_findings, coverage_info,
            )
            result.strategies = strategies

        # Phase 3: Generate attack hypotheses
        if self.config.mode in (OracleMode.HYPOTHESIS, OracleMode.FULL):
            hypotheses = await self._generate_hypotheses(
                source_code, contract_name, known_findings,
            )
            result.hypotheses = hypotheses

        # Phase 4: Prioritize targets
        if self.config.mode in (OracleMode.PRIORITIZE, OracleMode.FULL):
            priorities = await self._prioritize_targets(
                source_code, contract_name, coverage_info,
            )
            result.priority_targets = priorities

        result.total_llm_calls = self._call_count
        result.total_time_ms = (time.time() - start) * 1000
        return result

    async def explain_violations(
        self,
        source_code: str,
        violations: list[dict[str, Any]],
    ) -> list[ViolationExplanation]:
        """Get LLM explanations for discovered violations."""
        if not violations:
            return []

        explanations: list[ViolationExplanation] = []

        # Batch violations for efficiency
        batch_size = 5
        for i in range(0, len(violations), batch_size):
            batch = violations[i:i + batch_size]
            batch_explanations = await self._explain_batch(source_code, batch)
            explanations.extend(batch_explanations)

        return explanations

    async def suggest_next_mutations(
        self,
        source_code: str,
        coverage_info: dict[str, Any],
        recent_mutations: list[str],
        recent_results: list[dict[str, Any]],
    ) -> list[MutationStrategy]:
        """Suggest next mutations based on current fuzzing state.

        This is the online oracle — called periodically during fuzzing
        to adapt the strategy based on what's been learned.
        """
        cache_key = hashlib.md5(
            f"next:{str(coverage_info)}:{str(recent_mutations[-10:])}".encode()
        ).hexdigest()

        if cache_key in self._cache:
            return self._cache[cache_key]

        prompt = self._build_next_mutations_prompt(
            source_code, coverage_info, recent_mutations, recent_results,
        )

        response = await self._call_llm(prompt, max_tokens=2048)
        strategies = self._parse_strategies(response)

        if self.config.cache_responses:
            self._cache[cache_key] = strategies

        return strategies

    # ── Private: LLM Calls ───────────────────────────────────────────────────

    async def _call_llm(self, prompt: str, max_tokens: int = 4096) -> str:
        """Call the LLM with rate limiting and fallback."""
        # Rate limiting
        if not self._check_rate_limit():
            if self.config.fallback_to_heuristic:
                return self._heuristic_fallback(prompt)
            return ""

        self._call_count += 1
        self._call_timestamps.append(time.time())

        # Try Anthropic first
        anthropic = await self._get_anthropic_client()
        if anthropic:
            try:
                response = await anthropic.messages.create(
                    model=self.config.anthropic_model,
                    max_tokens=max_tokens,
                    temperature=self.config.temperature,
                    system=(
                        "You are an expert smart contract security auditor and fuzzing specialist. "
                        "You analyze Solidity code for vulnerabilities and generate targeted "
                        "testing strategies for a mutation-feedback fuzzer targeting Soul Protocol "
                        "(a ZK-proof privacy interoperability layer). "
                        "Always respond in structured JSON format."
                    ),
                    messages=[{"role": "user", "content": prompt}],
                )
                return response.content[0].text
            except Exception as e:
                logger.warning("Anthropic call failed: %s", e)

        # Fallback to OpenAI
        openai = await self._get_openai_client()
        if openai:
            try:
                response = await openai.chat.completions.create(
                    model=self.config.openai_model,
                    max_tokens=max_tokens,
                    temperature=self.config.temperature,
                    messages=[
                        {
                            "role": "system",
                            "content": (
                                "You are an expert smart contract security auditor. "
                                "Analyze Solidity code and generate fuzzing strategies. "
                                "Respond in structured JSON."
                            ),
                        },
                        {"role": "user", "content": prompt},
                    ],
                )
                return response.choices[0].message.content or ""
            except Exception as e:
                logger.warning("OpenAI call failed: %s", e)

        # Final fallback
        if self.config.fallback_to_heuristic:
            return self._heuristic_fallback(prompt)
        return ""

    def _check_rate_limit(self) -> bool:
        """Check if we're within rate limits."""
        now = time.time()

        # Check per-campaign limit
        if self._call_count >= self.config.max_calls_per_campaign:
            return False

        # Check per-minute limit
        recent = [t for t in self._call_timestamps if now - t < 60]
        self._call_timestamps = recent
        return len(recent) < self.config.max_calls_per_minute

    # ── Private: Prompts ─────────────────────────────────────────────────────

    async def _analyze_code(
        self,
        source_code: str,
        contract_name: str,
    ) -> list[CodeInsight]:
        """Analyze code for vulnerability patterns."""
        # Truncate source to fit token limit
        truncated = source_code[:self.config.max_input_tokens * 3]

        prompt = f"""Analyze this Soul Protocol Solidity contract for security vulnerabilities.

Contract: {contract_name}
Source:
```solidity
{truncated}
```

Identify:
1. ZK proof verification weaknesses
2. Nullifier management issues
3. Bridge/cross-chain vulnerabilities
4. Access control gaps
5. Economic exploits (flash loans, sandwich, etc.)
6. State consistency issues
7. Reentrancy vectors
8. Integer overflow/underflow risks

Respond with a JSON array of insights:
```json
[
  {{
    "category": "vulnerability|pattern|risk",
    "title": "Short title",
    "description": "Detailed description",
    "affected_functions": ["function1", "function2"],
    "severity": "critical|high|medium|low",
    "confidence": 0.0-1.0,
    "suggested_mutations": ["mutation_type1", "mutation_type2"]
  }}
]
```"""

        response = await self._call_llm(prompt, max_tokens=3000)
        return self._parse_insights(response)

    async def _generate_strategies(
        self,
        source_code: str,
        contract_name: str,
        findings: list[dict[str, Any]] | None,
        coverage: dict[str, Any] | None,
    ) -> list[MutationStrategy]:
        """Generate targeted mutation strategies."""
        truncated = source_code[:self.config.max_input_tokens * 3]

        findings_str = ""
        if findings:
            findings_str = "\n".join(
                f"- [{f.get('severity', 'MEDIUM')}] {f.get('title', '')}"
                for f in findings[:10]
            )

        coverage_str = ""
        if coverage:
            coverage_str = f"Line coverage: {coverage.get('line', 0)*100:.1f}%, Branch coverage: {coverage.get('branch', 0)*100:.1f}%"

        prompt = f"""Generate targeted mutation strategies for fuzzing this Soul Protocol contract.

Contract: {contract_name}
{f"Known findings:{chr(10)}{findings_str}" if findings_str else "No findings yet."}
{f"Coverage: {coverage_str}" if coverage_str else "No coverage data yet."}

Source:
```solidity
{truncated}
```

For each critical function, suggest the most effective mutations to test.
Focus on Soul Protocol-specific attacks: ZK proof manipulation, nullifier replay,
cross-chain bridge exploits, privacy leaks, and economic attacks.

Respond with JSON array:
```json
[
  {{
    "target_function": "functionName",
    "mutation_types": ["corrupt_proof", "replay_nullifier"],
    "rationale": "Why these mutations target this function",
    "priority": 1.0,
    "attack_class": "zk_proof_bypass",
    "confidence": 0.8,
    "input_template": {{"param1": "suggested_value"}}
  }}
]
```"""

        response = await self._call_llm(prompt, max_tokens=3000)
        return self._parse_strategies(response)

    async def _generate_hypotheses(
        self,
        source_code: str,
        contract_name: str,
        findings: list[dict[str, Any]] | None,
    ) -> list[AttackHypothesis]:
        """Generate attack hypotheses."""
        truncated = source_code[:self.config.max_input_tokens * 3]

        prompt = f"""Generate attack hypotheses for this Soul Protocol contract.

Contract: {contract_name}
Source:
```solidity
{truncated}
```

Generate sophisticated multi-step attack scenarios including:
1. Flash loan attacks combined with ZK proof manipulation
2. Cross-chain reentrancy via bridge callbacks
3. Nullifier collision attacks across domains
4. Privacy-breaking correlation attacks
5. Economic manipulation via sandwich/frontrunning
6. Governance/access control bypass chains

For each hypothesis, provide a step-by-step exploitation plan.

Respond with JSON array:
```json
[
  {{
    "title": "Flash Loan + Proof Replay Attack",
    "description": "...",
    "attack_class": "flash_loan_composable",
    "target_functions": ["deposit", "withdraw"],
    "prerequisites": ["Large pool liquidity"],
    "steps": ["Step 1: ...", "Step 2: ..."],
    "expected_impact": "Fund drain via proof replay",
    "mutation_sequence": ["flash_loan_sequence", "replay_proof", "withdraw"],
    "confidence": 0.7,
    "severity": "critical"
  }}
]
```"""

        response = await self._call_llm(prompt, max_tokens=4096)
        return self._parse_hypotheses(response)

    async def _prioritize_targets(
        self,
        source_code: str,
        contract_name: str,
        coverage: dict[str, Any] | None,
    ) -> list[dict[str, Any]]:
        """Prioritize fuzz targets based on code analysis."""
        truncated = source_code[:self.config.max_input_tokens * 3]

        prompt = f"""Prioritize functions for fuzzing in this Soul Protocol contract.

Contract: {contract_name}
{f"Current coverage: {json.dumps(coverage)}" if coverage else ""}

Source:
```solidity
{truncated}
```

Rank functions by security criticality. Consider:
- Functions handling value transfers
- Functions with ZK proof verification
- Functions with access control checks
- Functions modifying critical state
- Bridge/cross-chain message handlers
- Functions with complex control flow

Respond with JSON array ordered by priority (highest first):
```json
[
  {{
    "function": "functionName",
    "priority": 10,
    "reason": "Why this function is critical",
    "risk_level": "critical|high|medium|low",
    "suggested_approach": "Description of fuzzing approach"
  }}
]
```"""

        response = await self._call_llm(prompt, max_tokens=2048)
        return self._parse_priorities(response)

    async def _explain_batch(
        self,
        source_code: str,
        violations: list[dict[str, Any]],
    ) -> list[ViolationExplanation]:
        """Explain a batch of violations."""
        truncated = source_code[:self.config.max_input_tokens * 2]

        violations_str = json.dumps(violations[:5], indent=2, default=str)

        prompt = f"""Explain these fuzzer-discovered invariant violations in a Soul Protocol contract.

Source (partial):
```solidity
{truncated}
```

Violations:
```json
{violations_str}
```

For each violation, explain:
1. Root cause in the code
2. How it could be exploited
3. Impact severity
4. Suggested fix
5. Related vulnerability classes

Respond with JSON array:
```json
[
  {{
    "invariant_id": "<the actual invariant ID from the violation, e.g. SOUL-INV-001>",
    "explanation": "...",
    "root_cause": "...",
    "exploitability": "high|medium|low",
    "suggested_fix": "...",
    "severity_assessment": "critical|high|medium|low",
    "related_bugs": ["reentrancy", "flash_loan"],
    "exploit_scenario": "Step-by-step exploit scenario"
  }}
]
```"""

        response = await self._call_llm(prompt, max_tokens=3000)
        return self._parse_explanations(response)

    def _build_next_mutations_prompt(
        self,
        source_code: str,
        coverage: dict[str, Any],
        recent_mutations: list[str],
        recent_results: list[dict[str, Any]],
    ) -> str:
        """Build prompt for online mutation suggestion."""
        truncated = source_code[:self.config.max_input_tokens * 2]
        recent_str = ", ".join(recent_mutations[-20:])
        results_str = json.dumps(recent_results[-10:], indent=2, default=str)

        return f"""Based on the current fuzzing state, suggest the next mutation strategies.

Source (partial):
```solidity
{truncated}
```

Current coverage: {json.dumps(coverage)}
Recent mutations tried: {recent_str}
Recent results: {results_str}

What mutations should we try next to maximize coverage and find bugs?
Focus on uncovered paths and mutations that haven't been tried.

Respond with JSON array of strategies (same format as before).
"""

    # ── Private: Parsers ─────────────────────────────────────────────────────

    def _parse_json_response(self, response: str) -> Any:
        """Parse JSON from LLM response, handling markdown code blocks."""
        if not response:
            return []

        # Extract JSON from markdown code blocks
        import re
        json_match = re.search(r'```(?:json)?\s*\n?(.*?)\n?\s*```', response, re.DOTALL)
        if json_match:
            response = json_match.group(1)

        try:
            return json.loads(response)
        except json.JSONDecodeError:
            # Try to find the array/object in the response
            for start_char, end_char in [('[', ']'), ('{', '}')]:
                start = response.find(start_char)
                end = response.rfind(end_char)
                if start != -1 and end != -1:
                    try:
                        return json.loads(response[start:end + 1])
                    except json.JSONDecodeError:
                        continue
            logger.warning("Failed to parse LLM JSON response")
            return []

    def _parse_insights(self, response: str) -> list[CodeInsight]:
        """Parse code insights from LLM response."""
        data = self._parse_json_response(response)
        if not isinstance(data, list):
            return []

        insights = []
        for item in data:
            if isinstance(item, dict):
                insights.append(CodeInsight(
                    category=item.get("category", "risk"),
                    title=item.get("title", ""),
                    description=item.get("description", ""),
                    affected_functions=item.get("affected_functions", []),
                    severity=item.get("severity", "medium"),
                    confidence=item.get("confidence", 0.5),
                    suggested_mutations=item.get("suggested_mutations", []),
                ))
        return insights

    def _parse_strategies(self, response: str) -> list[MutationStrategy]:
        """Parse mutation strategies from LLM response."""
        data = self._parse_json_response(response)
        if not isinstance(data, list):
            return []

        strategies = []
        for item in data:
            if isinstance(item, dict):
                strategies.append(MutationStrategy(
                    target_function=item.get("target_function", ""),
                    mutation_types=item.get("mutation_types", []),
                    rationale=item.get("rationale", ""),
                    priority=item.get("priority", 1.0),
                    input_template=item.get("input_template", {}),
                    attack_class=item.get("attack_class", ""),
                    confidence=item.get("confidence", 0.5),
                ))
        return strategies

    def _parse_hypotheses(self, response: str) -> list[AttackHypothesis]:
        """Parse attack hypotheses from LLM response."""
        data = self._parse_json_response(response)
        if not isinstance(data, list):
            return []

        hypotheses = []
        for item in data:
            if isinstance(item, dict):
                hypotheses.append(AttackHypothesis(
                    title=item.get("title", ""),
                    description=item.get("description", ""),
                    attack_class=item.get("attack_class", ""),
                    target_functions=item.get("target_functions", []),
                    prerequisites=item.get("prerequisites", []),
                    steps=item.get("steps", []),
                    expected_impact=item.get("expected_impact", ""),
                    mutation_sequence=item.get("mutation_sequence", []),
                    confidence=item.get("confidence", 0.5),
                    severity=item.get("severity", "medium"),
                ))
        return hypotheses

    def _parse_explanations(self, response: str) -> list[ViolationExplanation]:
        """Parse violation explanations from LLM response."""
        data = self._parse_json_response(response)
        if not isinstance(data, list):
            return []

        explanations = []
        for item in data:
            if isinstance(item, dict):
                explanations.append(ViolationExplanation(
                    invariant_id=item.get("invariant_id", ""),
                    explanation=item.get("explanation", ""),
                    root_cause=item.get("root_cause", ""),
                    exploitability=item.get("exploitability", "medium"),
                    suggested_fix=item.get("suggested_fix", ""),
                    severity_assessment=item.get("severity_assessment", "medium"),
                    related_bugs=item.get("related_bugs", []),
                    exploit_scenario=item.get("exploit_scenario", ""),
                ))
        return explanations

    def _parse_priorities(self, response: str) -> list[dict[str, Any]]:
        """Parse priority targets from LLM response."""
        data = self._parse_json_response(response)
        if isinstance(data, list):
            return [item for item in data if isinstance(item, dict)]
        return []

    # ── Heuristic Fallback ───────────────────────────────────────────────────

    def _heuristic_fallback(self, prompt: str) -> str:
        """Generate heuristic responses when LLM is unavailable.

        Provides reasonable defaults based on keyword analysis of the prompt.
        """
        if "mutation strategies" in prompt.lower() or "suggest" in prompt.lower():
            return json.dumps([
                {
                    "target_function": "withdraw",
                    "mutation_types": ["replay_nullifier", "corrupt_proof", "stale_merkle_root"],
                    "rationale": "Withdrawal functions are high-value targets combining proof verification and fund transfers",
                    "priority": 10,
                    "attack_class": "proof_bypass",
                    "confidence": 0.6,
                },
                {
                    "target_function": "deposit",
                    "mutation_types": ["flash_loan_sequence", "dust_amount", "max_uint_amount"],
                    "rationale": "Deposit functions handle commitment insertion and balance changes",
                    "priority": 8,
                    "attack_class": "economic",
                    "confidence": 0.5,
                },
                {
                    "target_function": "crossChainTransfer",
                    "mutation_types": ["wrong_chain_id", "invalid_bridge_message", "duplicate_relay"],
                    "rationale": "Bridge functions are complex and prone to replay/routing attacks",
                    "priority": 9,
                    "attack_class": "bridge_exploit",
                    "confidence": 0.6,
                },
            ])

        if "attack hypothes" in prompt.lower():
            return json.dumps([
                {
                    "title": "Flash Loan Funded Proof Replay",
                    "description": "Use flash loan to fund deposit, replay proof to withdraw without burned nullifier",
                    "attack_class": "flash_loan_composable",
                    "target_functions": ["deposit", "withdraw"],
                    "prerequisites": ["Sufficient pool liquidity"],
                    "steps": [
                        "1. Flash borrow large amount",
                        "2. Deposit with crafted commitment",
                        "3. Attempt withdrawal with replayed proof",
                        "4. If successful, repay flash loan + profit",
                    ],
                    "expected_impact": "Fund drain",
                    "mutation_sequence": ["flash_loan_sequence", "replay_proof"],
                    "confidence": 0.5,
                    "severity": "critical",
                },
            ])

        if "analyze" in prompt.lower() or "vulnerability" in prompt.lower():
            return json.dumps([
                {
                    "category": "risk",
                    "title": "ZK Proof Verification Dependency",
                    "description": "Contract relies on external verifier for proof validation",
                    "affected_functions": ["unlockWithProof", "withdraw", "submitProof"],
                    "severity": "high",
                    "confidence": 0.5,
                    "suggested_mutations": ["corrupt_proof", "wrong_verifier", "invalid_public_inputs"],
                },
            ])

        if "explain" in prompt.lower() or "violation" in prompt.lower():
            return json.dumps([
                {
                    "invariant_id": "SOUL-INV-001",
                    "explanation": "The nullifier uniqueness check may be bypassed via a specific input sequence",
                    "root_cause": "Missing domain-specific nullifier validation",
                    "exploitability": "high",
                    "suggested_fix": "Add domain separator to nullifier hash computation",
                    "severity_assessment": "critical",
                    "related_bugs": ["double_spend", "replay_attack"],
                    "exploit_scenario": "Submit same nullifier with different domain parameters",
                },
            ])

        if "prioritize" in prompt.lower() or "priority" in prompt.lower():
            return json.dumps([
                {"function": "withdraw", "priority": 10, "reason": "Value extraction", "risk_level": "critical"},
                {"function": "deposit", "priority": 9, "reason": "Fund intake", "risk_level": "high"},
                {"function": "crossChainTransfer", "priority": 8, "reason": "Bridge", "risk_level": "high"},
                {"function": "unlockWithProof", "priority": 8, "reason": "ZK verification", "risk_level": "high"},
                {"function": "registerNullifier", "priority": 7, "reason": "Replay prevention", "risk_level": "high"},
            ])

        return "[]"
