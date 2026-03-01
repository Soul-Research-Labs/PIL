"""Soul Protocol integrated fuzzer — Advanced Edition v2.

End-to-end orchestration binding 13 specialized engines:
  - SoulProtocolModel      → contract inventory + invariants
  - SoulMutationEngine     → mutated inputs + grammar/dictionary/symbolic/LLM
  - SoulFuzzLoop           → coverage feedback + corpus
  - Soul detectors         → static pre-analysis (24 detectors)
  - ForgeExecutor          → real EVM execution via Foundry
  - SymbolicExecutor       → constraint-based path exploration
  - ConcolicEngine         → concrete + symbolic hybrid
  - DifferentialFuzzer     → cross-version comparison
  - LLMOracle              → AI-guided mutation strategy
  - PropertyTester         → cross-contract invariant testing
  - AdvancedCorpus         → coverage-guided power scheduling
  - EVMBytecodeAnalyzer    → deep opcode-level analysis + CFG
  - InvariantSynthesis     → Daikon-style dynamic invariant discovery
  - StateReplayEngine      → time-travel debugging + snapshot/replay
  - ExploitChainComposer   → multi-step exploit sequence synthesis
  - TaintGuidedMutator     → dataflow-aware mutation targeting
  - GasProfilerEngine      → per-opcode gas accounting + DoS detection

Pipeline (18 phases):
  Phase 1  — Static pre-scan (24 Soul detectors)
  Phase 2  — EVM bytecode analysis + CFG extraction
  Phase 3  — Target identification from protocol model + bytecode
  Phase 4  — Symbolic analysis for targeted seed generation
  Phase 5  — Taint analysis for dataflow-guided mutation
  Phase 6  — LLM oracle for attack strategies
  Phase 7  — Initial seed generation (model + symbolic + LLM + taint)
  Phase 8  — Mutation-feedback fuzz loop (coverage + taint guided)
  Phase 9  — Concolic exploration for hard-to-reach paths
  Phase 10 — Cross-contract property testing
  Phase 11 — Gas profiling + DoS vector detection
  Phase 12 — Dynamic invariant synthesis from traces
  Phase 13 — State snapshot analysis + violation bisection
  Phase 14 — Exploit chain composition from violations
  Phase 15 — Process violations + delta-debugging minimization
  Phase 16 — Differential testing (if versions available)
  Phase 17 — Generate PoC test cases (Foundry)
  Phase 18 — LLM explanation + final report

Public API:
  SoulFuzzer.run_campaign()          → full advanced 18-phase campaign
  SoulFuzzer.quick_fuzz()            → lightweight fast run
  SoulFuzzer.targeted_fuzz()         → fuzz single contract/invariant
  SoulFuzzer.concolic_campaign()     → concolic-focused campaign
  SoulFuzzer.differential_campaign() → cross-version diff testing
  SoulFuzzer.property_test()         → cross-contract property verification
  SoulFuzzer.get_campaign_status()   → live progress
"""

from __future__ import annotations

import asyncio
import hashlib
import logging
import time
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any

from engine.analyzer.soul.protocol_model import (
    SoulContractCategory,
    SoulProtocolModel,
)
from engine.analyzer.soul.detectors import SOUL_DETECTORS
from engine.analyzer.web3.base_detector import DetectorContext
from engine.core.types import FindingSchema, Severity
from engine.fuzzer.mutation_engine import (
    FuzzInputType,
    MutationResult,
    MutationType,
    SoulMutationEngine,
)
from engine.fuzzer.feedback_loop import (
    CoverageMap,
    FuzzCorpus,
    SoulFuzzLoop,
    SoulInvariantChecker,
)

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Campaign configuration
# ---------------------------------------------------------------------------

class FuzzMode(str, Enum):
    """Fuzzing intensity modes."""
    QUICK = "quick"            # 60 s, broad coverage
    STANDARD = "standard"      # 300 s, balanced
    DEEP = "deep"              # 900 s, exhaustive
    TARGETED = "targeted"      # until saturation, single target
    CONTINUOUS = "continuous"   # until manually stopped
    CONCOLIC = "concolic"      # concolic-driven exploration
    DIFFERENTIAL = "differential"  # cross-version comparison
    SYMBOLIC = "symbolic"      # symbolic execution only
    PROPERTY = "property"      # cross-contract property testing


@dataclass
class FuzzCampaignConfig:
    """Configuration for a Soul fuzzing campaign."""

    mode: FuzzMode = FuzzMode.STANDARD
    max_duration_sec: int = 300
    max_iterations: int = 50_000
    target_contracts: list[str] = field(default_factory=list)
    target_invariants: list[str] = field(default_factory=list)
    enabled_mutations: list[MutationType] | None = None
    enable_llm_advisor: bool = True
    enable_static_pre_scan: bool = True
    enable_symbolic: bool = True
    enable_concolic: bool = True
    enable_differential: bool = False
    enable_property_testing: bool = True
    enable_forge: bool = True
    enable_advanced_corpus: bool = True
    # New v2 engine flags
    enable_bytecode_analysis: bool = True
    enable_taint_analysis: bool = True
    enable_gas_profiling: bool = True
    enable_invariant_synthesis: bool = True
    enable_state_replay: bool = True
    enable_exploit_composition: bool = True
    forge_path: str = "forge"
    foundry_project: str | None = None
    rpc_url: str | None = None
    seed: int | None = None
    parallel_workers: int = 4
    corpus_dir: str | None = None
    save_corpus: bool = True
    contract_versions: list[dict[str, Any]] = field(default_factory=list)
    power_schedule: str = "fast"

    @classmethod
    def quick(cls) -> FuzzCampaignConfig:
        return cls(
            mode=FuzzMode.QUICK,
            max_duration_sec=60,
            max_iterations=5_000,
            enable_symbolic=False,
            enable_concolic=False,
            enable_differential=False,
            enable_property_testing=False,
            enable_bytecode_analysis=False,
            enable_taint_analysis=False,
            enable_gas_profiling=False,
            enable_invariant_synthesis=False,
            enable_state_replay=False,
            enable_exploit_composition=False,
        )

    @classmethod
    def deep(cls) -> FuzzCampaignConfig:
        return cls(
            mode=FuzzMode.DEEP,
            max_duration_sec=900,
            max_iterations=200_000,
            enable_llm_advisor=True,
            enable_symbolic=True,
            enable_concolic=True,
            enable_property_testing=True,
        )

    @classmethod
    def concolic(cls) -> FuzzCampaignConfig:
        return cls(
            mode=FuzzMode.CONCOLIC,
            max_duration_sec=600,
            max_iterations=100_000,
            enable_concolic=True,
            enable_symbolic=True,
        )

    @classmethod
    def differential(cls) -> FuzzCampaignConfig:
        return cls(
            mode=FuzzMode.DIFFERENTIAL,
            max_duration_sec=600,
            max_iterations=50_000,
            enable_differential=True,
        )


# ---------------------------------------------------------------------------
# Campaign result types
# ---------------------------------------------------------------------------

class ViolationSeverity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


@dataclass
class InvariantViolation:
    """A confirmed invariant violation found during fuzzing."""

    invariant_id: str
    invariant_desc: str
    severity: ViolationSeverity
    triggering_input: dict[str, Any]
    mutation_chain: list[str]
    tx_sequence: list[dict[str, Any]]
    coverage_at_trigger: float
    iteration: int
    timestamp: float
    minimized: bool = False
    poc_code: str | None = None


@dataclass
class FuzzCampaignResult:
    """Complete campaign results — advanced edition."""

    campaign_id: str
    mode: FuzzMode
    duration_sec: float
    total_iterations: int
    violations: list[InvariantViolation]
    static_findings: list[FindingSchema]
    coverage: dict[str, float]
    mutation_stats: dict[str, int]
    corpus_size: int
    unique_paths: int
    contracts_fuzzed: list[str]
    invariants_checked: list[str]
    llm_insights: list[str] = field(default_factory=list)

    # Advanced fields
    symbolic_paths_explored: int = 0
    concolic_generations: int = 0
    concolic_new_coverage_pct: float = 0.0
    differential_findings: list[dict[str, Any]] = field(default_factory=list)
    property_violations: list[dict[str, Any]] = field(default_factory=list)
    forge_executions: int = 0
    power_schedule: str = "fast"
    corpus_stats: dict[str, Any] = field(default_factory=dict)
    llm_strategies: list[dict[str, Any]] = field(default_factory=list)
    attack_hypotheses: list[dict[str, Any]] = field(default_factory=list)

    # v2 engine fields
    bytecode_analysis: dict[str, Any] = field(default_factory=dict)
    taint_flows: list[dict[str, Any]] = field(default_factory=list)
    gas_profile: dict[str, Any] = field(default_factory=dict)
    dos_vectors: list[dict[str, Any]] = field(default_factory=list)
    synthesized_invariants: list[dict[str, Any]] = field(default_factory=list)
    state_snapshots: int = 0
    exploit_chains: list[dict[str, Any]] = field(default_factory=list)
    taint_mutation_targets: list[dict[str, Any]] = field(default_factory=list)

    @property
    def critical_violations(self) -> list[InvariantViolation]:
        return [v for v in self.violations if v.severity == ViolationSeverity.CRITICAL]

    @property
    def total_findings(self) -> int:
        return (
            len(self.violations)
            + len(self.static_findings)
            + len(self.differential_findings)
            + len(self.property_violations)
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "campaign_id": self.campaign_id,
            "mode": self.mode.value,
            "duration_sec": round(self.duration_sec, 2),
            "total_iterations": self.total_iterations,
            "total_findings": self.total_findings,
            "violations": [
                {
                    "invariant_id": v.invariant_id,
                    "invariant_desc": v.invariant_desc,
                    "severity": v.severity.value,
                    "mutation_chain": v.mutation_chain,
                    "iteration": v.iteration,
                    "minimized": v.minimized,
                    "poc_code": v.poc_code,
                }
                for v in self.violations
            ],
            "static_findings_count": len(self.static_findings),
            "coverage": self.coverage,
            "mutation_stats": self.mutation_stats,
            "corpus_size": self.corpus_size,
            "unique_paths": self.unique_paths,
            "contracts_fuzzed": self.contracts_fuzzed,
            "invariants_checked": self.invariants_checked,
            "llm_insights": self.llm_insights,
            # Advanced
            "symbolic_paths_explored": self.symbolic_paths_explored,
            "concolic_generations": self.concolic_generations,
            "concolic_new_coverage_pct": round(self.concolic_new_coverage_pct, 2),
            "differential_findings": self.differential_findings[:20],
            "property_violations": self.property_violations[:20],
            "forge_executions": self.forge_executions,
            "power_schedule": self.power_schedule,
            "corpus_stats": self.corpus_stats,
            "llm_strategies": self.llm_strategies[:10],
            "attack_hypotheses": self.attack_hypotheses[:10],
            # v2 engines
            "bytecode_analysis": self.bytecode_analysis,
            "taint_flows": self.taint_flows[:30],
            "gas_profile": self.gas_profile,
            "dos_vectors": self.dos_vectors[:20],
            "synthesized_invariants": self.synthesized_invariants[:30],
            "state_snapshots": self.state_snapshots,
            "exploit_chains": self.exploit_chains[:20],
            "taint_mutation_targets": self.taint_mutation_targets[:20],
        }


# ---------------------------------------------------------------------------
# Soul Fuzzer — main orchestrator
# ---------------------------------------------------------------------------

class SoulFuzzer:
    """Advanced mutation-feedback fuzzer for Soul Protocol.

    Orchestrates an 18-phase pipeline with 13 specialized engines:
      1.  Static pre-scan with 24 Soul detectors
      2.  EVM bytecode analysis + CFG extraction
      3.  Protocol model construction & target selection
      4.  Symbolic analysis for targeted seed generation
      5.  Taint analysis for dataflow-guided mutation
      6.  LLM oracle for attack hypothesis + mutation strategy
      7.  Initial seed generation (model + symbolic + LLM + taint)
      8.  Mutation-feedback loop with ForgeExecutor + advanced corpus
      9.  Concolic exploration for hard-to-reach branches
      10. Cross-contract property testing
      11. Gas profiling + DoS vector detection
      12. Dynamic invariant synthesis from execution traces
      13. State snapshot analysis + violation bisection
      14. Exploit chain composition from violations
      15. Process violations + delta-debugging minimization
      16. Differential testing (optional, requires versions)
      17. Generate Foundry PoC test cases
      18. LLM explanation + final report
    """

    def __init__(self, config: FuzzCampaignConfig | None = None):
        self.config = config or FuzzCampaignConfig()
        self.model = SoulProtocolModel()
        self.mutation_engine = SoulMutationEngine(
            protocol_model=self.model,
            seed=self.config.seed,
        )
        self.fuzz_loop = SoulFuzzLoop(
            mutation_engine=self.mutation_engine,
            max_iterations=self.config.max_iterations,
            timeout_seconds=float(self.config.max_duration_sec),
        )
        self._campaign_id: str | None = None
        self._start_time: float = 0
        self._running = False
        self._violations: list[InvariantViolation] = []
        self._static_findings: list[FindingSchema] = []
        self._llm_insights: list[str] = []
        self._differential_findings: list[dict[str, Any]] = []
        self._property_violations: list[dict[str, Any]] = []
        self._symbolic_paths: int = 0
        self._concolic_stats: dict[str, Any] = {}
        self._forge_executions: int = 0
        self._llm_strategies: list[dict[str, Any]] = []
        self._attack_hypotheses: list[dict[str, Any]] = []
        self._corpus_stats: dict[str, Any] = {}

        # v2 engine results
        self._bytecode_analysis: dict[str, Any] = {}
        self._taint_flows: list[dict[str, Any]] = []
        self._gas_profile: dict[str, Any] = {}
        self._dos_vectors: list[dict[str, Any]] = []
        self._synthesized_invariants: list[dict[str, Any]] = []
        self._state_snapshots: int = 0
        self._exploit_chains: list[dict[str, Any]] = []
        self._taint_mutation_targets: list[dict[str, Any]] = []
        self._execution_traces: list[dict[str, Any]] = []

        # Advanced engine instances (lazily initialized)
        self._symbolic_executor = None
        self._concolic_engine = None
        self._forge_executor = None
        self._differential_fuzzer = None
        self._llm_oracle = None
        self._property_tester = None
        self._advanced_corpus = None
        self._adaptive_scheduler = None

        # v2 engines (lazily initialized)
        self._bytecode_analyzer = None
        self._taint_mutator = None
        self._gas_profiler = None
        self._invariant_synth = None
        self._state_replay = None
        self._exploit_composer = None

    # ------------------------------------------------------------------
    # Lazy engine initialization
    # ------------------------------------------------------------------

    def _init_symbolic(self, source_code: str):
        """Initialize symbolic execution engine."""
        try:
            from engine.fuzzer.symbolic import SymbolicExecutor
            self._symbolic_executor = SymbolicExecutor()
            logger.info("Symbolic executor initialized")
        except Exception as e:
            logger.warning("Failed to init symbolic executor: %s", e)

    def _init_concolic(self, source_code: str):
        """Initialize concolic engine."""
        try:
            from engine.fuzzer.concolic import ConcolicEngine, SearchStrategy
            self._concolic_engine = ConcolicEngine(
                source_code=source_code,
                strategy=SearchStrategy.HYBRID,
            )
            logger.info("Concolic engine initialized")
        except Exception as e:
            logger.warning("Failed to init concolic engine: %s", e)

    async def _init_forge(self, source_code: str, contract_name: str):
        """Initialize Forge executor for real EVM execution."""
        try:
            from engine.fuzzer.forge_executor import ForgeExecutor, ForgeConfig
            config = ForgeConfig(
                forge_path=self.config.forge_path,
                project_dir=self.config.foundry_project,
                rpc_url=self.config.rpc_url,
            )
            self._forge_executor = ForgeExecutor(config)
            await self._forge_executor.initialize(
                source_code=source_code,
                contract_name=contract_name,
            )
            logger.info("Forge executor initialized")
        except Exception as e:
            logger.warning("Failed to init Forge executor: %s", e)

    async def _init_llm_oracle(self, source_code: str):
        """Initialize LLM mutation oracle."""
        try:
            from engine.fuzzer.llm_oracle import LLMOracle, OracleConfig
            self._llm_oracle = LLMOracle(OracleConfig())
            logger.info("LLM oracle initialized")
        except Exception as e:
            logger.warning("Failed to init LLM oracle: %s", e)

    def _init_advanced_corpus(self):
        """Initialize advanced corpus with power scheduling."""
        try:
            from engine.fuzzer.corpus_evolution import (
                AdvancedCorpus,
                AdaptiveScheduler,
                PowerSchedule,
            )
            schedule_map = {
                "fast": PowerSchedule.FAST,
                "coe": PowerSchedule.COE,
                "exploit": PowerSchedule.EXPLOIT,
                "explore": PowerSchedule.EXPLORE,
                "rare": PowerSchedule.RARE,
            }
            schedule = schedule_map.get(self.config.power_schedule, PowerSchedule.FAST)
            self._advanced_corpus = AdvancedCorpus(schedule=schedule)
            self._adaptive_scheduler = AdaptiveScheduler(self._advanced_corpus)
            self.fuzz_loop.set_advanced_corpus(self._advanced_corpus)
            self.fuzz_loop.set_adaptive_scheduler(self._adaptive_scheduler)
            logger.info("Advanced corpus initialized (schedule=%s)", schedule.value)
        except Exception as e:
            logger.warning("Failed to init advanced corpus: %s", e)

    def _init_property_tester(self):
        """Initialize cross-contract property tester."""
        try:
            from engine.fuzzer.property_tester import CrossContractPropertyTester
            self._property_tester = CrossContractPropertyTester(
                executor=self._forge_executor,
                timeout_sec=min(120.0, self.config.max_duration_sec * 0.15),
            )
            logger.info("Property tester initialized")
        except Exception as e:
            logger.warning("Failed to init property tester: %s", e)

    # -- v2 engine initializers ----------------------------------------

    def _init_bytecode_analyzer(self):
        """Initialize EVM bytecode analysis engine."""
        try:
            from engine.fuzzer.bytecode_analyzer import EVMBytecodeAnalyzer
            self._bytecode_analyzer = EVMBytecodeAnalyzer()
            logger.info("EVM bytecode analyzer initialized")
        except Exception as e:
            logger.warning("Failed to init bytecode analyzer: %s", e)

    def _init_taint_mutator(self):
        """Initialize taint-guided mutator."""
        try:
            from engine.fuzzer.taint_mutator import TaintGuidedMutator
            self._taint_mutator = TaintGuidedMutator(seed=self.config.seed)
            logger.info("Taint-guided mutator initialized")
        except Exception as e:
            logger.warning("Failed to init taint mutator: %s", e)

    def _init_gas_profiler(self):
        """Initialize gas profiler engine."""
        try:
            from engine.fuzzer.gas_profiler import GasProfilerEngine
            self._gas_profiler = GasProfilerEngine()
            logger.info("Gas profiler initialized")
        except Exception as e:
            logger.warning("Failed to init gas profiler: %s", e)

    def _init_invariant_synth(self):
        """Initialize invariant synthesis engine."""
        try:
            from engine.fuzzer.invariant_synth import InvariantSynthesisEngine
            self._invariant_synth = InvariantSynthesisEngine()
            logger.info("Invariant synthesis engine initialized")
        except Exception as e:
            logger.warning("Failed to init invariant synthesis: %s", e)

    def _init_state_replay(self):
        """Initialize state snapshot & replay engine."""
        try:
            from engine.fuzzer.state_replay import StateReplayEngine
            self._state_replay = StateReplayEngine()
            logger.info("State replay engine initialized")
        except Exception as e:
            logger.warning("Failed to init state replay: %s", e)

    def _init_exploit_composer(self):
        """Initialize exploit chain composer."""
        try:
            from engine.fuzzer.exploit_composer import ExploitChainComposer
            self._exploit_composer = ExploitChainComposer()
            logger.info("Exploit chain composer initialized")
        except Exception as e:
            logger.warning("Failed to init exploit composer: %s", e)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def run_campaign(
        self,
        source_code: str,
        contract_name: str = "Unknown",
        source_files: dict[str, str] | None = None,
        bytecode: bytes | None = None,
    ) -> FuzzCampaignResult:
        """Run a full advanced 18-phase fuzzing campaign.

        Integrates all 13 engines: symbolic, concolic, LLM, Forge,
        differential, property testing, bytecode analysis, taint,
        gas profiling, invariant synthesis, state replay, exploit
        chain composition.
        """
        self._campaign_id = self._generate_campaign_id(source_code)
        self._start_time = time.time()
        self._running = True
        self._violations = []
        self._static_findings = []
        self._differential_findings = []
        self._property_violations = []

        logger.info(
            "Starting advanced Soul fuzz campaign v2 %s mode=%s",
            self._campaign_id,
            self.config.mode.value,
        )

        try:
            # ── Phase 1: Static pre-scan ──
            if self.config.enable_static_pre_scan:
                self._static_findings = await self._run_static_scan(
                    source_code, contract_name,
                )
                logger.info("Phase 1: Static scan found %d issues", len(self._static_findings))

            # ── Phase 2: EVM bytecode analysis ──
            if self.config.enable_bytecode_analysis and bytecode:
                self._bytecode_analysis = await self._run_bytecode_analysis(
                    bytecode, contract_name,
                )
                logger.info(
                    "Phase 2: Bytecode analysis — %d functions, %d patterns",
                    self._bytecode_analysis.get("functions", 0),
                    self._bytecode_analysis.get("patterns", 0),
                )

            # ── Phase 3: Target identification ──
            all_sources = {contract_name: source_code}
            if source_files:
                all_sources.update(source_files)
            targets = self._identify_targets(all_sources)
            logger.info("Phase 3: %d fuzz targets identified", len(targets))

            # ── Phase 4: Symbolic analysis ──
            symbolic_seeds: list[dict[str, Any]] = []
            if self.config.enable_symbolic:
                symbolic_seeds = await self._run_symbolic_analysis(source_code, targets)
                logger.info(
                    "Phase 4: Symbolic analysis — %d paths, %d seeds",
                    self._symbolic_paths,
                    len(symbolic_seeds),
                )

            # ── Phase 5: Taint analysis ──
            if self.config.enable_taint_analysis:
                await self._run_taint_analysis(source_code, targets)
                logger.info(
                    "Phase 5: Taint analysis — %d flows, %d mutation targets",
                    len(self._taint_flows),
                    len(self._taint_mutation_targets),
                )

            # ── Phase 6: LLM oracle for attack strategies ──
            if self.config.enable_llm_advisor:
                await self._run_llm_strategy(source_code, targets)
                logger.info(
                    "Phase 6: LLM oracle — %d strategies, %d hypotheses",
                    len(self._llm_strategies),
                    len(self._attack_hypotheses),
                )

            # ── Phase 7: Seed generation ──
            seeds = self._generate_seeds(source_code, targets, symbolic_seeds)
            logger.info("Phase 7: Generated %d initial seeds", len(seeds))

            # ── Phase 8: Initialize engines + run fuzz loop ──
            if self.config.enable_forge:
                await self._init_forge(source_code, contract_name)
            if self.config.enable_advanced_corpus:
                self._init_advanced_corpus()
            if self.config.enable_state_replay:
                self._init_state_replay()

            loop_results = await self._run_fuzz_loop(
                source_code, contract_name, seeds, targets,
            )
            logger.info(
                "Phase 8: Fuzz loop — %d iterations, %d raw violations",
                loop_results.get("iterations", 0),
                len(loop_results.get("violations", [])),
            )

            # ── Phase 9: Concolic exploration ──
            if self.config.enable_concolic:
                concolic_results = await self._run_concolic(source_code, targets)
                logger.info(
                    "Phase 9: Concolic — %d generations, %.1f%% new coverage",
                    self._concolic_stats.get("generations", 0),
                    self._concolic_stats.get("new_coverage_pct", 0),
                )

            # ── Phase 10: Cross-contract property testing ──
            if self.config.enable_property_testing:
                await self._run_property_testing()
                logger.info(
                    "Phase 10: Property testing — %d violations",
                    len(self._property_violations),
                )

            # ── Phase 11: Gas profiling ──
            if self.config.enable_gas_profiling:
                await self._run_gas_profiling(contract_name)
                logger.info(
                    "Phase 11: Gas profiling — %d DoS vectors",
                    len(self._dos_vectors),
                )

            # ── Phase 12: Invariant synthesis ──
            if self.config.enable_invariant_synthesis:
                await self._run_invariant_synthesis()
                logger.info(
                    "Phase 12: Invariant synthesis — %d invariants discovered",
                    len(self._synthesized_invariants),
                )

            # ── Phase 13: State snapshot analysis ──
            if self.config.enable_state_replay and self._state_replay:
                await self._run_state_analysis(loop_results)
                logger.info(
                    "Phase 13: State analysis — %d snapshots taken",
                    self._state_snapshots,
                )

            # ── Phase 14: Exploit chain composition ──
            if self.config.enable_exploit_composition:
                await self._run_exploit_composition(
                    contract_name, loop_results.get("violations", []),
                )
                logger.info(
                    "Phase 14: Exploit composition — %d chains generated",
                    len(self._exploit_chains),
                )

            # ── Phase 15: Process violations + minimize ──
            for violation_data in loop_results.get("violations", []):
                violation = self._process_violation(violation_data)
                if violation:
                    self._violations.append(violation)

            for violation in self._violations:
                await self._minimize_input(violation, source_code)
            logger.info(
                "Phase 15: Processed %d violations (%d minimized)",
                len(self._violations),
                sum(1 for v in self._violations if v.minimized),
            )

            # ── Phase 16: Differential testing ──
            if self.config.enable_differential and self.config.contract_versions:
                await self._run_differential(source_code, contract_name)
                logger.info(
                    "Phase 16: Differential — %d findings",
                    len(self._differential_findings),
                )

            # ── Phase 17: Generate PoCs ──
            for violation in self._violations:
                violation.poc_code = self._generate_poc(violation, contract_name)
            logger.info("Phase 17: Generated %d PoCs", len(self._violations))

            # ── Phase 18: LLM explanation + report ──
            if self.config.enable_llm_advisor and self._violations:
                self._llm_insights = await self._get_llm_insights(
                    source_code, self._violations,
                )
            logger.info("Phase 18: Report generation complete")

            duration = time.time() - self._start_time
            return self._build_result(loop_results, duration)

        finally:
            self._running = False

    async def quick_fuzz(
        self,
        source_code: str,
        contract_name: str = "Unknown",
    ) -> FuzzCampaignResult:
        """Quick 60-second fuzz for rapid feedback."""
        self.config = FuzzCampaignConfig.quick()
        return await self.run_campaign(source_code, contract_name)

    async def targeted_fuzz(
        self,
        source_code: str,
        contract_name: str,
        target_function: str | None = None,
        target_invariant: str | None = None,
    ) -> FuzzCampaignResult:
        """Fuzz a specific function or invariant."""
        self.config.mode = FuzzMode.TARGETED
        if target_function:
            self.config.target_contracts = [target_function]
        if target_invariant:
            self.config.target_invariants = [target_invariant]
        return await self.run_campaign(source_code, contract_name)

    async def concolic_campaign(
        self,
        source_code: str,
        contract_name: str = "Unknown",
    ) -> FuzzCampaignResult:
        """Concolic (concrete + symbolic) focused campaign."""
        self.config = FuzzCampaignConfig.concolic()
        return await self.run_campaign(source_code, contract_name)

    async def differential_campaign(
        self,
        source_code: str,
        contract_name: str,
        versions: list[dict[str, Any]],
    ) -> FuzzCampaignResult:
        """Differential testing across contract versions."""
        self.config = FuzzCampaignConfig.differential()
        self.config.contract_versions = versions
        self.config.enable_differential = True
        return await self.run_campaign(source_code, contract_name)

    async def property_test(
        self,
        source_code: str,
        contract_name: str = "Unknown",
    ) -> FuzzCampaignResult:
        """Cross-contract property verification campaign."""
        self.config.mode = FuzzMode.PROPERTY
        self.config.enable_property_testing = True
        self.config.enable_static_pre_scan = True
        return await self.run_campaign(source_code, contract_name)

    def get_campaign_status(self) -> dict[str, Any]:
        """Get live campaign progress."""
        if not self._running:
            return {"status": "idle"}

        elapsed = time.time() - self._start_time
        loop_summary = self.fuzz_loop.get_results_summary()

        return {
            "status": "running",
            "campaign_id": self._campaign_id,
            "mode": self.config.mode.value,
            "elapsed_sec": round(elapsed, 1),
            "violations_found": len(self._violations),
            "static_findings": len(self._static_findings),
            "differential_findings": len(self._differential_findings),
            "property_violations": len(self._property_violations),
            "symbolic_paths": self._symbolic_paths,
            "forge_executions": self._forge_executions,
            # v2 engine status
            "taint_flows": len(self._taint_flows),
            "taint_targets": len(self._taint_mutation_targets),
            "dos_vectors": len(self._dos_vectors),
            "synthesized_invariants": len(self._synthesized_invariants),
            "state_snapshots": self._state_snapshots,
            "exploit_chains": len(self._exploit_chains),
            **loop_summary,
        }

    # ------------------------------------------------------------------
    # Phase 1 — Static pre-scan
    # ------------------------------------------------------------------

    async def _run_static_scan(
        self,
        source_code: str,
        contract_name: str,
    ) -> list[FindingSchema]:
        """Run all 24 Soul detectors as static pre-scan."""
        findings: list[FindingSchema] = []
        lines = source_code.splitlines()

        context = DetectorContext(
            contract_name=contract_name,
            source_code=source_code,
            lines=lines,
            ast=None,
            cfg=None,
            taint_results=None,
            call_graph=None,
            slither_results=None,
        )

        for detector_cls in SOUL_DETECTORS:
            try:
                detector = detector_cls()
                result = detector.detect(context)
                findings.extend(result)
            except Exception as exc:
                logger.warning("Detector %s failed: %s", detector_cls.__name__, exc)

        return findings

    # ------------------------------------------------------------------
    # Phase 2 — Target identification
    # ------------------------------------------------------------------

    def _identify_targets(
        self, source_files: dict[str, str],
    ) -> list[dict[str, Any]]:
        """Identify fuzz targets from source files + protocol model."""
        targets: list[dict[str, Any]] = []

        model_targets = self.model.get_fuzz_targets()
        for t in model_targets:
            targets.append({
                "contract": t.get("contract", ""),
                "function": t.get("function", ""),
                "category": t.get("category", ""),
                "inputs": t.get("inputs", []),
                "invariants": t.get("invariants", []),
                "priority": t.get("priority", 1),
            })

        for name, code in source_files.items():
            category = self.model.identify_contract_category(code)
            critical_fns = self.model.get_critical_functions(category)
            for fn in critical_fns:
                if fn not in [t["function"] for t in targets]:
                    targets.append({
                        "contract": name,
                        "function": fn,
                        "category": category.value if category else "unknown",
                        "inputs": [],
                        "invariants": [],
                        "priority": 2,
                    })

        if self.config.target_contracts:
            targets = [
                t for t in targets
                if t["contract"] in self.config.target_contracts
                or t["function"] in self.config.target_contracts
            ]

        targets.sort(key=lambda t: t["priority"])
        return targets

    # ------------------------------------------------------------------
    # Phase 3 — Symbolic analysis
    # ------------------------------------------------------------------

    async def _run_symbolic_analysis(
        self,
        source_code: str,
        targets: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        """Run symbolic execution to generate targeted seeds."""
        symbolic_seeds: list[dict[str, Any]] = []

        self._init_symbolic(source_code)
        if not self._symbolic_executor:
            return symbolic_seeds

        try:
            result = self._symbolic_executor.analyze(source_code)

            self._symbolic_paths = result.paths_explored

            # Convert symbolic constraints into concrete seeds
            for seed_data in result.generated_seeds:
                symbolic_seeds.append(seed_data)

            # Feed symbolic seeds to mutation engine
            self.mutation_engine.add_symbolic_seeds(symbolic_seeds)

        except Exception as e:
            logger.warning("Symbolic analysis failed: %s", e)

        return symbolic_seeds

    # ------------------------------------------------------------------
    # Phase 4 — LLM strategy
    # ------------------------------------------------------------------

    async def _run_llm_strategy(
        self,
        source_code: str,
        targets: list[dict[str, Any]],
    ) -> None:
        """Get LLM-guided attack strategies and mutation priorities."""
        await self._init_llm_oracle(source_code)
        if not self._llm_oracle:
            return

        try:
            oracle_result = await self._llm_oracle.analyze_contract(source_code)

            if oracle_result.strategies:
                self._llm_strategies = [
                    {
                        "function": s.function,
                        "mutations": s.mutations,
                        "rationale": s.rationale,
                    }
                    for s in oracle_result.strategies
                ]
                self.mutation_engine.set_llm_strategies(self._llm_strategies)

            if oracle_result.hypotheses:
                self._attack_hypotheses = [
                    {
                        "title": h.title,
                        "description": h.description,
                        "steps": h.steps,
                        "impact": h.impact,
                    }
                    for h in oracle_result.hypotheses
                ]

        except Exception as e:
            logger.warning("LLM strategy analysis failed: %s", e)

    # ------------------------------------------------------------------
    # Phase 5 — Seed generation
    # ------------------------------------------------------------------

    def _generate_seeds(
        self,
        source_code: str,
        targets: list[dict[str, Any]],
        symbolic_seeds: list[dict[str, Any]] | None = None,
    ) -> list[dict[str, Any]]:
        """Generate initial seeds from model + symbolic + LLM + static."""
        seeds = self.mutation_engine.generate_initial_seeds(
            source_code=source_code,
            targets=targets,
        )

        # Add symbolic seeds
        if symbolic_seeds:
            for ss in symbolic_seeds:
                seeds.append({
                    "type": "symbolic",
                    "source": "symbolic_executor",
                    "values": ss,
                    "energy": 8,
                })

        # Add static-finding-guided seeds
        for finding in self._static_findings:
            sev = finding.get("severity", "")
            if sev in (Severity.CRITICAL.value, Severity.HIGH.value, "CRITICAL", "HIGH"):
                seeds.append({
                    "type": FuzzInputType.TARGETED.value,
                    "source": "static_finding",
                    "finding_id": finding.get("id", ""),
                    "target_line": finding.get("location", {}).get("start_line", 0),
                    "values": {},
                    "energy": 10,
                })

        # Add LLM-hypothesis-guided seeds
        for hypothesis in self._attack_hypotheses:
            seeds.append({
                "type": "llm_hypothesis",
                "source": "llm_oracle",
                "hypothesis": hypothesis.get("title", ""),
                "values": {},
                "energy": 9,
            })

        # Add taint-guided mutation seeds (v2)
        for taint_target in self._taint_mutation_targets:
            seeds.append({
                "type": "taint_guided",
                "source": "taint_mutator",
                "function": taint_target.get("function", ""),
                "param": taint_target.get("param", ""),
                "taint_path": taint_target.get("taint_path", ""),
                "recommended_mutations": taint_target.get("mutations", []),
                "values": taint_target.get("seed_values", {}),
                "energy": taint_target.get("priority", 8),
            })

        # Add bytecode-informed seeds (v2)
        if self._bytecode_analysis:
            for pattern in self._bytecode_analysis.get("soul_patterns", []):
                seeds.append({
                    "type": "bytecode_pattern",
                    "source": "bytecode_analyzer",
                    "pattern_type": pattern.get("type", ""),
                    "selector": pattern.get("selector", ""),
                    "values": {},
                    "energy": 7,
                })

        return seeds

    # ------------------------------------------------------------------
    # Phase 6 — Fuzz loop
    # ------------------------------------------------------------------

    async def _run_fuzz_loop(
        self,
        source_code: str,
        contract_name: str,
        seeds: list[dict[str, Any]],
        targets: list[dict[str, Any]],
    ) -> dict[str, Any]:
        """Execute the advanced mutation-feedback fuzz loop."""
        max_iters = self.config.max_iterations
        max_time = self.config.max_duration_sec
        violations: list[dict[str, Any]] = []
        mutation_stats: dict[str, int] = {}
        iteration = 0
        start = time.time()

        # Initialize corpus
        corpus = self.fuzz_loop.corpus
        for seed_data in seeds:
            corpus.add_seed(seed_data)

        # Wire Forge executor if available
        if self._forge_executor:
            self.fuzz_loop.set_forge_executor(self._forge_executor)

        invariant_checker = SoulInvariantChecker()
        coverage = CoverageMap()

        while iteration < max_iters and (time.time() - start) < max_time:
            iteration += 1

            seed = corpus.select_seed()
            if seed is None:
                break

            mutation = self.mutation_engine.select_mutation(
                target_function=seed.get("function", "") if isinstance(seed, dict) else "",
            )

            mutated = self.mutation_engine.mutate_seed(seed, mutation)
            mutation_name = mutation.value if mutation else "none"
            mutation_stats[mutation_name] = mutation_stats.get(mutation_name, 0) + 1

            # Execute via Forge or simulation
            exec_result = await self._execute(source_code, contract_name, mutated)

            # Update coverage
            new_coverage = coverage.record_execution(
                path_hash=hashlib.md5(
                    f"{exec_result.get('revert_reason', '')}:{exec_result.get('gas_used', 0)}".encode()
                ).hexdigest(),
                revert_reason=exec_result.get("revert_reason", ""),
            )

            # Update advanced corpus if available
            if self._advanced_corpus:
                seed_id = mutated.get("id", str(iteration)) if isinstance(mutated, dict) else str(iteration)
                self._advanced_corpus.record_execution(
                    seed_id=seed_id,
                    new_coverage=new_coverage,
                    exec_time_us=exec_result.get("execution_time_us", 0),
                    violation=bool(exec_result.get("violations")),
                )

            # Adaptive schedule switching
            if self._adaptive_scheduler and iteration % 100 == 0:
                self._adaptive_scheduler.record_coverage(coverage.line_coverage)
                self._adaptive_scheduler.maybe_switch()

            # Check invariants
            inv_violations = invariant_checker.check_all(
                exec_result,
                state_before={},
                state_after=exec_result.get("state_changes", {}),
            ) if hasattr(invariant_checker, 'check_all') else []

            if inv_violations:
                for inv_v in (inv_violations if isinstance(inv_violations, list) else [inv_violations]):
                    violations.append({
                        "invariant_id": inv_v if isinstance(inv_v, str) else inv_v.get("id", ""),
                        "invariant_desc": "",
                        "input": mutated,
                        "mutation": mutation_name,
                        "iteration": iteration,
                        "coverage": coverage.line_coverage,
                    })

            # Update mutation weights (feedback)
            if new_coverage or inv_violations:
                self.mutation_engine.update_weights(mutation, 1.5)
                # Learn from interesting values
                if isinstance(mutated, dict):
                    for val in mutated.get("values", {}).values():
                        self.mutation_engine.add_to_dictionary(val)
            else:
                self.mutation_engine.update_weights(mutation, 0.99)

            # Track forge executions
            if self._forge_executor:
                self._forge_executions += 1

            # Progress logging
            if iteration % 1000 == 0:
                elapsed = time.time() - start
                logger.info(
                    "Fuzz iter %d/%d (%.0fs) cov=%.1f%% violations=%d corpus=%d",
                    iteration, max_iters, elapsed,
                    coverage.line_coverage,
                    len(violations),
                    len(corpus.seeds),
                )

        # Store corpus stats
        if self._advanced_corpus:
            self._corpus_stats = self._advanced_corpus.get_stats()

        return {
            "iterations": iteration,
            "violations": violations,
            "mutation_stats": mutation_stats,
            "coverage": coverage.to_dict(),
            "corpus_size": len(corpus.seeds),
            "unique_paths": coverage.path_count,
        }

    async def _execute(
        self,
        source_code: str,
        contract_name: str,
        input_data: Any,
    ) -> dict[str, Any]:
        """Execute via ForgeExecutor or simulation fallback."""
        if self._forge_executor:
            try:
                result = await self._forge_executor.execute(input_data)
                return {
                    "success": result.success if hasattr(result, 'success') else not result.get("reverted", False),
                    "revert_reason": getattr(result, 'revert_reason', result.get("revert_reason", "")),
                    "gas_used": getattr(result, 'gas_used', result.get("gas_used", 0)),
                    "state_changes": getattr(result, 'state_changes', result.get("state_changes", {})),
                    "events": getattr(result, 'logs', result.get("events", [])),
                    "coverage_bitmap": getattr(result, 'coverage_bitmap', b""),
                    "execution_time_us": getattr(result, 'execution_time_us', 0),
                }
            except Exception as e:
                logger.debug("Forge execution failed, falling back to simulation: %s", e)

        return self._simulate_execution(source_code, contract_name, input_data)

    def _simulate_execution(
        self,
        source_code: str,
        contract_name: str,
        input_data: Any,
    ) -> dict[str, Any]:
        """Heuristic simulation when Forge is not available."""
        result: dict[str, Any] = {
            "success": True,
            "revert_reason": None,
            "gas_used": 0,
            "state_changes": [],
            "events": [],
            "return_data": b"",
            "coverage_bitmap": set(),
        }

        mutation_type = ""
        if isinstance(input_data, dict):
            mutation_type = input_data.get("mutation_type", "")
        elif hasattr(input_data, 'mutation_history'):
            mutation_type = input_data.mutation_history[-1].value if input_data.mutation_history else ""

        high_revert_mutations = {
            "corrupt_proof", "truncate_proof", "wrong_verifier",
            "replay_nullifier", "zero_nullifier", "wrong_chain_id",
            "invalid_bridge_message", "max_uint_amount",
            "storage_collision", "type_confusion",
        }

        if mutation_type in high_revert_mutations:
            import random
            if random.random() < 0.85:
                result["success"] = False
                result["revert_reason"] = f"Simulated revert from {mutation_type}"
                path_hash = hashlib.md5(
                    f"{contract_name}:{mutation_type}:revert".encode()
                ).hexdigest()[:8]
                result["coverage_bitmap"] = {path_hash}
            else:
                path_hash = hashlib.md5(
                    f"{contract_name}:{mutation_type}:pass:{time.time_ns() % 1000}".encode()
                ).hexdigest()[:8]
                result["coverage_bitmap"] = {path_hash}
        else:
            path_hash = hashlib.md5(
                f"{contract_name}:{mutation_type}:success:{hash(str(input_data)) % 1000}".encode()
            ).hexdigest()[:8]
            result["coverage_bitmap"] = {path_hash}
            result["gas_used"] = 21000 + len(str(input_data)) * 10

        return result

    # ------------------------------------------------------------------
    # Phase 7 — Concolic exploration
    # ------------------------------------------------------------------

    async def _run_concolic(
        self,
        source_code: str,
        targets: list[dict[str, Any]],
    ) -> dict[str, Any]:
        """Run concolic execution for hard-to-reach branches."""
        self._init_concolic(source_code)
        if not self._concolic_engine:
            return {}

        try:
            result = await self._concolic_engine.run_concolic(
                max_generations=20,
                timeout_sec=min(120.0, self.config.max_duration_sec * 0.2),
            )

            self._concolic_stats = {
                "generations": result.generations if hasattr(result, 'generations') else 0,
                "new_coverage_pct": result.new_coverage_pct if hasattr(result, 'new_coverage_pct') else 0,
                "paths_explored": result.paths_explored if hasattr(result, 'paths_explored') else 0,
                "bugs_found": result.bugs_found if hasattr(result, 'bugs_found') else 0,
            }

            # Feed concolic results back to mutation engine
            if hasattr(result, 'new_inputs'):
                self.mutation_engine.add_symbolic_seeds(result.new_inputs)

            return self._concolic_stats

        except Exception as e:
            logger.warning("Concolic exploration failed: %s", e)
            return {}

    # ------------------------------------------------------------------
    # Phase 8 — Cross-contract property testing
    # ------------------------------------------------------------------

    async def _run_property_testing(self) -> None:
        """Run cross-contract property testing."""
        self._init_property_tester()
        if not self._property_tester:
            return

        try:
            result = await self._property_tester.run_property_tests(
                per_pattern=10,
            )

            self._property_violations = [
                v.to_dict() for v in result.violations
            ]

        except Exception as e:
            logger.warning("Property testing failed: %s", e)

    # ------------------------------------------------------------------
    # Phase 2 — EVM bytecode analysis (v2)
    # ------------------------------------------------------------------

    async def _run_bytecode_analysis(
        self, bytecode: bytes, contract_name: str,
    ) -> dict[str, Any]:
        """Analyze raw EVM bytecode for opcode patterns, CFG, storage layout."""
        self._init_bytecode_analyzer()
        if not self._bytecode_analyzer:
            return {}

        try:
            result = self._bytecode_analyzer.analyze(bytecode)

            # Enrich with Soul protocol pattern matching
            soul_patterns = []
            if hasattr(self._bytecode_analyzer, "match_soul_patterns"):
                soul_patterns = self._bytecode_analyzer.match_soul_patterns(result)

            # Generate coverage bitmap from CFG
            coverage_bitmap = None
            if hasattr(self._bytecode_analyzer, "generate_coverage_bitmap"):
                coverage_bitmap = self._bytecode_analyzer.generate_coverage_bitmap(result)

            analysis = {
                "contract": contract_name,
                "functions": len(result.get("functions", {})),
                "basic_blocks": len(result.get("cfg", {}).get("blocks", [])),
                "patterns": len(soul_patterns),
                "soul_patterns": soul_patterns,
                "storage_layout": result.get("storage_layout", {}),
                "selectors": result.get("function_selectors", {}),
                "delegate_calls": result.get("delegate_calls", []),
                "cfg_edges": len(result.get("cfg", {}).get("edges", [])),
                "coverage_bitmap_size": len(coverage_bitmap) if coverage_bitmap else 0,
                "raw": result,
            }

            logger.info(
                "Bytecode analysis for %s: %d functions, %d blocks, %d patterns",
                contract_name,
                analysis["functions"],
                analysis["basic_blocks"],
                analysis["patterns"],
            )
            return analysis

        except Exception as e:
            logger.warning("Bytecode analysis failed: %s", e)
            return {}

    # ------------------------------------------------------------------
    # Phase 5 — Taint analysis (v2)
    # ------------------------------------------------------------------

    async def _run_taint_analysis(
        self, source_code: str, targets: list[dict[str, Any]],
    ) -> None:
        """Run taint-guided dataflow analysis to find sensitive flows."""
        self._init_taint_mutator()
        if not self._taint_mutator:
            return

        try:
            # Analyze each target function for taint flows
            for target in targets:
                func_name = target.get("function", target.get("name", ""))
                if not func_name:
                    continue

                result = self._taint_mutator.analyze(
                    source_code=source_code,
                    function_name=func_name,
                    bytecode_hints=self._bytecode_analysis,
                )

                if result.get("flows"):
                    self._taint_flows.extend(result["flows"])

                if result.get("mutation_targets"):
                    self._taint_mutation_targets.extend(result["mutation_targets"])

            # Deduplicate flows by source-sink pair
            seen_pairs: set[tuple[str, str]] = set()
            unique_flows: list[dict[str, Any]] = []
            for flow in self._taint_flows:
                pair = (
                    flow.get("source", {}).get("id", ""),
                    flow.get("sink", {}).get("id", ""),
                )
                if pair not in seen_pairs:
                    seen_pairs.add(pair)
                    unique_flows.append(flow)
            self._taint_flows = unique_flows

            # Prioritize mutation targets by criticality
            self._taint_mutation_targets.sort(
                key=lambda t: t.get("priority", 0), reverse=True,
            )

            logger.info(
                "Taint analysis: %d unique flows, %d mutation targets",
                len(self._taint_flows),
                len(self._taint_mutation_targets),
            )

        except Exception as e:
            logger.warning("Taint analysis failed: %s", e)

    # ------------------------------------------------------------------
    # Phase 11 — Gas profiling (v2)
    # ------------------------------------------------------------------

    async def _run_gas_profiling(self, contract_name: str) -> None:
        """Profile gas consumption and detect DoS-via-gas vectors."""
        self._init_gas_profiler()
        if not self._gas_profiler:
            return

        try:
            # Collect execution traces from the fuzz loop
            traces = self.fuzz_loop.get_execution_traces()

            # Profile each function
            profile_result = self._gas_profiler.profile(
                traces=traces,
                contract_name=contract_name,
            )

            # Detect gas anomalies (potential DoS vectors)
            anomalies = self._gas_profiler.detect_anomalies(profile_result)

            # Build gas profile summary
            self._gas_profile = {
                "contract": contract_name,
                "functions": profile_result.get("function_profiles", {}),
                "hotspots": profile_result.get("hotspots", []),
                "total_gas_sampled": profile_result.get("total_gas", 0),
                "anomaly_count": len(anomalies),
            }

            # Convert anomalies to DoS vectors
            for anomaly in anomalies:
                dos_vector = {
                    "type": anomaly.get("anomaly_type", "unknown"),
                    "function": anomaly.get("function", ""),
                    "severity": anomaly.get("severity", "medium"),
                    "description": anomaly.get("description", ""),
                    "estimated_gas": anomaly.get("gas_cost", 0),
                    "worst_case_gas": anomaly.get("worst_case", 0),
                    "trigger_input": anomaly.get("trigger", {}),
                    "mitigation": anomaly.get("mitigation", ""),
                }
                self._dos_vectors.append(dos_vector)

            logger.info(
                "Gas profiling for %s: %d anomalies, %d DoS vectors",
                contract_name,
                len(anomalies),
                len(self._dos_vectors),
            )

        except Exception as e:
            logger.warning("Gas profiling failed: %s", e)

    # ------------------------------------------------------------------
    # Phase 12 — Invariant synthesis (v2)
    # ------------------------------------------------------------------

    async def _run_invariant_synthesis(self) -> None:
        """Synthesize new invariants from observed execution traces."""
        self._init_invariant_synth()
        if not self._invariant_synth:
            return

        try:
            # Feed execution traces from fuzz loop
            traces = self.fuzz_loop.get_execution_traces()
            if not traces:
                logger.info("No execution traces for invariant synthesis")
                return

            # Get existing invariants as seeds
            existing_invariants = [
                {"id": inv.id, "description": inv.description}
                for inv in self.model.invariants
            ]

            result = self._invariant_synth.synthesize(
                traces=traces,
                seed_invariants=existing_invariants,
                protocol_model=self.model.get_invariant_synthesis_seeds(),
            )

            # Filter to high-confidence invariants
            for inv in result.get("invariants", []):
                confidence = inv.get("confidence", 0)
                if confidence >= 0.7:
                    self._synthesized_invariants.append({
                        "expression": inv.get("expression", ""),
                        "category": inv.get("category", "unknown"),
                        "confidence": confidence,
                        "support": inv.get("support", 0),
                        "counter_examples": inv.get("counter_examples", 0),
                        "is_novel": inv.get("is_novel", True),
                        "related_invariant": inv.get("related_to", ""),
                    })

            logger.info(
                "Invariant synthesis: %d candidates → %d high-confidence",
                len(result.get("invariants", [])),
                len(self._synthesized_invariants),
            )

        except Exception as e:
            logger.warning("Invariant synthesis failed: %s", e)

    # ------------------------------------------------------------------
    # Phase 13 — State snapshot analysis (v2)
    # ------------------------------------------------------------------

    async def _run_state_analysis(
        self, loop_results: dict[str, Any],
    ) -> None:
        """Analyze state transitions via snapshots, bisect violations."""
        if not self._state_replay:
            return

        try:
            violations = loop_results.get("violations", [])

            # Take post-campaign state snapshot
            current_state = self.fuzz_loop.get_current_state()
            if current_state:
                self._state_replay.take_snapshot(
                    state=current_state,
                    label="post_fuzz_loop",
                )
                self._state_snapshots += 1

            # For each violation, attempt to bisect the causal transaction
            for violation in violations[:self.config.max_iterations // 10]:
                try:
                    bisect_result = self._state_replay.bisect_violation(
                        violation=violation,
                        traces=self.fuzz_loop.get_execution_traces(),
                    )

                    if bisect_result:
                        violation["bisect_result"] = {
                            "causal_tx_index": bisect_result.get("tx_index", -1),
                            "minimal_prefix": bisect_result.get("prefix_len", 0),
                            "state_diff": bisect_result.get("state_diff", {}),
                            "root_cause": bisect_result.get("root_cause", ""),
                        }
                        self._state_snapshots += bisect_result.get("snapshots_taken", 0)

                except Exception as e:
                    logger.debug("Bisection failed for violation: %s", e)

            # Replay interesting transaction sequences
            interesting_seqs = loop_results.get("interesting_sequences", [])
            for seq in interesting_seqs[:5]:
                try:
                    replay_result = self._state_replay.replay(
                        tx_sequence=seq,
                    )
                    if replay_result and replay_result.get("divergence"):
                        logger.info(
                            "State replay found divergence at tx %d",
                            replay_result["divergence_index"],
                        )
                except Exception as e:
                    logger.debug("State replay failed: %s", e)

            logger.info(
                "State analysis: %d snapshots, %d violations bisected",
                self._state_snapshots,
                sum(1 for v in violations if "bisect_result" in v),
            )

        except Exception as e:
            logger.warning("State analysis failed: %s", e)

    # ------------------------------------------------------------------
    # Phase 14 — Exploit chain composition (v2)
    # ------------------------------------------------------------------

    async def _run_exploit_composition(
        self,
        contract_name: str,
        violations: list[dict[str, Any]],
    ) -> None:
        """Compose multi-step exploit chains from discovered violations."""
        self._init_exploit_composer()
        if not self._exploit_composer:
            return

        try:
            # Map violations to exploit goals
            exploit_goals = self.model.get_exploit_goals()

            # Compose chains from violations
            chain_results = self._exploit_composer.compose_for_violations(
                violations=violations,
                contract_name=contract_name,
                exploit_goals=exploit_goals,
                taint_flows=self._taint_flows,
                gas_profile=self._gas_profile,
            )

            for chain in chain_results.get("chains", []):
                if chain.get("feasibility", 0) >= 0.5:
                    # Generate Foundry PoC for each viable chain
                    poc = None
                    if hasattr(self._exploit_composer, "generate_poc"):
                        poc = self._exploit_composer.generate_poc(
                            chain=chain,
                            contract_name=contract_name,
                        )

                    self._exploit_chains.append({
                        "goal": chain.get("goal", ""),
                        "steps": chain.get("steps", []),
                        "primitives": chain.get("primitives", []),
                        "feasibility": chain.get("feasibility", 0),
                        "impact": chain.get("impact", "unknown"),
                        "poc_code": poc,
                        "related_violations": chain.get("violation_ids", []),
                        "taint_evidence": chain.get("taint_evidence", []),
                    })

            logger.info(
                "Exploit composition: %d chains (%.0f%% viable)",
                len(self._exploit_chains),
                (
                    100.0 * len(self._exploit_chains) / max(len(chain_results.get("chains", [])), 1)
                ),
            )

        except Exception as e:
            logger.warning("Exploit composition failed: %s", e)

    # ------------------------------------------------------------------
    # Phase 9 — Process violations + minimize
    # ------------------------------------------------------------------

    def _process_violation(
        self, violation_data: dict[str, Any],
    ) -> InvariantViolation | None:
        """Convert raw violation data into structured InvariantViolation."""
        inv_id = violation_data.get("invariant_id", "")

        severity_map = {
            "SOUL-INV-001": ViolationSeverity.CRITICAL,
            "SOUL-INV-002": ViolationSeverity.HIGH,
            "SOUL-INV-003": ViolationSeverity.HIGH,
            "SOUL-INV-010": ViolationSeverity.CRITICAL,
            "SOUL-INV-011": ViolationSeverity.CRITICAL,
            "SOUL-INV-012": ViolationSeverity.HIGH,
            "SOUL-INV-013": ViolationSeverity.HIGH,
            "SOUL-INV-020": ViolationSeverity.CRITICAL,
            "SOUL-INV-030": ViolationSeverity.CRITICAL,
            "SOUL-INV-031": ViolationSeverity.HIGH,
            "SOUL-INV-032": ViolationSeverity.HIGH,
            "SOUL-INV-033": ViolationSeverity.CRITICAL,
            "SOUL-INV-040": ViolationSeverity.CRITICAL,
            "SOUL-INV-041": ViolationSeverity.HIGH,
            "SOUL-INV-042": ViolationSeverity.HIGH,
            "SOUL-INV-060": ViolationSeverity.HIGH,
            "SOUL-INV-070": ViolationSeverity.HIGH,
            "SOUL-INV-080": ViolationSeverity.HIGH,
            "SOUL-INV-090": ViolationSeverity.MEDIUM,
        }
        severity = severity_map.get(inv_id, ViolationSeverity.MEDIUM)

        return InvariantViolation(
            invariant_id=inv_id,
            invariant_desc=violation_data.get("invariant_desc", ""),
            severity=severity,
            triggering_input=violation_data.get("input", {}),
            mutation_chain=[violation_data.get("mutation", "")],
            tx_sequence=[violation_data.get("input", {})],
            coverage_at_trigger=violation_data.get("coverage", 0.0),
            iteration=violation_data.get("iteration", 0),
            timestamp=time.time(),
        )

    async def _minimize_input(
        self,
        violation: InvariantViolation,
        source_code: str,
    ) -> None:
        """Delta-debugging input minimization."""
        original = violation.triggering_input.copy()
        fields = list(original.get("values", {}).keys())

        for field_name in fields:
            test_input = original.copy()
            test_values = test_input.get("values", {}).copy()
            del test_values[field_name]
            test_input["values"] = test_values

            exec_result = self._simulate_execution(source_code, "", test_input)
            checker = SoulInvariantChecker()
            still_violates = checker.check_all(
                exec_result, state_before={}, state_after={},
            ) if hasattr(checker, 'check_all') else []

            if still_violates:
                original = test_input

        violation.triggering_input = original
        violation.minimized = True

    # ------------------------------------------------------------------
    # Phase 10 — Differential testing
    # ------------------------------------------------------------------

    async def _run_differential(
        self,
        source_code: str,
        contract_name: str,
    ) -> None:
        """Run differential fuzzing across contract versions."""
        if not self.config.contract_versions:
            return

        try:
            from engine.fuzzer.differential import (
                DifferentialFuzzer,
                ContractVersion,
            )

            versions = []
            # Current version
            versions.append(ContractVersion(
                name="current",
                source_code=source_code,
                label="Current",
            ))

            # Additional versions from config
            for v_data in self.config.contract_versions:
                versions.append(ContractVersion(
                    name=v_data.get("name", "v_unknown"),
                    source_code=v_data.get("source_code", ""),
                    label=v_data.get("label", ""),
                ))

            diff_fuzzer = DifferentialFuzzer(
                versions=versions,
                executor=self._forge_executor,
            )

            result = await diff_fuzzer.run(
                max_iterations=min(5000, self.config.max_iterations // 5),
                timeout_sec=min(120.0, self.config.max_duration_sec * 0.15),
            )

            self._differential_findings = [
                f.to_dict() if hasattr(f, 'to_dict') else f
                for f in (result.findings if hasattr(result, 'findings') else [])
            ]

        except Exception as e:
            logger.warning("Differential testing failed: %s", e)

    # ------------------------------------------------------------------
    # Phase 11 — PoC generation
    # ------------------------------------------------------------------

    def _generate_poc(
        self,
        violation: InvariantViolation,
        contract_name: str,
    ) -> str:
        """Generate a Foundry test PoC for the violation."""
        inv_id = violation.invariant_id
        mutation = violation.mutation_chain[0] if violation.mutation_chain else "unknown"
        values = violation.triggering_input.get("values", {})

        value_lines = []
        for k, v in values.items():
            if isinstance(v, int):
                value_lines.append(f"        uint256 {k} = {v};")
            elif isinstance(v, str) and v.startswith("0x"):
                if len(v) == 42:
                    value_lines.append(f"        address {k} = {v};")
                else:
                    value_lines.append(f'        bytes32 {k} = hex"{v[2:]}";')
            elif isinstance(v, bytes):
                value_lines.append(f'        bytes memory {k} = hex"{v.hex()}";')
            else:
                value_lines.append(f"        // {k} = {v}")

        values_block = "\n".join(value_lines) if value_lines else "        // No specific values"

        # Generate contract call block from tx_sequence
        call_lines: list[str] = []
        for tx_idx, tx in enumerate(violation.tx_sequence):
            func = tx.get("function", "") if isinstance(tx, dict) else ""
            tx_values = tx.get("values", {}) if isinstance(tx, dict) else {}
            msg_value = tx.get("msg_value", 0) if isinstance(tx, dict) else 0

            if not func:
                call_lines.append(f"        // tx[{tx_idx}]: no target function resolved")
                continue

            # Build argument list from tx values
            args = []
            for _k, v in tx_values.items():
                if isinstance(v, int):
                    args.append(str(v))
                elif isinstance(v, str) and v.startswith("0x"):
                    args.append(v)
                elif isinstance(v, bytes):
                    args.append(f'hex"{v.hex()}"')
                else:
                    args.append(f"/* {v} */")
            args_str = ", ".join(args)

            if msg_value:
                call_lines.append(f"        target.{func}{{value: {msg_value}}}({args_str});")
            else:
                call_lines.append(f"        target.{func}({args_str});")

        if not call_lines:
            # Fallback: use triggering_input directly
            func = violation.triggering_input.get("function", "")
            if func:
                args = []
                for _k, v in values.items():
                    if isinstance(v, int):
                        args.append(str(v))
                    elif isinstance(v, str):
                        args.append(v)
                    else:
                        args.append(f"/* {v} */")
                args_str = ", ".join(args)
                call_lines.append(f"        target.{func}({args_str});")
            else:
                call_lines.append("        // Could not resolve target function — manual wiring required")

        call_block = "\n".join(call_lines)

        return f"""// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "../src/{contract_name}.sol";

/**
 * @title PoC: {inv_id} Violation
 * @notice Generated by ZASEON Soul Fuzzer (Advanced Edition)
 * @dev Mutation: {mutation}
 *      Invariant: {violation.invariant_desc}
 *      Found at iteration: {violation.iteration}
 *      Campaign: {self._campaign_id}
 */
contract {inv_id.replace("-", "_")}_PoC is Test {{
    {contract_name} target;

    function setUp() public {{
        target = new {contract_name}();
    }}

    function test_violation_{inv_id.replace("-", "_")}() public {{
{values_block}

        // Execute the violation sequence
        // Mutation: {mutation}
        // Invariant: {inv_id}: {violation.invariant_desc}

{call_block}
    }}
}}
"""

    # ------------------------------------------------------------------
    # Phase 12 — LLM explanation
    # ------------------------------------------------------------------

    async def _get_llm_insights(
        self,
        source_code: str,
        violations: list[InvariantViolation],
    ) -> list[str]:
        """Get LLM-guided insights on violations."""
        insights: list[str] = []

        # Use LLM oracle if available
        if self._llm_oracle:
            try:
                explanations = await self._llm_oracle.explain_violations(
                    source_code=source_code,
                    violations=[
                        {
                            "invariant_id": v.invariant_id,
                            "invariant_desc": v.invariant_desc,
                            "severity": v.severity.value,
                            "mutation": v.mutation_chain[0] if v.mutation_chain else "",
                        }
                        for v in violations[:10]
                    ],
                )
                if explanations:
                    for exp in explanations:
                        insights.append(
                            f"[{exp.severity}] {exp.title}: {exp.root_cause}. "
                            f"Fix: {exp.fix_suggestion}"
                            if hasattr(exp, 'root_cause') else str(exp)
                        )
                return insights
            except Exception as e:
                logger.debug("LLM explanation failed: %s", e)

        # Heuristic fallback
        by_category: dict[str, list[InvariantViolation]] = {}
        for v in violations:
            prefix = v.invariant_id.split("-")[1] if "-" in v.invariant_id else "unknown"
            by_category.setdefault(prefix, []).append(v)

        for category, cat_violations in by_category.items():
            count = len(cat_violations)
            severities = [v.severity.value for v in cat_violations]
            mutations = [v.mutation_chain[0] for v in cat_violations if v.mutation_chain]

            insight = (
                f"[{category.upper()}] {count} violation(s) found. "
                f"Severities: {', '.join(set(severities))}. "
                f"Effective mutations: {', '.join(set(mutations)[:5])}. "
            )

            if any(s == "critical" for s in severities):
                insight += (
                    "CRITICAL: These violations indicate exploitable bugs "
                    "that could lead to fund loss or protocol compromise."
                )

            insights.append(insight)

        return insights

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _generate_campaign_id(self, source_code: str) -> str:
        content_hash = hashlib.sha256(source_code.encode()).hexdigest()[:12]
        ts = int(time.time())
        return f"soul-fuzz-{ts}-{content_hash}"

    def _build_result(
        self,
        loop_results: dict[str, Any],
        duration: float,
    ) -> FuzzCampaignResult:
        return FuzzCampaignResult(
            campaign_id=self._campaign_id or "",
            mode=self.config.mode,
            duration_sec=duration,
            total_iterations=loop_results.get("iterations", 0),
            violations=self._violations,
            static_findings=self._static_findings,
            coverage=loop_results.get("coverage", {}),
            mutation_stats=loop_results.get("mutation_stats", {}),
            corpus_size=loop_results.get("corpus_size", 0),
            unique_paths=loop_results.get("unique_paths", 0),
            contracts_fuzzed=self.config.target_contracts or ["all"],
            invariants_checked=(
                self.config.target_invariants
                or [inv.id for inv in self.model.invariants]
            ),
            llm_insights=self._llm_insights,
            # Advanced v1
            symbolic_paths_explored=self._symbolic_paths,
            concolic_generations=self._concolic_stats.get("generations", 0),
            concolic_new_coverage_pct=self._concolic_stats.get("new_coverage_pct", 0),
            differential_findings=self._differential_findings,
            property_violations=self._property_violations,
            forge_executions=self._forge_executions,
            power_schedule=self.config.power_schedule,
            corpus_stats=self._corpus_stats,
            llm_strategies=self._llm_strategies,
            attack_hypotheses=self._attack_hypotheses,
            # Advanced v2
            bytecode_analysis=self._bytecode_analysis,
            taint_flows=self._taint_flows,
            gas_profile=self._gas_profile,
            dos_vectors=self._dos_vectors,
            synthesized_invariants=self._synthesized_invariants,
            state_snapshots=self._state_snapshots,
            exploit_chains=self._exploit_chains,
            taint_mutation_targets=self._taint_mutation_targets,
        )
