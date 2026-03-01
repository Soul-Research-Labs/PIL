"""Soul Protocol fuzzer API endpoints — Advanced Edition v2.

Routes:
  POST /api/v1/soul/fuzz              — Start a fuzzing campaign (18-phase, 13 engines)
  POST /api/v1/soul/quick-fuzz        — Quick 60-second fuzz
  POST /api/v1/soul/targeted-fuzz     — Fuzz specific function/invariant
  POST /api/v1/soul/concolic          — Concolic-driven fuzzing campaign
  POST /api/v1/soul/differential      — Cross-version differential testing
  POST /api/v1/soul/symbolic          — Symbolic execution analysis only
  POST /api/v1/soul/property-test     — Cross-contract property verification
  POST /api/v1/soul/bytecode-analysis — EVM bytecode deep analysis
  POST /api/v1/soul/taint-analysis    — Taint-guided dataflow analysis
  POST /api/v1/soul/gas-profile       — Gas profiling & DoS vector detection
  POST /api/v1/soul/scan              — Static-only Soul detector scan
  GET  /api/v1/soul/campaign/{id}     — Get campaign status/results
  GET  /api/v1/soul/campaign/{id}/stream — SSE stream for live campaign updates
  GET  /api/v1/soul/invariants        — List all Soul invariants
  GET  /api/v1/soul/detectors         — List all Soul detectors
  GET  /api/v1/soul/mutation-types     — List available mutation strategies
  GET  /api/v1/soul/power-schedules   — List available power schedules
  GET  /api/v1/soul/forge-status      — Check Forge executor availability
  POST /api/v1/soul/fetch             — Fetch Soul contracts from GitHub
  GET  /api/v1/soul/protocol-model    — Get Soul protocol model
  GET  /api/v1/soul/engine-status     — Get status of all 13 engines
"""

from __future__ import annotations

import asyncio
import json
import logging
import shutil
import time
import traceback
from typing import Any

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Request
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field

from engine.analyzer.soul.protocol_model import SoulProtocolModel
from engine.analyzer.soul.detectors import SOUL_DETECTORS
from engine.core.database import get_db
from engine.api.middleware.auth import get_current_user
from engine.models.user import User as AuthUser
from engine.fuzzer.soul_fuzzer import (
    FuzzCampaignConfig,
    FuzzCampaignResult,
    FuzzMode,
    SoulFuzzer,
)
from engine.ingestion.soul_fetcher import SoulContractFetcher, SoulContractDir
from engine.models.soul import SoulCampaign, SoulFinding
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

logger = logging.getLogger(__name__)

router = APIRouter()

# In-memory campaign store (replace with DB in production)
_campaigns: dict[str, dict[str, Any]] = {}
_fuzzers: dict[str, SoulFuzzer] = {}


# ── Schemas ──────────────────────────────────────────────────────────────────


class SoulFuzzRequest(BaseModel):
    """Request to start a Soul Protocol fuzzing campaign."""
    source_code: str = Field(..., description="Solidity source code to fuzz")
    contract_name: str = Field(default="SoulContract", description="Contract name")
    mode: str = Field(default="standard", description="Fuzz mode: quick/standard/deep/targeted")
    max_duration_sec: int = Field(default=300, ge=10, le=3600, description="Max duration in seconds")
    max_iterations: int = Field(default=50_000, ge=100, le=1_000_000)
    target_functions: list[str] = Field(default_factory=list, description="Specific functions to fuzz")
    target_invariants: list[str] = Field(default_factory=list, description="Specific invariant IDs")
    enable_llm: bool = Field(default=True, description="Enable LLM-guided strategy")
    enable_static_scan: bool = Field(default=True, description="Run static detectors first")
    enable_symbolic: bool = Field(default=True, description="Enable symbolic execution")
    enable_concolic: bool = Field(default=True, description="Enable concolic exploration")
    enable_forge: bool = Field(default=True, description="Enable Forge EVM execution")
    enable_property_testing: bool = Field(default=True, description="Enable cross-contract property testing")
    enable_advanced_corpus: bool = Field(default=True, description="Enable advanced corpus evolution with power scheduling")
    enable_bytecode_analysis: bool = Field(default=True, description="Enable EVM bytecode deep analysis")
    enable_taint_analysis: bool = Field(default=True, description="Enable taint-guided dataflow analysis")
    enable_gas_profiling: bool = Field(default=True, description="Enable gas profiling & DoS detection")
    enable_invariant_synthesis: bool = Field(default=True, description="Enable dynamic invariant synthesis")
    enable_state_replay: bool = Field(default=True, description="Enable state snapshot & replay analysis")
    enable_exploit_composition: bool = Field(default=True, description="Enable multi-step exploit chain composition")
    power_schedule: str = Field(default="fast", description="Power schedule: fast/coe/lin/quad/exploit/explore/mmopt/rare")
    additional_sources: dict[str, str] = Field(
        default_factory=dict,
        description="Additional source files {filename: code}",
    )
    bytecode: str | None = Field(default=None, description="Hex-encoded EVM bytecode for bytecode analysis")


class SoulQuickFuzzRequest(BaseModel):
    """Quick 60-second fuzz request."""
    source_code: str
    contract_name: str = "SoulContract"


class SoulTargetedFuzzRequest(BaseModel):
    """Targeted fuzz request for specific function/invariant."""
    source_code: str
    contract_name: str = "SoulContract"
    target_function: str | None = None
    target_invariant: str | None = None
    max_duration_sec: int = Field(default=120, ge=10, le=1800)


class SoulConcolicRequest(BaseModel):
    """Concolic-driven fuzzing campaign."""
    source_code: str = Field(..., description="Solidity source code")
    contract_name: str = Field(default="SoulContract")
    max_duration_sec: int = Field(default=600, ge=30, le=3600)
    max_iterations: int = Field(default=100_000, ge=100, le=1_000_000)
    search_strategy: str = Field(default="generational", description="Search strategy: generational/dfs/bfs/random_path/coverage_opt/hybrid")
    enable_forge: bool = Field(default=True)
    additional_sources: dict[str, str] = Field(default_factory=dict)


class SoulDifferentialRequest(BaseModel):
    """Cross-version differential testing."""
    source_code: str = Field(..., description="Current version source code")
    contract_name: str = Field(default="SoulContract")
    previous_source: str = Field(..., description="Previous version source code")
    previous_name: str = Field(default="SoulContract_v1", description="Previous version contract name")
    max_duration_sec: int = Field(default=300, ge=30, le=3600)
    diff_types: list[str] = Field(
        default_factory=lambda: ["state_divergence", "output_mismatch", "gas_difference"],
        description="Differential types to check",
    )
    additional_sources: dict[str, str] = Field(default_factory=dict)


class SoulSymbolicRequest(BaseModel):
    """Symbolic execution analysis only."""
    source_code: str = Field(..., description="Solidity source code")
    contract_name: str = Field(default="SoulContract")
    max_paths: int = Field(default=1000, ge=10, le=50_000)
    timeout_sec: int = Field(default=120, ge=10, le=600)
    target_functions: list[str] = Field(default_factory=list)


class SoulPropertyTestRequest(BaseModel):
    """Cross-contract property verification."""
    source_code: str = Field(..., description="Solidity source code")
    contract_name: str = Field(default="SoulContract")
    property_types: list[str] = Field(
        default_factory=lambda: [
            "fund_conservation", "nullifier_consistency", "state_lifecycle",
            "bridge_integrity", "swap_completeness", "privacy_guarantee",
        ],
        description="Property types to verify",
    )
    max_sequences: int = Field(default=500, ge=10, le=10_000)
    max_seq_length: int = Field(default=20, ge=3, le=100)
    additional_sources: dict[str, str] = Field(default_factory=dict)


class SoulStaticScanRequest(BaseModel):
    """Static-only scan with Soul detectors."""
    source_code: str
    contract_name: str = "SoulContract"


class SoulFetchRequest(BaseModel):
    """Fetch Soul contracts from GitHub."""
    branch: str = "main"
    category: str | None = None
    contract_name: str | None = None
    with_dependencies: bool = False


class SoulFindingSummary(BaseModel):
    """Summarized finding."""
    id: str = ""
    title: str
    severity: str
    description: str
    category: str = ""
    detector_id: str = ""
    remediation: str = ""
    file_path: str = ""
    start_line: int = 0


class SoulViolationSummary(BaseModel):
    """Summarized invariant violation."""
    invariant_id: str
    invariant_desc: str
    severity: str
    mutation: str = ""
    iteration: int = 0
    coverage_at_trigger: float = 0.0
    minimized: bool = False
    has_poc: bool = False


class SoulFuzzResponse(BaseModel):
    """Fuzz campaign response — advanced edition."""
    campaign_id: str
    status: str
    mode: str
    duration_sec: float = 0.0
    total_iterations: int = 0
    violations: list[SoulViolationSummary] = []
    static_findings: list[SoulFindingSummary] = []
    coverage: dict[str, float] = {}
    mutation_stats: dict[str, int] = {}
    corpus_size: int = 0
    unique_paths: int = 0
    contracts_fuzzed: list[str] = []
    invariants_checked: list[str] = []
    llm_insights: list[str] = []
    score: float = 100.0
    # Advanced fields
    symbolic_paths_explored: int = 0
    concolic_generations: int = 0
    concolic_new_coverage_pct: float = 0.0
    differential_findings: list[dict[str, Any]] = []
    property_violations: list[dict[str, Any]] = []
    forge_executions: int = 0
    power_schedule: str = "fast"
    corpus_stats: dict[str, Any] = {}
    llm_strategies: list[dict[str, Any]] = []
    attack_hypotheses: list[dict[str, Any]] = []
    total_findings: int = 0
    # v2 engine fields
    bytecode_analysis: dict[str, Any] = {}
    taint_flows: list[dict[str, Any]] = []
    gas_profile: dict[str, Any] = {}
    dos_vectors: list[dict[str, Any]] = []
    synthesized_invariants: list[dict[str, Any]] = []
    state_snapshots: int = 0
    exploit_chains: list[dict[str, Any]] = []
    taint_mutation_targets: list[dict[str, Any]] = []


class SoulConcolicResponse(BaseModel):
    """Concolic campaign response."""
    campaign_id: str
    status: str
    mode: str = "concolic"
    duration_sec: float = 0.0
    total_iterations: int = 0
    violations: list[SoulViolationSummary] = []
    coverage: dict[str, float] = {}
    concolic_generations: int = 0
    concolic_new_coverage_pct: float = 0.0
    symbolic_paths_explored: int = 0
    corpus_size: int = 0
    unique_paths: int = 0
    score: float = 100.0


class SoulDifferentialResponse(BaseModel):
    """Differential testing response."""
    campaign_id: str
    status: str
    mode: str = "differential"
    duration_sec: float = 0.0
    total_inputs_tested: int = 0
    differential_findings: list[dict[str, Any]] = []
    findings_by_type: dict[str, int] = {}
    findings_by_severity: dict[str, int] = {}
    inputs_with_divergence_pct: float = 0.0
    score: float = 100.0


class SoulSymbolicResponse(BaseModel):
    """Symbolic execution response."""
    campaign_id: str
    status: str
    mode: str = "symbolic"
    duration_sec: float = 0.0
    paths_explored: int = 0
    constraints_generated: int = 0
    seeds_generated: int = 0
    unreachable_branches: int = 0
    target_coverage: dict[str, float] = {}
    interesting_paths: list[dict[str, Any]] = []


class SoulPropertyTestResponse(BaseModel):
    """Property testing response."""
    campaign_id: str
    status: str
    mode: str = "property"
    duration_sec: float = 0.0
    sequences_tested: int = 0
    properties_checked: int = 0
    property_violations: list[dict[str, Any]] = []
    violations_by_type: dict[str, int] = {}
    violations_by_severity: dict[str, int] = {}
    all_properties_held: bool = True
    score: float = 100.0


class SoulForgeStatusResponse(BaseModel):
    """Forge executor availability status."""
    forge_available: bool
    forge_version: str = ""
    forge_path: str = ""
    solc_available: bool = False
    solc_version: str = ""
    capabilities: list[str] = []


class SoulStaticScanResponse(BaseModel):
    """Static scan response."""
    contract_name: str
    findings: list[SoulFindingSummary]
    findings_count: int
    findings_by_severity: dict[str, int]
    findings_by_category: dict[str, int]
    detectors_run: int
    scan_duration_ms: int


class SoulProtocolModelResponse(BaseModel):
    """Protocol model response."""
    contracts: list[dict[str, Any]]
    invariants: list[dict[str, Any]]
    attack_surface: list[dict[str, Any]]
    fuzz_targets: list[dict[str, Any]]


class SoulFetchResponse(BaseModel):
    """Fetch response."""
    commit: str = ""
    branch: str = ""
    total_contracts: int = 0
    total_lines: int = 0
    categories: dict[str, int] = {}
    contracts: list[dict[str, str]] = []


# ── Campaign status helpers ──────────────────────────────────────────────────


def _compute_score(result: FuzzCampaignResult) -> float:
    """Compute a security score (0-100) from campaign results."""
    score = 100.0

    # Deduct for violations
    for v in result.violations:
        if v.severity.value == "critical":
            score -= 25
        elif v.severity.value == "high":
            score -= 15
        elif v.severity.value == "medium":
            score -= 8
        elif v.severity.value == "low":
            score -= 3

    # Deduct for static findings
    for f in result.static_findings:
        sev = f.get("severity", "")
        if sev in ("CRITICAL", "critical"):
            score -= 15
        elif sev in ("HIGH", "high"):
            score -= 8
        elif sev in ("MEDIUM", "medium"):
            score -= 4
        elif sev in ("LOW", "low"):
            score -= 2

    # Deduct for v2 findings
    for dos in getattr(result, 'dos_vectors', []):
        sev = dos.get('severity', 'medium') if isinstance(dos, dict) else 'medium'
        if sev in ('critical', 'CRITICAL'):
            score -= 12
        elif sev in ('high', 'HIGH'):
            score -= 6
        else:
            score -= 3

    for chain in getattr(result, 'exploit_chains', []):
        feasibility = chain.get('feasibility', 0) if isinstance(chain, dict) else 0
        if feasibility >= 0.8:
            score -= 20
        elif feasibility >= 0.5:
            score -= 10

    return max(0.0, min(100.0, score))


def _result_to_response(result: FuzzCampaignResult) -> SoulFuzzResponse:
    """Convert FuzzCampaignResult to API response."""
    violations = [
        SoulViolationSummary(
            invariant_id=v.invariant_id,
            invariant_desc=v.invariant_desc,
            severity=v.severity.value,
            mutation=v.mutation_chain[0] if v.mutation_chain else "",
            iteration=v.iteration,
            coverage_at_trigger=v.coverage_at_trigger,
            minimized=v.minimized,
            has_poc=v.poc_code is not None,
        )
        for v in result.violations
    ]

    static_findings = [
        SoulFindingSummary(
            id=f.get("id", ""),
            title=f.get("title", ""),
            severity=f.get("severity", ""),
            description=f.get("description", ""),
            category=f.get("category", ""),
            detector_id=f.get("detector_id", ""),
            remediation=f.get("remediation", ""),
            file_path=f.get("file_path", ""),
            start_line=f.get("location", {}).get("start_line", 0),
        )
        for f in result.static_findings
    ]

    return SoulFuzzResponse(
        campaign_id=result.campaign_id,
        status="completed",
        mode=result.mode.value,
        duration_sec=result.duration_sec,
        total_iterations=result.total_iterations,
        violations=violations,
        static_findings=static_findings,
        coverage=result.coverage,
        mutation_stats=result.mutation_stats,
        corpus_size=result.corpus_size,
        unique_paths=result.unique_paths,
        contracts_fuzzed=result.contracts_fuzzed,
        invariants_checked=result.invariants_checked,
        llm_insights=result.llm_insights,
        score=_compute_score(result),
        # Advanced fields
        symbolic_paths_explored=result.symbolic_paths_explored,
        concolic_generations=result.concolic_generations,
        concolic_new_coverage_pct=result.concolic_new_coverage_pct,
        differential_findings=result.differential_findings[:20],
        property_violations=result.property_violations[:20],
        forge_executions=result.forge_executions,
        power_schedule=result.power_schedule,
        corpus_stats=result.corpus_stats,
        llm_strategies=result.llm_strategies[:10],
        attack_hypotheses=result.attack_hypotheses[:10],
        total_findings=result.total_findings,
        # v2 engine fields
        bytecode_analysis=result.bytecode_analysis or {},
        taint_flows=result.taint_flows[:50],
        gas_profile=result.gas_profile or {},
        dos_vectors=result.dos_vectors[:20],
        synthesized_invariants=result.synthesized_invariants[:30],
        state_snapshots=result.state_snapshots,
        exploit_chains=result.exploit_chains[:20],
        taint_mutation_targets=result.taint_mutation_targets[:30],
    )


# ── Background task runner ────────────────────────────────────────────────────


async def _run_fuzz_campaign(
    campaign_id: str,
    fuzzer: SoulFuzzer,
    source_code: str,
    contract_name: str,
    source_files: dict[str, str] | None,
) -> None:
    """Run a fuzz campaign in the background and persist results to DB."""
    from engine.core.database import get_session_factory
    from datetime import datetime, timezone

    try:
        _campaigns[campaign_id]["status"] = "running"
        result = await fuzzer.run_campaign(source_code, contract_name, source_files)
        response = _result_to_response(result)
        _campaigns[campaign_id] = {
            "status": "completed",
            "result": result,
            "response": response,
        }

        # Persist to database
        try:
            async with get_session_factory()() as session:
                async with session.begin():
                    campaign = await session.get(SoulCampaign, campaign_id)
                    if not campaign:
                        campaign = SoulCampaign(id=campaign_id)
                        session.add(campaign)
                    campaign.status = "completed"
                    campaign.completed_at = datetime.now(timezone.utc)
                    campaign.duration_sec = result.duration_sec
                    campaign.total_iterations = result.total_iterations
                    campaign.violations_count = len(result.violations)
                    campaign.coverage = result.coverage
                    campaign.mutation_stats = result.mutation_stats
                    campaign.corpus_size = result.corpus_size
                    campaign.unique_paths = result.unique_paths
                    campaign.score = _compute_score(result)
                    campaign.result = response.model_dump()
                    campaign.bytecode_report = result.bytecode_analysis or {}
                    campaign.gas_profile = result.gas_profile or {}
                    campaign.exploit_chains = result.exploit_chains[:20]

                    # Persist violations as SoulFindings
                    for v in result.violations:
                        session.add(SoulFinding(
                            campaign_id=campaign_id,
                            title=f"Invariant violation: {v.invariant_id}",
                            description=v.invariant_desc,
                            severity=v.severity.value,
                            category="invariant_violation",
                            finding_type="violation",
                            poc_code=v.poc_code,
                            metadata={"iteration": v.iteration, "coverage": v.coverage_at_trigger},
                        ))

                    # Persist static findings
                    for f in result.static_findings:
                        session.add(SoulFinding(
                            campaign_id=campaign_id,
                            title=f.get("title", ""),
                            description=f.get("description", ""),
                            severity=f.get("severity", "MEDIUM"),
                            category=f.get("category", ""),
                            detector_id=f.get("detector_id", ""),
                            finding_type="static",
                            file_path=f.get("file_path", ""),
                            start_line=f.get("location", {}).get("start_line", 0),
                            remediation=f.get("remediation", ""),
                        ))
        except Exception as db_err:
            logger.warning("Failed to persist campaign %s to DB: %s", campaign_id, db_err)

    except Exception as e:
        logger.error("Campaign %s failed: %s\n%s", campaign_id, e, traceback.format_exc())
        _campaigns[campaign_id] = {
            "status": "failed",
            "error": str(e),
        }
        # Persist failure
        try:
            async with get_session_factory()() as session:
                async with session.begin():
                    campaign = await session.get(SoulCampaign, campaign_id)
                    if campaign:
                        campaign.status = "failed"
                        campaign.error_message = str(e)
        except Exception as persist_err:
            logger.warning("Failed to persist campaign failure status for %s: %s", campaign_id, persist_err)


# ── Routes ────────────────────────────────────────────────────────────────────


@router.post("/fuzz", response_model=SoulFuzzResponse)
async def start_fuzz_campaign(
    req: SoulFuzzRequest,
    background_tasks: BackgroundTasks,
    user: AuthUser = Depends(get_current_user),
) -> SoulFuzzResponse:
    """Start a Soul Protocol fuzzing campaign.

    Runs the full mutation-feedback fuzzer with 24 Soul-specific detectors,
    25 invariant checks, and 35+ mutation strategies.
    """
    mode_map = {
        "quick": FuzzMode.QUICK,
        "standard": FuzzMode.STANDARD,
        "deep": FuzzMode.DEEP,
        "targeted": FuzzMode.TARGETED,
    }

    config = FuzzCampaignConfig(
        mode=mode_map.get(req.mode, FuzzMode.STANDARD),
        max_duration_sec=req.max_duration_sec,
        max_iterations=req.max_iterations,
        target_contracts=req.target_functions,
        target_invariants=req.target_invariants,
        enable_llm_advisor=req.enable_llm,
        enable_static_pre_scan=req.enable_static_scan,
        enable_symbolic=req.enable_symbolic,
        enable_concolic=req.enable_concolic,
        enable_forge=req.enable_forge,
        enable_property_testing=req.enable_property_testing,
        enable_advanced_corpus=req.enable_advanced_corpus,
        enable_bytecode_analysis=req.enable_bytecode_analysis,
        enable_taint_analysis=req.enable_taint_analysis,
        enable_gas_profiling=req.enable_gas_profiling,
        enable_invariant_synthesis=req.enable_invariant_synthesis,
        enable_state_replay=req.enable_state_replay,
        enable_exploit_composition=req.enable_exploit_composition,
        power_schedule=req.power_schedule,
    )

    fuzzer = SoulFuzzer(config)

    # Decode optional bytecode for bytecode analysis
    bytecode_bytes = None
    if req.bytecode:
        try:
            bytecode_bytes = bytes.fromhex(req.bytecode.removeprefix("0x"))
        except ValueError:
            logger.warning("Invalid bytecode hex, skipping bytecode analysis")

    # For quick/standard, run synchronously for immediate response
    if config.mode in (FuzzMode.QUICK, FuzzMode.STANDARD):
        try:
            result = await fuzzer.run_campaign(
                req.source_code,
                req.contract_name,
                req.additional_sources or None,
                bytecode=bytecode_bytes,
            )
            return _result_to_response(result)
        except Exception as e:
            logger.error("Fuzz campaign failed: %s", e)
            raise HTTPException(500, detail=f"Fuzz campaign failed: {e}")

    # For deep/targeted, run in background
    campaign_id = fuzzer._generate_campaign_id(req.source_code)
    _campaigns[campaign_id] = {"status": "starting"}
    _fuzzers[campaign_id] = fuzzer

    # Persist initial campaign record to DB
    try:
        from engine.core.database import get_session_factory
        from datetime import datetime, timezone
        async with get_session_factory()() as session:
            async with session.begin():
                db_campaign = SoulCampaign(
                    status="starting",
                    mode=req.mode,
                    contract_name=req.contract_name,
                    source_code=req.source_code[:100_000],  # Limit stored source
                    config=config.__dict__ if hasattr(config, '__dict__') else {},
                    started_at=datetime.now(timezone.utc),
                )
                # Override the auto-generated UUID with the campaign_id
                import uuid as _uuid
                db_campaign.id = _uuid.UUID(campaign_id) if len(campaign_id) == 36 else db_campaign.id
                session.add(db_campaign)
    except Exception as db_err:
        logger.warning("Failed to persist initial campaign to DB: %s", db_err)

    background_tasks.add_task(
        _run_fuzz_campaign,
        campaign_id,
        fuzzer,
        req.source_code,
        req.contract_name,
        req.additional_sources or None,
    )

    return SoulFuzzResponse(
        campaign_id=campaign_id,
        status="starting",
        mode=config.mode.value,
    )


@router.post("/quick-fuzz", response_model=SoulFuzzResponse)
async def quick_fuzz(req: SoulQuickFuzzRequest, user: AuthUser = Depends(get_current_user)) -> SoulFuzzResponse:
    """Quick 60-second fuzz for rapid feedback."""
    fuzzer = SoulFuzzer(FuzzCampaignConfig.quick())
    try:
        result = await fuzzer.run_campaign(req.source_code, req.contract_name)
        return _result_to_response(result)
    except Exception as e:
        logger.error("Quick fuzz failed: %s", e)
        raise HTTPException(500, detail=f"Quick fuzz failed: {e}")


@router.post("/targeted-fuzz", response_model=SoulFuzzResponse)
async def targeted_fuzz(req: SoulTargetedFuzzRequest, user: AuthUser = Depends(get_current_user)) -> SoulFuzzResponse:
    """Fuzz a specific function or invariant."""
    config = FuzzCampaignConfig(
        mode=FuzzMode.TARGETED,
        max_duration_sec=req.max_duration_sec,
    )
    if req.target_function:
        config.target_contracts = [req.target_function]
    if req.target_invariant:
        config.target_invariants = [req.target_invariant]

    fuzzer = SoulFuzzer(config)
    try:
        result = await fuzzer.run_campaign(req.source_code, req.contract_name)
        return _result_to_response(result)
    except Exception as e:
        logger.error("Targeted fuzz failed: %s", e)
        raise HTTPException(500, detail=f"Targeted fuzz failed: {e}")


@router.post("/scan", response_model=SoulStaticScanResponse)
async def static_scan(req: SoulStaticScanRequest, user: AuthUser = Depends(get_current_user)) -> SoulStaticScanResponse:
    """Run static-only scan with all 24 Soul Protocol detectors."""
    from engine.analyzer.web3.base_detector import DetectorContext

    start = time.time()

    context = DetectorContext(
        contract_name=req.contract_name,
        source_code=req.source_code,
        lines=req.source_code.splitlines(),
        ast=None,
        cfg=None,
        taint_results=None,
        call_graph=None,
        slither_results=None,
    )

    findings: list[dict[str, Any]] = []
    for detector_cls in SOUL_DETECTORS:
        try:
            detector = detector_cls()
            result = detector.detect(context)
            findings.extend(result)
        except Exception as e:
            logger.warning("Detector %s failed: %s", detector_cls.__name__, e)

    elapsed_ms = int((time.time() - start) * 1000)

    # Count by severity and category
    by_severity: dict[str, int] = {}
    by_category: dict[str, int] = {}
    for f in findings:
        sev = f.get("severity", "UNKNOWN")
        by_severity[sev] = by_severity.get(sev, 0) + 1
        cat = f.get("category", "unknown")
        by_category[cat] = by_category.get(cat, 0) + 1

    finding_summaries = [
        SoulFindingSummary(
            id=f.get("id", ""),
            title=f.get("title", ""),
            severity=f.get("severity", ""),
            description=f.get("description", ""),
            category=f.get("category", ""),
            detector_id=f.get("detector_id", ""),
            remediation=f.get("remediation", ""),
            file_path=f.get("file_path", ""),
            start_line=f.get("location", {}).get("start_line", 0),
        )
        for f in findings
    ]

    return SoulStaticScanResponse(
        contract_name=req.contract_name,
        findings=finding_summaries,
        findings_count=len(findings),
        findings_by_severity=by_severity,
        findings_by_category=by_category,
        detectors_run=len(SOUL_DETECTORS),
        scan_duration_ms=elapsed_ms,
    )


@router.get("/campaign/{campaign_id}")
async def get_campaign(
    campaign_id: str,
    db: AsyncSession = Depends(get_db),
) -> dict[str, Any]:
    """Get campaign status and results (in-memory first, then DB fallback)."""
    # Check in-memory cache first (for active/recently completed campaigns)
    if campaign_id in _campaigns:
        campaign = _campaigns[campaign_id]
        status = campaign.get("status", "unknown")

        if status == "completed" and "response" in campaign:
            return campaign["response"].model_dump()

        if status == "running" and campaign_id in _fuzzers:
            return _fuzzers[campaign_id].get_campaign_status()

        if status == "failed":
            return {
                "status": "failed",
                "campaign_id": campaign_id,
                "error": campaign.get("error", "Unknown error"),
            }

        return {"status": status, "campaign_id": campaign_id}

    # Fallback to database for persisted campaigns
    try:
        import uuid as _uuid
        result = await db.execute(
            select(SoulCampaign).where(SoulCampaign.id == _uuid.UUID(campaign_id))
        )
        db_campaign = result.scalar_one_or_none()
        if db_campaign:
            if db_campaign.result:
                return db_campaign.result
            return {
                "campaign_id": campaign_id,
                "status": db_campaign.status,
                "mode": db_campaign.mode,
                "duration_sec": db_campaign.duration_sec,
                "total_iterations": db_campaign.total_iterations,
                "violations_count": db_campaign.violations_count,
                "score": db_campaign.score,
                "error": db_campaign.error_message,
            }
    except Exception as db_err:
        logger.debug("DB lookup for campaign %s failed: %s", campaign_id, db_err)

    raise HTTPException(404, detail="Campaign not found")


@router.get("/invariants")
async def list_invariants() -> list[dict[str, Any]]:
    """List all 25 Soul Protocol invariants checked by the fuzzer."""
    model = SoulProtocolModel()
    return [
        {
            "id": inv.id,
            "description": inv.description,
            "severity": inv.severity,
            "category": inv.category,
            "contracts": inv.contracts,
        }
        for inv in model.invariants
    ]


@router.get("/detectors")
async def list_detectors() -> list[dict[str, str]]:
    """List all 24 Soul Protocol-specific detectors."""
    return [
        {
            "id": getattr(d, "DETECTOR_ID", ""),
            "name": getattr(d, "NAME", d.__name__),
            "description": getattr(d, "DESCRIPTION", ""),
            "severity": getattr(d, "SEVERITY", "").value
                if hasattr(getattr(d, "SEVERITY", ""), "value") else "",
            "category": getattr(d, "CATEGORY", ""),
        }
        for d in SOUL_DETECTORS
    ]


@router.post("/fetch", response_model=SoulFetchResponse)
async def fetch_soul_contracts(req: SoulFetchRequest, user: AuthUser = Depends(get_current_user)) -> SoulFetchResponse:
    """Fetch Soul Protocol contracts from GitHub."""
    fetcher = SoulContractFetcher()

    try:
        if req.contract_name and req.with_dependencies:
            deps = await fetcher.fetch_with_dependencies(
                req.contract_name, req.branch,
            )
            return SoulFetchResponse(
                branch=req.branch,
                total_contracts=len(deps),
                contracts=[
                    {"name": name, "path": name}
                    for name in deps
                ],
            )

        if req.contract_name:
            contract = await fetcher.fetch_contract(req.contract_name, req.branch)
            if not contract:
                raise HTTPException(404, detail=f"Contract {req.contract_name} not found")
            return SoulFetchResponse(
                branch=req.branch,
                total_contracts=1,
                contracts=[{
                    "name": contract.name,
                    "path": contract.path,
                }],
            )

        if req.category:
            try:
                cat = SoulContractDir(req.category)
            except ValueError:
                raise HTTPException(400, detail=f"Unknown category: {req.category}")
            files = await fetcher.fetch_category(cat, req.branch)
            return SoulFetchResponse(
                branch=req.branch,
                total_contracts=len(files),
                categories={req.category: len(files)},
                contracts=[
                    {"name": f.name, "path": f.path}
                    for f in files
                ],
            )

        snapshot = await fetcher.fetch_all(req.branch)
        categories = {
            cat: len(files) for cat, files in snapshot.by_category.items()
        }
        return SoulFetchResponse(
            commit=snapshot.commit,
            branch=snapshot.branch,
            total_contracts=snapshot.total_contracts,
            total_lines=snapshot.total_lines,
            categories=categories,
            contracts=[
                {"name": f.name, "path": f.path}
                for f in snapshot.files[:100]  # Limit response size
            ],
        )

    except HTTPException:
        raise
    except Exception as e:
        logger.error("Fetch failed: %s", e)
        raise HTTPException(500, detail=f"Fetch failed: {e}")


@router.get("/protocol-model", response_model=SoulProtocolModelResponse)
async def get_protocol_model() -> SoulProtocolModelResponse:
    """Get the full Soul Protocol model used by the fuzzer."""
    model = SoulProtocolModel()

    contracts = [
        {
            "name": c.name,
            "category": c.category.value if hasattr(c.category, "value") else str(c.category),
            "functions": [
                {
                    "name": f.name,
                    "visibility": f.visibility,
                    "mutability": f.mutability,
                    "parameters": f.parameters,
                }
                for f in c.functions
            ],
            "state_variables": [
                {"name": sv.name, "type": sv.type}
                for sv in c.state_variables
            ],
        }
        for c in model.contracts
    ]

    invariants = [
        {
            "id": inv.id,
            "description": inv.description,
            "severity": inv.severity,
            "category": inv.category,
            "contracts": inv.contracts,
        }
        for inv in model.invariants
    ]

    attack_surface = model.get_attack_surface()
    fuzz_targets = model.get_fuzz_targets()

    return SoulProtocolModelResponse(
        contracts=contracts,
        invariants=invariants,
        attack_surface=attack_surface,
        fuzz_targets=fuzz_targets,
    )


# ── Advanced endpoints ────────────────────────────────────────────────────────


@router.post("/concolic", response_model=SoulConcolicResponse)
async def concolic_campaign(
    req: SoulConcolicRequest,
    background_tasks: BackgroundTasks,
    user: AuthUser = Depends(get_current_user),
) -> SoulConcolicResponse:
    """Run a concolic-driven fuzzing campaign.

    Uses SAGE-style generational search: concrete execution + symbolic
    constraint negation to systematically explore hard-to-reach paths.
    """
    config = FuzzCampaignConfig.concolic()
    config.max_duration_sec = req.max_duration_sec
    config.max_iterations = req.max_iterations
    config.enable_forge = req.enable_forge

    fuzzer = SoulFuzzer(config)

    try:
        result = await fuzzer.run_campaign(
            req.source_code,
            req.contract_name,
            req.additional_sources or None,
        )

        violations = [
            SoulViolationSummary(
                invariant_id=v.invariant_id,
                invariant_desc=v.invariant_desc,
                severity=v.severity.value,
                mutation=v.mutation_chain[0] if v.mutation_chain else "",
                iteration=v.iteration,
                coverage_at_trigger=v.coverage_at_trigger,
                minimized=v.minimized,
                has_poc=v.poc_code is not None,
            )
            for v in result.violations
        ]

        return SoulConcolicResponse(
            campaign_id=result.campaign_id,
            status="completed",
            duration_sec=result.duration_sec,
            total_iterations=result.total_iterations,
            violations=violations,
            coverage=result.coverage,
            concolic_generations=result.concolic_generations,
            concolic_new_coverage_pct=result.concolic_new_coverage_pct,
            symbolic_paths_explored=result.symbolic_paths_explored,
            corpus_size=result.corpus_size,
            unique_paths=result.unique_paths,
            score=_compute_score(result),
        )
    except Exception as e:
        logger.error("Concolic campaign failed: %s", e)
        raise HTTPException(500, detail=f"Concolic campaign failed: {e}")


@router.post("/differential", response_model=SoulDifferentialResponse)
async def differential_testing(req: SoulDifferentialRequest, user: AuthUser = Depends(get_current_user)) -> SoulDifferentialResponse:
    """Run cross-version differential testing.

    Compares behavior between two versions of a contract to detect
    state divergence, output mismatches, gas differences, and event changes.
    """
    config = FuzzCampaignConfig.differential()
    config.max_duration_sec = req.max_duration_sec
    config.contract_versions = [
        {"name": req.contract_name, "source": req.source_code, "label": "current"},
        {"name": req.previous_name, "source": req.previous_source, "label": "previous"},
    ]

    fuzzer = SoulFuzzer(config)

    try:
        result = await fuzzer.run_campaign(
            req.source_code,
            req.contract_name,
            req.additional_sources or None,
        )

        # Count findings by type and severity
        by_type: dict[str, int] = {}
        by_severity: dict[str, int] = {}
        for df in result.differential_findings:
            dt = df.get("diff_type", "unknown")
            by_type[dt] = by_type.get(dt, 0) + 1
            ds = df.get("severity", "medium")
            by_severity[ds] = by_severity.get(ds, 0) + 1

        divergence_pct = 0.0
        if result.total_iterations > 0:
            divergence_pct = len(result.differential_findings) / result.total_iterations * 100

        return SoulDifferentialResponse(
            campaign_id=result.campaign_id,
            status="completed",
            duration_sec=result.duration_sec,
            total_inputs_tested=result.total_iterations,
            differential_findings=result.differential_findings[:50],
            findings_by_type=by_type,
            findings_by_severity=by_severity,
            inputs_with_divergence_pct=round(divergence_pct, 2),
            score=_compute_score(result),
        )
    except Exception as e:
        logger.error("Differential testing failed: %s", e)
        raise HTTPException(500, detail=f"Differential testing failed: {e}")


@router.post("/symbolic", response_model=SoulSymbolicResponse)
async def symbolic_analysis(req: SoulSymbolicRequest, user: AuthUser = Depends(get_current_user)) -> SoulSymbolicResponse:
    """Run symbolic execution analysis.

    Explores reachable paths through constraint solving (Z3 or interval
    analysis fallback) and generates targeted seeds for fuzzing.
    """
    from engine.fuzzer.symbolic import SymbolicExecutor

    start = time.time()

    try:
        executor = SymbolicExecutor(max_depth=50, timeout_per_path=10.0)
        analysis = await asyncio.get_event_loop().run_in_executor(
            None, executor.analyze, req.source_code,
        )

        # Build targeted seeds
        seeds = executor.generate_targeted_seeds(analysis, max_seeds=100)

        # Compute per-function estimated coverage
        target_coverage: dict[str, float] = {}
        for func in analysis.get("functions", []):
            fname = func.get("name", "unknown")
            total_branches = func.get("total_branches", 1)
            explored = func.get("explored_branches", 0)
            target_coverage[fname] = explored / max(total_branches, 1)

        elapsed = time.time() - start

        return SoulSymbolicResponse(
            campaign_id=hashlib.md5(req.source_code.encode()).hexdigest()[:12],
            status="completed",
            duration_sec=round(elapsed, 2),
            paths_explored=analysis.get("total_paths", 0),
            constraints_generated=analysis.get("total_constraints", 0),
            seeds_generated=len(seeds),
            unreachable_branches=analysis.get("unreachable_branches", 0),
            target_coverage=target_coverage,
            interesting_paths=analysis.get("interesting_paths", [])[:20],
        )
    except Exception as e:
        logger.error("Symbolic analysis failed: %s", e)
        raise HTTPException(500, detail=f"Symbolic analysis failed: {e}")


import hashlib


@router.post("/property-test", response_model=SoulPropertyTestResponse)
async def property_test(req: SoulPropertyTestRequest, user: AuthUser = Depends(get_current_user)) -> SoulPropertyTestResponse:
    """Run cross-contract property verification.

    Tests protocol-level invariants across the 6-layer Soul architecture
    including fund conservation, nullifier consistency, bridge integrity, etc.
    """
    from engine.fuzzer.property_tester import CrossContractPropertyTester, PropertyType

    start = time.time()

    try:
        model = SoulProtocolModel()
        tester = CrossContractPropertyTester(
            protocol_model=model,
            max_sequences=req.max_sequences,
            max_seq_length=req.max_seq_length,
        )

        # Map property type strings to enums
        prop_types = []
        for pt_str in req.property_types:
            try:
                prop_types.append(PropertyType(pt_str))
            except ValueError:
                logger.warning("Unknown property type: %s", pt_str)

        test_result = await asyncio.get_event_loop().run_in_executor(
            None, tester.run, req.source_code, prop_types or None,
        )

        elapsed = time.time() - start

        # Aggregate violations
        violations_list = test_result.get("violations", [])
        by_type: dict[str, int] = {}
        by_severity: dict[str, int] = {}
        for pv in violations_list:
            pt = pv.get("property_type", "unknown")
            by_type[pt] = by_type.get(pt, 0) + 1
            ps = pv.get("severity", "medium")
            by_severity[ps] = by_severity.get(ps, 0) + 1

        return SoulPropertyTestResponse(
            campaign_id=hashlib.md5(req.source_code.encode()).hexdigest()[:12],
            status="completed",
            duration_sec=round(elapsed, 2),
            sequences_tested=test_result.get("sequences_tested", 0),
            properties_checked=test_result.get("properties_checked", 0),
            property_violations=violations_list[:50],
            violations_by_type=by_type,
            violations_by_severity=by_severity,
            all_properties_held=len(violations_list) == 0,
            score=max(0.0, 100.0 - len(violations_list) * 10),
        )
    except Exception as e:
        logger.error("Property testing failed: %s", e)
        raise HTTPException(500, detail=f"Property testing failed: {e}")


# ── v2 Standalone Engine Endpoints ────────────────────────────────────────────


class SoulBytecodeAnalysisRequest(BaseModel):
    """Standalone bytecode analysis request."""
    bytecode: str = Field(..., description="Hex-encoded EVM bytecode")
    contract_name: str = Field(default="SoulContract")


class SoulTaintAnalysisRequest(BaseModel):
    """Standalone taint analysis request."""
    source_code: str = Field(..., description="Solidity source code")
    contract_name: str = Field(default="SoulContract")
    target_functions: list[str] = Field(default_factory=list, description="Functions to analyze (all if empty)")


class SoulGasProfileRequest(BaseModel):
    """Standalone gas profiling request."""
    source_code: str = Field(..., description="Solidity source code")
    contract_name: str = Field(default="SoulContract")
    max_iterations: int = Field(default=5_000, ge=100, le=100_000)


@router.post("/bytecode-analysis")
async def bytecode_analysis(req: SoulBytecodeAnalysisRequest, user: AuthUser = Depends(get_current_user)) -> dict[str, Any]:
    """Run standalone EVM bytecode deep analysis.

    Disassembles bytecode into opcodes, builds CFG, extracts storage layout,
    detects delegate calls, matches Soul Protocol patterns, and generates
    coverage bitmaps.
    """
    start = time.time()

    try:
        bytecode_bytes = bytes.fromhex(req.bytecode.removeprefix("0x"))
    except ValueError:
        raise HTTPException(400, detail="Invalid hex-encoded bytecode")

    try:
        from engine.fuzzer.bytecode_analyzer import EVMBytecodeAnalyzer

        analyzer = EVMBytecodeAnalyzer()
        result = analyzer.analyze(bytecode_bytes)

        elapsed = time.time() - start
        return {
            "status": "completed",
            "contract_name": req.contract_name,
            "duration_sec": round(elapsed, 3),
            "functions": len(result.get("functions", {})),
            "basic_blocks": len(result.get("cfg", {}).get("blocks", [])),
            "cfg_edges": len(result.get("cfg", {}).get("edges", [])),
            "storage_layout": result.get("storage_layout", {}),
            "function_selectors": result.get("function_selectors", {}),
            "delegate_calls": result.get("delegate_calls", []),
            "soul_patterns": result.get("soul_patterns", []),
            "coverage_bitmap_size": result.get("coverage_bitmap_size", 0),
        }
    except ImportError:
        raise HTTPException(501, detail="Bytecode analyzer engine not available")
    except Exception as e:
        logger.error("Bytecode analysis failed: %s", e)
        raise HTTPException(500, detail=f"Bytecode analysis failed: {e}")


@router.post("/taint-analysis")
async def taint_analysis(req: SoulTaintAnalysisRequest, user: AuthUser = Depends(get_current_user)) -> dict[str, Any]:
    """Run standalone taint-guided dataflow analysis.

    Tracks data propagation from taint sources (user inputs, proof data,
    nullifiers) through operations to taint sinks (zk_verify, state writes,
    bridge relay) to identify sensitive flows and recommend mutations.
    """
    start = time.time()

    try:
        from engine.fuzzer.taint_mutator import TaintGuidedMutator

        mutator = TaintGuidedMutator()

        # Identify targets
        model = SoulProtocolModel()
        targets = model.get_fuzz_targets()

        if req.target_functions:
            targets = [t for t in targets if t.get("function", "") in req.target_functions]

        all_flows: list[dict[str, Any]] = []
        all_targets: list[dict[str, Any]] = []

        for target in targets:
            func_name = target.get("function", target.get("name", ""))
            if not func_name:
                continue

            result = mutator.analyze(
                source_code=req.source_code,
                function_name=func_name,
            )

            if result.get("flows"):
                all_flows.extend(result["flows"])
            if result.get("mutation_targets"):
                all_targets.extend(result["mutation_targets"])

        elapsed = time.time() - start

        return {
            "status": "completed",
            "contract_name": req.contract_name,
            "duration_sec": round(elapsed, 3),
            "total_flows": len(all_flows),
            "total_mutation_targets": len(all_targets),
            "flows": all_flows[:100],
            "mutation_targets": all_targets[:50],
            "critical_flows": [
                f for f in all_flows if f.get("criticality", "") == "critical"
            ][:20],
        }
    except ImportError:
        raise HTTPException(501, detail="Taint analysis engine not available")
    except Exception as e:
        logger.error("Taint analysis failed: %s", e)
        raise HTTPException(500, detail=f"Taint analysis failed: {e}")


@router.post("/gas-profile")
async def gas_profile(req: SoulGasProfileRequest, user: AuthUser = Depends(get_current_user)) -> dict[str, Any]:
    """Run standalone gas profiling and DoS vector detection.

    Profiles per-opcode gas consumption with Berlin/Shanghai costs,
    detects gas anomalies, and identifies functions vulnerable to
    gas-based denial-of-service attacks.
    """
    start = time.time()

    try:
        from engine.fuzzer.gas_profiler import GasProfilerEngine

        profiler = GasProfilerEngine()

        # Quick fuzz to generate traces
        config = FuzzCampaignConfig.quick()
        config.max_iterations = min(req.max_iterations, 5_000)
        config.max_duration_sec = 30

        fuzzer = SoulFuzzer(config)
        result = await fuzzer.run_campaign(req.source_code, req.contract_name)

        # Extract gas profile from result
        elapsed = time.time() - start

        gas_data = result.gas_profile or {}
        return {
            "status": "completed",
            "contract_name": req.contract_name,
            "duration_sec": round(elapsed, 3),
            "function_profiles": gas_data.get("functions", {}),
            "hotspots": gas_data.get("hotspots", []),
            "anomaly_count": gas_data.get("anomaly_count", 0),
            "dos_vectors": result.dos_vectors[:20],
            "total_gas_sampled": gas_data.get("total_gas", 0),
        }
    except ImportError:
        raise HTTPException(501, detail="Gas profiler engine not available")
    except Exception as e:
        logger.error("Gas profiling failed: %s", e)
        raise HTTPException(500, detail=f"Gas profiling failed: {e}")


@router.get("/engine-status")
async def engine_status() -> dict[str, Any]:
    """Check availability of all 13 fuzzing engines."""
    engines: dict[str, dict[str, Any]] = {}

    engine_imports = {
        "symbolic": "engine.fuzzer.symbolic.SymbolicExecutor",
        "concolic": "engine.fuzzer.concolic.ConcolicExecutor",
        "forge_executor": "engine.fuzzer.forge_executor.ForgeExecutor",
        "differential": "engine.fuzzer.differential.DifferentialTester",
        "llm_oracle": "engine.fuzzer.llm_oracle.LLMOracle",
        "property_tester": "engine.fuzzer.property_tester.CrossContractPropertyTester",
        "corpus_evolution": "engine.fuzzer.corpus_evolution.AdvancedCorpusManager",
        "bytecode_analyzer": "engine.fuzzer.bytecode_analyzer.EVMBytecodeAnalyzer",
        "taint_mutator": "engine.fuzzer.taint_mutator.TaintGuidedMutator",
        "gas_profiler": "engine.fuzzer.gas_profiler.GasProfilerEngine",
        "invariant_synth": "engine.fuzzer.invariant_synth.InvariantSynthesisEngine",
        "state_replay": "engine.fuzzer.state_replay.StateReplayEngine",
        "exploit_composer": "engine.fuzzer.exploit_composer.ExploitChainComposer",
    }

    for name, import_path in engine_imports.items():
        module_path, class_name = import_path.rsplit(".", 1)
        try:
            import importlib
            mod = importlib.import_module(module_path)
            cls = getattr(mod, class_name)
            engines[name] = {"available": True, "class": class_name}
        except Exception as e:
            engines[name] = {"available": False, "error": str(e)}

    available_count = sum(1 for e in engines.values() if e.get("available"))
    return {
        "total_engines": len(engines),
        "available": available_count,
        "unavailable": len(engines) - available_count,
        "engines": engines,
    }


@router.get("/campaign/{campaign_id}/stream")
async def stream_campaign(campaign_id: str, request: Request) -> StreamingResponse:
    """Server-Sent Events stream for live campaign updates.

    Sends periodic updates with:
      - iteration count
      - coverage percentages
      - violations found
      - current phase
      - corpus size
    """
    if campaign_id not in _campaigns and campaign_id not in _fuzzers:
        raise HTTPException(404, detail="Campaign not found")

    async def event_stream():
        last_iterations = 0
        while True:
            if await request.is_disconnected():
                break

            # Get live status
            if campaign_id in _fuzzers:
                status = _fuzzers[campaign_id].get_campaign_status()
            elif campaign_id in _campaigns:
                campaign = _campaigns[campaign_id]
                if campaign.get("status") == "completed" and "response" in campaign:
                    data = campaign["response"].model_dump()
                    data["status"] = "completed"
                    yield f"data: {json.dumps(data)}\n\n"
                    break
                elif campaign.get("status") == "failed":
                    yield f"data: {json.dumps({'status': 'failed', 'error': campaign.get('error', 'Unknown')})}\n\n"
                    break
                else:
                    status = {"status": campaign.get("status", "unknown")}
            else:
                yield f"data: {json.dumps({'status': 'not_found'})}\n\n"
                break

            iterations = status.get("iterations", 0)
            # Only send if there's new data
            if iterations != last_iterations or status.get("status") in ("completed", "failed"):
                yield f"data: {json.dumps(status)}\n\n"
                last_iterations = iterations

            if status.get("status") in ("completed", "failed"):
                break

            await asyncio.sleep(1.0)

    return StreamingResponse(
        event_stream(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )


@router.get("/forge-status", response_model=SoulForgeStatusResponse)
async def forge_status() -> SoulForgeStatusResponse:
    """Check Forge executor availability and capabilities."""
    forge_path = shutil.which("forge")
    solc_path = shutil.which("solc")

    forge_available = forge_path is not None
    forge_version = ""
    solc_version = ""
    capabilities = []

    if forge_available:
        capabilities.append("evm_execution")
        capabilities.append("invariant_testing")
        capabilities.append("fuzz_testing")
        capabilities.append("trace_analysis")
        capabilities.append("gas_reporting")
        try:
            import subprocess
            result = subprocess.run(
                [forge_path, "--version"],
                capture_output=True, text=True, timeout=5,
            )
            forge_version = result.stdout.strip().split("\n")[0] if result.stdout else ""
        except Exception as ver_err:
            logger.debug("Failed to detect forge version: %s", ver_err)

    if solc_path:
        capabilities.append("compilation")
        try:
            import subprocess
            result = subprocess.run(
                [solc_path, "--version"],
                capture_output=True, text=True, timeout=5,
            )
            lines = result.stdout.strip().split("\n")
            solc_version = lines[-1] if lines else ""
        except Exception as ver_err:
            logger.debug("Failed to detect solc version: %s", ver_err)

    return SoulForgeStatusResponse(
        forge_available=forge_available,
        forge_version=forge_version,
        forge_path=forge_path or "",
        solc_available=solc_path is not None,
        solc_version=solc_version,
        capabilities=capabilities,
    )


@router.get("/mutation-types")
async def list_mutation_types() -> list[dict[str, Any]]:
    """List all available mutation strategies with descriptions."""
    from engine.fuzzer.mutation_engine import MutationType

    descriptions = {
        "BOUNDARY": "Test boundary values (uint max, zero, overflow thresholds)",
        "ARITHMETIC": "Arithmetic mutations (add, sub, multiply, negate)",
        "BITFLIP": "Bit-level mutations for binary data",
        "BYTEFLIP": "Byte-level mutations for calldata/bytes fields",
        "INTERESTING_VALUE": "Known interesting constants (powers of 2, special addresses)",
        "FUNCTION_SELECTOR": "Mutate function selectors for unexpected dispatch",
        "ADDRESS": "Address mutations (zero, max, contract addresses)",
        "REENTRANCY": "Inject reentrant call patterns",
        "FLASH_LOAN": "Simulate flash loan attack sequences",
        "ORACLE_MANIPULATION": "Manipulate oracle price feed values",
        "TIMESTAMP": "Block timestamp and number manipulation",
        "GAS_LIMIT": "Gas limit edge case testing",
        "CALLDATA": "Raw calldata mutation",
        "STATE_CORRUPTION": "State variable corruption patterns",
        "CROSS_CONTRACT": "Cross-contract interaction mutations",
        "GRAMMAR_AWARE": "Soul Protocol grammar-aware mutations (deposit/withdraw/bridge/lock/swap templates)",
        "DICTIONARY": "Learned interesting values from previous executions",
        "SYMBOLIC_GUIDED": "Seeds from symbolic constraint solving (Z3/interval analysis)",
        "CONCOLIC_GUIDED": "Seeds from concolic execution branch negation",
        "LLM_GUIDED": "AI-generated mutation strategies (Claude/GPT-4o)",
        "HAVOC": "Stacked random mutations (2-8 operations)",
        "SPLICE": "Crossover between two corpus entries",
        "TYPE_CONFUSION": "Type confusion mutations (int↔address↔bytes↔bool)",
        "ABI_EDGE_CASE": "ABI encoding edge cases (huge arrays, empty strings, max offsets)",
        "STORAGE_COLLISION": "Storage slot collision patterns (EIP-1967 proxy slots)",
    }

    result = []
    for mt in MutationType:
        result.append({
            "id": mt.value,
            "name": mt.name,
            "description": descriptions.get(mt.value, mt.value),
        })
    return result


@router.get("/power-schedules")
async def list_power_schedules() -> list[dict[str, str]]:
    """List available power scheduling algorithms."""
    return [
        {
            "id": "fast",
            "name": "FAST",
            "description": "Frequency-based stochastic scheduling — favors rarely-hit paths (default)",
        },
        {
            "id": "coe",
            "name": "COE (Cut-Off Exponential)",
            "description": "Limits energy for high-frequency seeds, focuses on rare edge exploration",
        },
        {
            "id": "lin",
            "name": "LIN (Linear)",
            "description": "Linear scaling based on execution count — balanced explore/exploit",
        },
        {
            "id": "quad",
            "name": "QUAD (Quadratic)",
            "description": "Quadratic decay for well-explored seeds, aggressive on new seeds",
        },
        {
            "id": "exploit",
            "name": "EXPLOIT",
            "description": "Pure exploitation — maximizes energy for seeds nearest to violations",
        },
        {
            "id": "explore",
            "name": "EXPLORE",
            "description": "Pure exploration — uniform energy distribution across all seeds",
        },
        {
            "id": "mmopt",
            "name": "MMOPT (MOpt-Mutator)",
            "description": "Mutation-aware scheduling that adapts to mutator productivity",
        },
        {
            "id": "rare",
            "name": "RARE",
            "description": "Strongly favors seeds covering rare edges (exponential boost for rareness)",
        },
    ]
