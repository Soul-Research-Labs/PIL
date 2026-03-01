"""QuickScan endpoint — instant contract scanning by address or source."""

from __future__ import annotations

import logging
import time
import traceback
from typing import Any

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession

from engine.core.database import get_db
from engine.api.middleware.auth import get_current_user, get_current_user_optional
from engine.models.user import User
from engine.core.chains import get_chain_config, get_all_chains
from engine.core.types import Severity
from engine.pipeline.orchestrator import ScanOrchestrator

logger = logging.getLogger(__name__)

router = APIRouter()


# ── Schemas ──────────────────────────────────────────────────────────────────


class QuickScanRequest(BaseModel):
    """Request to perform a quick scan of a deployed contract."""

    contract_address: str = Field(
        ..., pattern=r"^0x[a-fA-F0-9]{40}$", description="Contract address (0x...)"
    )
    chain: str = Field(..., description="Chain identifier (e.g., 'ethereum', 'polygon')")


class QuickScanFileScanRequest(BaseModel):
    """Request to scan an uploaded Solidity source."""

    source_code: str
    filename: str = "Contract.sol"
    compiler_version: str | None = None


class DeepScanRequest(BaseModel):
    """Request to perform a deep LLM-powered scan."""

    contract_address: str | None = Field(
        None, pattern=r"^0x[a-fA-F0-9]{40}$", description="Contract address"
    )
    chain: str = "ethereum"
    source_code: str | None = None
    filename: str = "Contract.sol"
    project_id: str | None = None


class QuickScanFindingSummary(BaseModel):
    """Summarized finding for QuickScan results."""

    title: str
    severity: str
    scwe_id: str = ""
    description: str
    location: str = ""
    remediation: str = ""
    confidence: float = 0.8
    category: str = ""
    metadata: dict[str, Any] = {}


class GasOptimizationSummary(BaseModel):
    """Gas optimization item."""
    description: str = ""
    suggestion: str = ""
    estimated_gas_saved: int = 0
    category: str = ""


class AnalysisMetadata(BaseModel):
    """Metadata about the analysis pipeline."""
    static_findings_count: int = 0
    llm_findings_count: int = 0
    total_after_dedup: int = 0
    llm_overall_risk: str | None = None
    llm_attack_surface: list[str] | None = None
    llm_contract_summary: str | None = None
    detectors_run: list[str] = []
    findings_by_category: dict[str, int] = {}


class QuickScanResponse(BaseModel):
    """QuickScan result summary."""

    scan_id: str = ""
    contract_address: str | None = None
    chain: str | None = None
    contract_name: str = ""
    compiler_version: str = ""
    security_score: float = 100.0
    threat_score: float = 0.0
    findings_count: int = 0
    findings_by_severity: dict[str, int] = {}
    findings: list[QuickScanFindingSummary] = []
    gas_optimizations: list[GasOptimizationSummary] = []
    gas_optimizations_count: int = 0
    lines_of_code: int = 0
    scan_duration_ms: int = 0
    analysis: AnalysisMetadata = AnalysisMetadata()


class ChainInfo(BaseModel):
    """Supported chain information."""

    chain_id: int
    name: str
    short_name: str
    explorer_url: str


# ── Helpers ──────────────────────────────────────────────────────────────────


def _pipeline_result_to_response(
    raw: dict[str, Any],
    address: str | None = None,
    chain: str | None = None,
    duration_ms: int = 0,
) -> QuickScanResponse:
    """Convert pipeline result dict → QuickScanResponse."""
    findings = []
    for f in raw.get("findings", []):
        loc = f.get("location", {})
        loc_str = ""
        if loc.get("file"):
            loc_str = f"{loc['file']}:{loc.get('start_line', 0)}"
        findings.append(QuickScanFindingSummary(
            title=f.get("title", ""),
            severity=f.get("severity", "informational"),
            scwe_id=f.get("scwe_id", ""),
            description=f.get("description", ""),
            location=loc_str,
            remediation=f.get("remediation", ""),
            confidence=f.get("confidence", 0.8),
            category=f.get("category", ""),
            metadata=f.get("metadata", {}),
        ))

    gas_opts = [
        GasOptimizationSummary(**g) for g in raw.get("gas_optimizations", [])
    ]

    analysis_raw = raw.get("analysis", {})
    analysis = AnalysisMetadata(
        static_findings_count=analysis_raw.get("static_findings_count", 0),
        llm_findings_count=analysis_raw.get("llm_findings_count", 0),
        total_after_dedup=analysis_raw.get("total_after_dedup", 0),
        llm_overall_risk=analysis_raw.get("llm_overall_risk"),
        llm_attack_surface=analysis_raw.get("llm_attack_surface"),
        llm_contract_summary=analysis_raw.get("llm_contract_summary"),
        detectors_run=analysis_raw.get("detectors_run", []),
        findings_by_category=analysis_raw.get("findings_by_category", {}),
    )

    return QuickScanResponse(
        scan_id=raw.get("scan_id", ""),
        contract_address=address,
        chain=chain,
        contract_name=raw.get("metadata", {}).get("contract_name", ""),
        compiler_version=raw.get("metadata", {}).get("compiler_version", ""),
        security_score=raw.get("security_score", 100.0),
        threat_score=raw.get("threat_score", 0.0),
        findings_count=raw.get("total_findings", len(findings)),
        findings_by_severity=raw.get("severity_summary", {}),
        findings=findings,
        gas_optimizations=gas_opts,
        gas_optimizations_count=len(gas_opts),
        lines_of_code=raw.get("total_lines_scanned", 0),
        scan_duration_ms=duration_ms or int(raw.get("scan_duration_seconds", 0) * 1000),
        analysis=analysis,
    )


# ── Routes ───────────────────────────────────────────────────────────────────


@router.get("/chains", response_model=list[ChainInfo])
async def list_supported_chains() -> list[ChainInfo]:
    """List all supported blockchain networks."""
    return [
        ChainInfo(
            chain_id=c.chain_id,
            name=c.name,
            short_name=c.short_name,
            explorer_url=c.explorer_url,
        )
        for c in get_all_chains()
    ]


@router.post("/address", response_model=QuickScanResponse)
async def quickscan_by_address(
    payload: QuickScanRequest,
    background_tasks: BackgroundTasks,
    user: User = Depends(get_current_user),
) -> QuickScanResponse:
    """Perform a QuickScan on a deployed contract by address + chain.

    Fetches verified source code from the block explorer, compiles it,
    runs the full static detector suite, and returns a summary report.
    """
    chain_config = get_chain_config(payload.chain)
    if not chain_config:
        raise HTTPException(
            status_code=400,
            detail=f"Unsupported chain: {payload.chain}. Use GET /chains for supported chains.",
        )

    t0 = time.time()
    try:
        orchestrator = ScanOrchestrator(enable_llm=False)
        raw = await orchestrator.run_quickscan({
            "address": payload.contract_address,
            "chain": payload.chain,
        })
    except Exception as exc:
        logger.error("QuickScan by address failed: %s\n%s", exc, traceback.format_exc())
        raise HTTPException(status_code=500, detail=f"Scan failed: {exc}") from exc

    duration_ms = int((time.time() - t0) * 1000)
    return _pipeline_result_to_response(raw, address=payload.contract_address, chain=payload.chain, duration_ms=duration_ms)


@router.post("/source", response_model=QuickScanResponse)
async def quickscan_by_source(
    payload: QuickScanFileScanRequest,
    user: User = Depends(get_current_user),
) -> QuickScanResponse:
    """Perform a QuickScan on uploaded Solidity source code."""
    if not payload.source_code.strip():
        raise HTTPException(status_code=400, detail="Source code cannot be empty")

    t0 = time.time()
    try:
        orchestrator = ScanOrchestrator(enable_llm=False)
        raw = await orchestrator.run_quickscan({
            "source_code": payload.source_code,
            "filename": payload.filename,
        })
    except Exception as exc:
        logger.error("QuickScan by source failed: %s\n%s", exc, traceback.format_exc())
        raise HTTPException(status_code=500, detail=f"Scan failed: {exc}") from exc

    duration_ms = int((time.time() - t0) * 1000)
    return _pipeline_result_to_response(raw, duration_ms=duration_ms)


@router.post("/deep", response_model=QuickScanResponse)
async def deep_scan(
    payload: DeepScanRequest,
    user: User = Depends(get_current_user),
) -> QuickScanResponse:
    """Perform a deep scan with LLM analysis and PoC verification.

    This runs the full pipeline: static detectors → LLM deep analysis
    (5-pass: summarize, vulnerability, cross-contract, economic, invariant)
    → PoC generation for high-confidence findings.
    """
    if not payload.contract_address and not payload.source_code:
        raise HTTPException(status_code=400, detail="Provide either contract_address or source_code")

    t0 = time.time()
    try:
        orchestrator = ScanOrchestrator(enable_llm=True)
        request: dict[str, Any] = {}
        if payload.contract_address:
            request["address"] = payload.contract_address
            request["chain"] = payload.chain
        else:
            request["source_code"] = payload.source_code
            request["filename"] = payload.filename
        if payload.project_id:
            request["project_id"] = payload.project_id

        raw = await orchestrator.run_deep_scan(request)
    except Exception as exc:
        logger.error("Deep scan failed: %s\n%s", exc, traceback.format_exc())
        raise HTTPException(status_code=500, detail=f"Deep scan failed: {exc}") from exc

    duration_ms = int((time.time() - t0) * 1000)
    return _pipeline_result_to_response(
        raw,
        address=payload.contract_address,
        chain=payload.chain,
        duration_ms=duration_ms,
    )
