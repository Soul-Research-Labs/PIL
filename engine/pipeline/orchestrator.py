"""Scan orchestrator — coordinates the smart contract analysis pipeline."""

from __future__ import annotations

import asyncio
import logging
import time
import uuid
from typing import Any


# ── Retry helper for transient S3 / DB failures ─────────────────────────────

# Exceptions considered transient and safe to retry
_TRANSIENT_MESSAGES = (
    "connection reset",
    "connection refused",
    "broken pipe",
    "timed out",
    "timeout",
    "temporarily unavailable",
    "too many connections",
    "could not connect",
    "operational error",
    "service unavailable",
    "throttl",
    "rate limit",
)


def _is_transient(exc: Exception) -> bool:
    """Return True if the exception looks transient (network / DB / S3)."""
    msg = str(exc).lower()
    return any(t in msg for t in _TRANSIENT_MESSAGES)


async def _retry_async(
    coro_factory,  # callable returning a coroutine
    *,
    max_retries: int = 3,
    base_delay: float = 1.0,
    max_delay: float = 15.0,
    label: str = "operation",
):
    """Retry an async operation with exponential back-off on transient errors."""
    last_exc: Exception | None = None
    for attempt in range(max_retries + 1):
        try:
            return await coro_factory()
        except Exception as exc:
            last_exc = exc
            if attempt >= max_retries or not _is_transient(exc):
                raise
            delay = min(base_delay * (2 ** attempt), max_delay)
            logging.getLogger(__name__).warning(
                "Transient error in %s (attempt %d/%d), retrying in %.1fs: %s",
                label, attempt + 1, max_retries, delay, exc,
            )
            await asyncio.sleep(delay)
    raise last_exc  # unreachable but keeps mypy happy


def _retry_sync(
    fn,  # callable
    *,
    max_retries: int = 3,
    base_delay: float = 1.0,
    max_delay: float = 15.0,
    label: str = "operation",
):
    """Retry a synchronous operation with exponential back-off on transient errors."""
    last_exc: Exception | None = None
    for attempt in range(max_retries + 1):
        try:
            return fn()
        except Exception as exc:
            last_exc = exc
            if attempt >= max_retries or not _is_transient(exc):
                raise
            delay = min(base_delay * (2 ** attempt), max_delay)
            logging.getLogger(__name__).warning(
                "Transient error in %s (attempt %d/%d), retrying in %.1fs: %s",
                label, attempt + 1, max_retries, delay, exc,
            )
            time.sleep(delay)
    raise last_exc  # unreachable but keeps mypy happy

from engine.analyzer.web3.analyzer import Web3Analyzer
from engine.core.config import get_settings
from engine.core.types import (
    FindingSchema,
    ScanResult,
    ScanStatus,
    ScanType,
    SecurityScore,
    Severity,
)
from engine.ingestion.contract_fetcher import ContractFetcher
from engine.ingestion.github import GitHubIngester
from engine.ingestion.solidity_compiler import SolidityCompiler
from engine.reports.generator import ReportGenerator
from engine.verifier.poc_generator import VerificationEngine


class ScanOrchestrator:
    """Coordinates the smart contract scan pipeline.

    Full scan flow:
    1. CLONING — Ingest source (GitHub clone or contract fetch)
    2. COMPILING — Compile Solidity contracts
    3. ANALYZING — Run static detectors
    4. DEEP_ANALYSIS — Run LLM-powered deep vulnerability analysis
    5. VERIFYING — Generate and execute Foundry PoCs
    6. COMPLETED — Calculate scores and store results
    """

    def __init__(self, enable_llm: bool = True) -> None:
        self._settings = get_settings()
        self._web3_analyzer = Web3Analyzer(enable_llm=enable_llm)
        self._compiler = SolidityCompiler()
        self._contract_fetcher = ContractFetcher()
        self._github = GitHubIngester()
        self._verifier = VerificationEngine()
        self._reporter = ReportGenerator()

    async def run(
        self,
        scan_id: str,
        project_id: str,
        config: dict[str, Any],
        task: Any = None,
    ) -> dict:
        """Run a full smart contract scan pipeline."""
        results: list[ScanResult] = []

        try:
            # Step 1: Ingest
            self._update_status(task, "CLONING")
            source_data = await self._ingest(config)

            source_code = source_data.get("source_code", "")
            compilation = source_data.get("compilation")
            contract_source = source_data.get("contract_source")

            if not source_code:
                raise ValueError("No Solidity source code found to analyze")

            # Step 2: Compile (if not already done during ingestion)
            self._update_status(task, "COMPILING")
            if not compilation:
                compilation = self._compiler.compile_source(source_code)

            # Step 3+4: Analyze with static detectors + LLM deep analysis
            self._update_status(task, "ANALYZING")
            web3_result = self._web3_analyzer.analyze(
                source_code=source_code,
                compilation=compilation,
                contract_source=contract_source,
                scan_id=scan_id,
                enable_llm=True,
            )
            results.append(web3_result)

            # Merge results
            merged = self._merge_results(results, scan_id)

            # Step 5: Verify high-confidence findings with PoC generation
            self._update_status(task, "VERIFYING")
            critical_high = [
                f for f in merged.findings
                if f.severity in (Severity.CRITICAL, Severity.HIGH) and f.confidence >= 0.7
            ]

            if critical_high:
                verified = await self._verifier.verify_findings(
                    critical_high,
                    source_code,
                    is_smart_contract=True,
                    max_concurrent=3,
                )
                # Merge verified findings back
                verified_map = {id(f): f for f in verified}
                for i, f in enumerate(merged.findings):
                    if id(f) in verified_map:
                        merged.findings[i] = verified_map[id(f)]

            # Recalculate score after verification (discarded findings removed from penalty)
            score = SecurityScore.calculate(merged.findings)
            merged.security_score = score.score
            merged.threat_score = score.threat_score

            self._update_status(task, "COMPLETED")

            return self._result_to_dict(merged)

        except Exception as e:
            self._update_status(task, "FAILED")
            raise

    async def run_quickscan(
        self,
        request: dict[str, Any],
        task: Any = None,
    ) -> dict:
        """Run a quick scan on an address or source code.

        Quick scans run static detectors only (no LLM, no PoC verification).
        """
        scan_id = str(uuid.uuid4())

        if request.get("address"):
            # Fetch contract from blockchain
            self._update_status(task, "CLONING")
            chain = request.get("chain", "ethereum")
            contract_source = await self._contract_fetcher.fetch_contract_source(
                request["address"], chain
            )

            source_code = contract_source.source_code
            self._update_status(task, "COMPILING")
            compilation = self._compiler.compile_source(source_code)

            self._update_status(task, "ANALYZING")
            result = self._web3_analyzer.analyze(
                source_code=source_code,
                compilation=compilation,
                contract_source=contract_source,
                scan_id=scan_id,
                enable_llm=False,  # Quick scan — no LLM
            )

        elif request.get("source_code"):
            source_code = request["source_code"]

            self._update_status(task, "COMPILING")
            compilation = self._compiler.compile_source(source_code)

            self._update_status(task, "ANALYZING")
            result = self._web3_analyzer.analyze(
                source_code=source_code,
                compilation=compilation,
                scan_id=scan_id,
                enable_llm=False,  # Quick scan — no LLM
            )
        else:
            raise ValueError("Either 'address' or 'source_code' is required")

        self._update_status(task, "COMPLETED")
        return self._result_to_dict(result)

    async def run_deep_scan(
        self,
        request: dict[str, Any],
        task: Any = None,
    ) -> dict:
        """Run a deep scan with LLM analysis and PoC verification.

        Full pipeline: ingest → compile → static + LLM → PoC verify.
        """
        scan_id = str(uuid.uuid4())
        config = {
            "source_type": "contract" if request.get("address") else "upload",
            **request,
        }
        if request.get("address"):
            config["contract_address"] = request["address"]

        return await self.run(
            scan_id=scan_id,
            project_id=request.get("project_id", ""),
            config=config,
            task=task,
        )

    async def verify_scan_findings(
        self,
        scan_id: str,
        finding_ids: list[str],
    ) -> dict:
        """Verify specific findings from a scan by running Foundry PoC execution."""
        from engine.core.database import get_session_factory
        from engine.models.scan import Finding, Scan

        async with get_session_factory()() as session:
            from sqlalchemy import select

            # Load the scan
            scan = await session.get(Scan, uuid.UUID(scan_id))
            if not scan:
                return {"scan_id": scan_id, "error": "Scan not found", "verified": 0}

            # Load the specified findings
            result = await session.execute(
                select(Finding).where(
                    Finding.scan_id == uuid.UUID(scan_id),
                    Finding.id.in_([uuid.UUID(fid) for fid in finding_ids]),
                )
            )
            findings = list(result.scalars().all())

            if not findings:
                return {"scan_id": scan_id, "verified": 0, "message": "No findings matched"}

            # Convert DB findings to FindingSchema for verification
            finding_schemas = [
                FindingSchema(
                    id=str(f.id),
                    title=f.title,
                    description=f.description,
                    severity=Severity(f.severity) if f.severity in [s.value for s in Severity] else Severity.MEDIUM,
                    category=f.category,
                    location={"file": f.file_path, "start_line": f.start_line, "end_line": f.end_line},
                    remediation=f.remediation,
                    confidence=f.cvss_score / 10.0 if f.cvss_score else 0.5,
                )
                for f in findings
            ]

            # Run PoC verification
            verified = await self._verifier.verify_findings(
                finding_schemas, "", is_smart_contract=True, max_concurrent=2
            )

            # Update findings in DB
            for f_schema in verified:
                for f_db in findings:
                    if str(f_db.id) == f_schema.id and hasattr(f_schema, "poc_script"):
                        f_db.poc_script = getattr(f_schema, "poc_script", None)
                        f_db.poc_output = getattr(f_schema, "poc_output", None)

            await _retry_async(
                lambda: session.commit(),
                max_retries=3,
                label="DB commit (verify findings)",
            )

        return {"scan_id": scan_id, "verified": len(verified)}

    async def generate_scan_report(
        self,
        scan_id: str,
        format: str = "pdf",
    ) -> dict:
        """Generate a report for a completed scan."""
        from engine.core.database import get_session_factory
        from engine.models.scan import Finding, Report, Scan

        async with get_session_factory()() as session:
            from sqlalchemy import select
            from sqlalchemy.orm import selectinload

            # Load scan with findings
            result = await session.execute(
                select(Scan).where(Scan.id == uuid.UUID(scan_id)).options(selectinload(Scan.findings))
            )
            scan = result.scalar_one_or_none()
            if not scan:
                return {"scan_id": scan_id, "error": "Scan not found"}

            # Build ScanResult from DB
            scan_result = ScanResult(
                scan_id=scan_id,
                scan_type=ScanType.SMART_CONTRACT,
                status=ScanStatus.COMPLETED,
                findings=[
                    FindingSchema(
                        id=str(f.id), title=f.title, description=f.description,
                        severity=Severity(f.severity) if f.severity in [s.value for s in Severity] else Severity.MEDIUM,
                        category=f.category,
                        location={"file": f.file_path, "start_line": f.start_line, "end_line": f.end_line},
                        remediation=f.remediation, confidence=f.cvss_score / 10.0 if f.cvss_score else 0.5,
                    )
                    for f in scan.findings
                ],
                security_score=scan.security_score or 0.0,
                threat_score=scan.threat_score or 0.0,
            )

            # Generate the report
            if format == "pdf":
                import tempfile
                output_path = f"/tmp/zaseon_report_{scan_id}.{format}"
                output = self._reporter.generate_pdf(scan_result, output_path=output_path)
                # Read the generated file for upload
                with open(output_path, "rb") as f:
                    output = f.read()
            elif format == "html":
                output = self._reporter.generate_html(scan_result)
            elif format == "json":
                output = self._reporter.generate_json(scan_result)
            elif format == "sarif":
                output = self._reporter.generate_sarif(scan_result)
            else:
                output = self._reporter.generate_pdf(scan_result)

            # Upload to S3 if available (with retry for transient failures)
            file_key = f"reports/{scan_id}/{uuid.uuid4()}.{format}"
            try:
                import boto3
                settings = get_settings()
                s3 = boto3.client(
                    "s3",
                    endpoint_url=settings.s3_endpoint,
                    aws_access_key_id=settings.s3_access_key,
                    aws_secret_access_key=settings.s3_secret_key,
                )
                body = output if isinstance(output, bytes) else output.encode()
                _retry_sync(
                    lambda: s3.put_object(Bucket=settings.s3_bucket_reports, Key=file_key, Body=body),
                    max_retries=3,
                    label="S3 report upload",
                )
            except Exception as s3_err:
                logging.getLogger(__name__).warning("S3 report upload failed (best-effort): %s", s3_err)

            # Update report record if one exists
            report_result = await session.execute(
                select(Report).where(Report.scan_id == uuid.UUID(scan_id)).order_by(Report.created_at.desc())
            )
            report = report_result.scalar_one_or_none()
            if report:
                report.file_key = file_key
                report.file_size_bytes = len(output) if output else 0
                await _retry_async(
                    lambda: session.commit(),
                    max_retries=3,
                    label="DB commit (report update)",
                )

        return {"scan_id": scan_id, "format": format, "status": "generated", "file_key": file_key}

    async def _ingest(self, config: dict[str, Any]) -> dict:
        """Ingest Solidity source code based on configuration."""
        source_type = config.get("source_type", "contract")
        result: dict[str, Any] = {}

        if source_type == "github":
            github_url = config["github_url"]
            branch = config.get("branch", "main")
            clone_path = await self._github.clone_repo(github_url, branch=branch)
            file_tree = self._github.get_file_tree(clone_path)

            # Only read Solidity files
            sol_files: dict[str, str] = {}
            for fpath in file_tree:
                if fpath.endswith(".sol"):
                    try:
                        full_path = clone_path / fpath
                        sol_files[fpath] = full_path.read_text(errors="replace")
                    except Exception as e:
                        logging.getLogger(__name__).debug("Failed to read %s: %s", fpath, e)
                        continue

            if sol_files:
                result["source_code"] = "\n".join(sol_files.values())
                compilation = self._compiler.compile_source(result["source_code"])
                result["compilation"] = compilation

        elif source_type == "contract":
            address = config["contract_address"]
            chain = config.get("chain", "ethereum")
            contract_source = await self._contract_fetcher.fetch_contract_source(address, chain)
            result["contract_source"] = contract_source
            result["source_code"] = contract_source.source_code

            compilation = self._compiler.compile_source(contract_source.source_code)
            result["compilation"] = compilation

        elif source_type == "upload":
            result["source_code"] = config.get("source_code", "")

        return result

    def _merge_results(self, results: list[ScanResult], scan_id: str) -> ScanResult:
        """Merge multiple scan results into one."""
        if not results:
            return ScanResult(
                scan_id=scan_id,
                scan_type=ScanType.SMART_CONTRACT,
                status=ScanStatus.COMPLETED,
                findings=[],
                gas_optimizations=[],
                security_score=100,
                threat_score=0,
                total_lines_scanned=0,
                scan_duration_seconds=0,
            )

        if len(results) == 1:
            return results[0]

        all_findings: list[FindingSchema] = []
        all_gas = []
        total_lines = 0
        total_duration = 0.0

        for r in results:
            all_findings.extend(r.findings)
            all_gas.extend(r.gas_optimizations)
            total_lines += r.total_lines_scanned
            total_duration += r.scan_duration_seconds

        score = SecurityScore.calculate(all_findings)

        return ScanResult(
            scan_id=scan_id,
            scan_type=ScanType.SMART_CONTRACT,
            status=ScanStatus.COMPLETED,
            findings=all_findings,
            gas_optimizations=all_gas,
            security_score=score.score,
            threat_score=score.threat_score,
            total_lines_scanned=total_lines,
            scan_duration_seconds=total_duration,
            metadata={"merged_from": len(results)},
        )

    def _result_to_dict(self, result: ScanResult) -> dict:
        """Convert ScanResult to serializable dict with LLM analysis metadata."""
        meta = result.metadata or {}

        # Severity summary
        severity_counts: dict[str, int] = {}
        for f in result.findings:
            sev = f.severity.value
            severity_counts[sev] = severity_counts.get(sev, 0) + 1

        return {
            "scan_id": result.scan_id,
            "scan_type": result.scan_type.value,
            "status": result.status.value,
            "security_score": result.security_score,
            "threat_score": result.threat_score,
            "total_lines_scanned": result.total_lines_scanned,
            "scan_duration_seconds": result.scan_duration_seconds,
            "total_findings": len(result.findings),
            "severity_summary": severity_counts,
            "findings": [
                {
                    "title": f.title,
                    "description": f.description,
                    "severity": f.severity.value,
                    "category": f.category,
                    "cwe_id": f.cwe_id,
                    "scwe_id": f.scwe_id,
                    "location": {
                        "file": f.location.file_path,
                        "start_line": f.location.start_line,
                        "end_line": f.location.end_line,
                        "snippet": f.location.snippet,
                    },
                    "remediation": f.remediation,
                    "proof_of_concept": f.poc_script,
                    "confidence": f.confidence,
                    "status": f.status.value if f.status else "open",
                    "metadata": f.metadata,
                }
                for f in result.findings
            ],
            "gas_optimizations": [
                {
                    "description": g.description,
                    "suggestion": g.suggestion,
                    "estimated_gas_saved": g.estimated_gas_saved,
                    "category": g.category,
                }
                for g in result.gas_optimizations
            ],
            # LLM analysis metadata
            "analysis": {
                "static_findings_count": meta.get("static_findings_count", 0),
                "llm_findings_count": meta.get("llm_findings_count", 0),
                "total_after_dedup": meta.get("total_findings_after_dedup", 0),
                "llm_overall_risk": meta.get("llm_overall_risk"),
                "llm_attack_surface": meta.get("llm_attack_surface"),
                "llm_invariants": meta.get("llm_invariants"),
                "llm_contract_summary": meta.get("llm_contract_summary"),
                "llm_token_usage": meta.get("llm_token_usage"),
                "findings_by_category": meta.get("findings_by_category", {}),
                "detectors_run": meta.get("detectors_run", []),
            },
            "metadata": meta,
        }

    def _update_status(self, task: Any, step: str) -> None:
        """Update Celery task state."""
        if task:
            task.update_state(state="PROGRESS", meta={"step": step})
