"""Celery tasks — async scan pipeline orchestration."""

from __future__ import annotations

import asyncio
import traceback
from typing import Any

from engine.pipeline import celery_app


def _run_async(coro):
    """Helper to run async code in sync Celery tasks."""
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()


@celery_app.task(bind=True, name="engine.pipeline.tasks.run_scan")
def run_scan(self, scan_id: str, project_id: str, scan_config: dict[str, Any]) -> dict:
    """Run a smart contract security scan.

    Pipeline:
    1. Ingest source (clone repo / fetch contract)
    2. Compile Solidity contracts
    3. Analyze (Web3 detectors + LLM analysis)
    4. Verify findings (Foundry PoC execution)
    5. Generate report
    6. Store results
    """
    from engine.pipeline.orchestrator import ScanOrchestrator

    self.update_state(state="STARTED", meta={"step": "initializing"})

    try:
        orchestrator = ScanOrchestrator()
        result = _run_async(orchestrator.run(scan_id, project_id, scan_config, self))
        return result
    except Exception as e:
        self.update_state(state="FAILURE", meta={"error": str(e), "traceback": traceback.format_exc()})
        raise


@celery_app.task(bind=True, name="engine.pipeline.tasks.run_quickscan")
def run_quickscan(self, request: dict[str, Any]) -> dict:
    """Run a quick scan (address or source code)."""
    from engine.pipeline.orchestrator import ScanOrchestrator

    self.update_state(state="STARTED", meta={"step": "initializing"})

    try:
        orchestrator = ScanOrchestrator()
        result = _run_async(orchestrator.run_quickscan(request, self))
        return result
    except Exception as e:
        self.update_state(state="FAILURE", meta={"error": str(e)})
        raise


@celery_app.task(bind=True, name="engine.pipeline.tasks.verify_findings")
def verify_findings(self, scan_id: str, finding_ids: list[str]) -> dict:
    """Verify specific findings with PoC execution."""
    from engine.pipeline.orchestrator import ScanOrchestrator

    try:
        orchestrator = ScanOrchestrator()
        result = _run_async(orchestrator.verify_scan_findings(scan_id, finding_ids))
        return result
    except Exception as e:
        self.update_state(state="FAILURE", meta={"error": str(e)})
        raise


@celery_app.task(bind=True, name="engine.pipeline.tasks.generate_report")
def generate_report(self, scan_id: str, format: str = "pdf") -> dict:
    """Generate a report for a completed scan."""
    from engine.pipeline.orchestrator import ScanOrchestrator

    try:
        orchestrator = ScanOrchestrator()
        result = _run_async(orchestrator.generate_scan_report(scan_id, format))
        return result
    except Exception as e:
        self.update_state(state="FAILURE", meta={"error": str(e)})
        raise


@celery_app.task(
    bind=True,
    name="engine.pipeline.tasks.run_soul_campaign",
    time_limit=3600,
    soft_time_limit=1800,
)
def run_soul_campaign(self, campaign_id: str, config: dict[str, Any]) -> dict:
    """Run a Soul Protocol fuzzing campaign via Celery.

    Supports the full 18-phase pipeline with all 13 engines.
    """
    import logging

    logger = logging.getLogger(__name__)
    self.update_state(state="STARTED", meta={"step": "initializing", "campaign_id": campaign_id})

    try:
        from engine.fuzzer.soul_fuzzer import SoulFuzzer, FuzzCampaignConfig, FuzzMode

        source_code = config.pop("source_code", "")
        contract_name = config.pop("contract_name", "SoulContract")
        mode = config.pop("mode", "standard")

        fuzz_config = FuzzCampaignConfig(
            source_code=source_code,
            contract_name=contract_name,
            mode=FuzzMode(mode) if mode in [m.value for m in FuzzMode] else FuzzMode.STANDARD,
            max_duration_sec=config.get("max_duration_sec", 300),
            max_iterations=config.get("max_iterations", 50_000),
            enable_llm=config.get("enable_llm", True),
            enable_symbolic=config.get("enable_symbolic", True),
            enable_concolic=config.get("enable_concolic", True),
            enable_forge=config.get("enable_forge", True),
        )

        fuzzer = SoulFuzzer()
        result = _run_async(fuzzer.run_campaign(fuzz_config))

        self.update_state(state="SUCCESS", meta={"campaign_id": campaign_id})
        return result if isinstance(result, dict) else {"campaign_id": campaign_id, "status": "completed"}

    except Exception as e:
        logger.error("Soul campaign %s failed: %s", campaign_id, e)
        self.update_state(state="FAILURE", meta={"error": str(e), "campaign_id": campaign_id})
        raise


@celery_app.task(
    bind=True,
    name="engine.pipeline.tasks.run_soul_quickfuzz",
    time_limit=120,
    soft_time_limit=90,
)
def run_soul_quickfuzz(self, campaign_id: str, source_code: str, contract_name: str = "SoulContract") -> dict:
    """Run a quick 60-second Soul fuzz via Celery."""
    self.update_state(state="STARTED", meta={"step": "quick_fuzz", "campaign_id": campaign_id})

    try:
        from engine.fuzzer.soul_fuzzer import SoulFuzzer, FuzzCampaignConfig, FuzzMode

        config = FuzzCampaignConfig(
            source_code=source_code,
            contract_name=contract_name,
            mode=FuzzMode.QUICK,
            max_duration_sec=60,
            max_iterations=5000,
        )

        fuzzer = SoulFuzzer()
        result = _run_async(fuzzer.run_campaign(config))

        return result if isinstance(result, dict) else {"campaign_id": campaign_id, "status": "completed"}

    except Exception as e:
        self.update_state(state="FAILURE", meta={"error": str(e), "campaign_id": campaign_id})
        raise
