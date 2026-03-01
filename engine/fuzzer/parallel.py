"""Parallel fuzzing across multiple Forge instances.

Spawns N independent ``ForgeExecutor`` workers, each with its own
temporary Foundry project directory.  Corpus seeds are partitioned
across workers, and coverage bitmaps are merged periodically to
distribute novel-path discoveries.

Architecture::

    ParallelFuzzer
     ├─ Worker-0  (ForgeExecutor + seed partition[0])
     ├─ Worker-1  (ForgeExecutor + seed partition[1])
     ├─ …
     └─ Worker-N  (ForgeExecutor + seed partition[N])
            │
            └─ periodic coverage merge  ──► global bitmap
"""

from __future__ import annotations

import asyncio
import logging
import math
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from engine.fuzzer.forge_executor import (
    ForgeConfig,
    ForgeExecutor,
    ForgeExecutionResult,
    ForgeProjectManager,
)

logger = logging.getLogger(__name__)


# ── Configuration ────────────────────────────────────────────────────────────


class MergeStrategy(Enum):
    """How to redistribute coverage information across workers."""
    UNION = "union"          # simple set-union of coverage bitmaps
    WEIGHTED = "weighted"    # favour high-coverage workers for seed donation


@dataclass
class ParallelFuzzerConfig:
    """Settings for the parallel fuzzing pool."""
    num_workers: int = 4
    merge_interval_sec: float = 15.0
    merge_strategy: MergeStrategy = MergeStrategy.UNION
    # Per-worker Forge config (cloned per worker)
    forge_config: ForgeConfig = field(default_factory=ForgeConfig.default)
    # Campaign budget
    total_iterations: int = 10_000
    total_timeout_sec: float = 600.0
    # Seed corpus
    initial_seeds: list[dict[str, Any]] = field(default_factory=list)


@dataclass
class WorkerState:
    """Runtime state for one parallel worker."""
    worker_id: int
    iterations: int = 0
    coverage_bitmap: set[str] = field(default_factory=set)
    findings: list[dict[str, Any]] = field(default_factory=list)
    last_new_coverage_at: float = 0.0
    # Tracks seeds assigned to this worker
    seed_queue: list[dict[str, Any]] = field(default_factory=list)
    # Status
    active: bool = True
    error: str | None = None


@dataclass
class ParallelFuzzResult:
    """Merged result of a parallel fuzzing campaign."""
    total_iterations: int = 0
    total_coverage_paths: int = 0
    merged_coverage_bitmap: set[str] = field(default_factory=set)
    findings: list[dict[str, Any]] = field(default_factory=list)
    worker_stats: list[dict[str, Any]] = field(default_factory=list)
    elapsed_sec: float = 0.0
    merge_count: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "total_iterations": self.total_iterations,
            "total_coverage_paths": self.total_coverage_paths,
            "findings_count": len(self.findings),
            "elapsed_sec": round(self.elapsed_sec, 2),
            "merge_count": self.merge_count,
            "worker_stats": self.worker_stats,
        }


# ── Parallel Fuzzer ──────────────────────────────────────────────────────────


class ParallelFuzzer:
    """Coordinate N Forge-backed fuzzing workers in parallel.

    Usage::

        config = ParallelFuzzerConfig(num_workers=4)
        fuzzer = ParallelFuzzer(config)
        result = await fuzzer.run(
            source_code="...",
            contract_name="Token",
            abi=[...],
        )
    """

    def __init__(self, config: ParallelFuzzerConfig) -> None:
        self.config = config
        self._workers: list[WorkerState] = []
        self._global_bitmap: set[str] = set()
        self._running = False
        self._merge_count = 0

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def run(
        self,
        source_code: str,
        contract_name: str,
        abi: list[dict[str, Any]],
        source_filename: str = "",
    ) -> ParallelFuzzResult:
        """Execute a parallel fuzzing campaign.

        Creates *num_workers* independent Forge projects, partitions
        seed corpus, runs workers concurrently, and merges coverage.
        """
        if not source_filename:
            source_filename = f"{contract_name}.sol"

        start = time.monotonic()
        self._running = True
        num = self.config.num_workers

        # Partition seeds round-robin
        partitions: list[list[dict[str, Any]]] = [[] for _ in range(num)]
        for i, seed in enumerate(self.config.initial_seeds):
            partitions[i % num].append(seed)

        # Initialise worker states
        self._workers = [
            WorkerState(
                worker_id=i,
                seed_queue=partitions[i],
                last_new_coverage_at=start,
            )
            for i in range(num)
        ]

        # Launch workers + merge loop concurrently
        worker_tasks = [
            asyncio.create_task(
                self._worker_loop(
                    w, source_code, contract_name,
                    source_filename, abi,
                )
            )
            for w in self._workers
        ]

        merge_task = asyncio.create_task(self._merge_loop())

        # Wait for all workers to finish (or timeout)
        try:
            await asyncio.wait_for(
                asyncio.gather(*worker_tasks, return_exceptions=True),
                timeout=self.config.total_timeout_sec,
            )
        except asyncio.TimeoutError:
            logger.info("Parallel fuzzer reached timeout after %.0fs",
                        self.config.total_timeout_sec)

        self._running = False
        merge_task.cancel()
        try:
            await merge_task
        except asyncio.CancelledError:
            pass

        return self._build_result(time.monotonic() - start)

    # ------------------------------------------------------------------
    # Worker loop
    # ------------------------------------------------------------------

    async def _worker_loop(
        self,
        worker: WorkerState,
        source_code: str,
        contract_name: str,
        source_filename: str,
        abi: list[dict[str, Any]],
    ) -> None:
        """Run fuzzing iterations in a dedicated Forge project."""
        cfg = ForgeConfig(
            solc_version=self.config.forge_config.solc_version,
            evm_version=self.config.forge_config.evm_version,
            optimizer_runs=self.config.forge_config.optimizer_runs,
            gas_limit=self.config.forge_config.gas_limit,
            fork_url=self.config.forge_config.fork_url,
            fork_block=self.config.forge_config.fork_block,
            test_timeout=self.config.forge_config.test_timeout,
        )

        project_mgr = ForgeProjectManager(cfg)
        try:
            project_mgr.init_project({source_filename: source_code})
        except Exception as exc:
            worker.error = f"Project init failed: {exc}"
            worker.active = False
            return

        executor = ForgeExecutor(cfg)
        executor._project_manager = project_mgr  # reuse the initialised project

        iters_per_worker = math.ceil(
            self.config.total_iterations / self.config.num_workers
        )

        try:
            for iteration in range(iters_per_worker):
                if not self._running:
                    break

                # Pick a seed (cycle through queue + donated seeds)
                seed = self._pick_seed(worker, iteration, abi)

                result = await self._execute_one(
                    executor, worker, seed, contract_name, source_filename,
                )

                if result is None:
                    continue

                worker.iterations += 1

                # Track coverage
                new_paths = result.coverage_bitmap - worker.coverage_bitmap
                if new_paths:
                    worker.coverage_bitmap.update(new_paths)
                    worker.last_new_coverage_at = time.monotonic()

                # Track findings (reverts that indicate violations)
                if result.reverted and result.revert_reason:
                    worker.findings.append({
                        "worker": worker.worker_id,
                        "iteration": iteration,
                        "revert_reason": result.revert_reason,
                        "gas_used": result.gas_used,
                        "seed": seed,
                    })

        except Exception as exc:
            worker.error = str(exc)
            logger.exception("Worker %d failed", worker.worker_id)
        finally:
            worker.active = False
            project_mgr.cleanup()

    # ------------------------------------------------------------------
    # Seed selection
    # ------------------------------------------------------------------

    def _pick_seed(
        self,
        worker: WorkerState,
        iteration: int,
        abi: list[dict[str, Any]],
    ) -> dict[str, Any]:
        """Select next seed for a worker: cycle queue → generate random."""
        if worker.seed_queue:
            return worker.seed_queue[iteration % len(worker.seed_queue)]

        # Fall back to a minimal random seed derived from ABI
        mutators = [
            item for item in abi
            if item.get("type") == "function"
            and item.get("stateMutability") not in ("view", "pure")
        ]
        if mutators:
            target_fn = mutators[iteration % len(mutators)]
            return {
                "function": target_fn["name"],
                "inputs": {
                    p.get("name", f"arg{j}"): 0
                    for j, p in enumerate(target_fn.get("inputs", []))
                },
            }
        return {"function": "fallback", "inputs": {}}

    # ------------------------------------------------------------------
    # Execution wrapper
    # ------------------------------------------------------------------

    async def _execute_one(
        self,
        executor: ForgeExecutor,
        worker: WorkerState,
        seed: dict[str, Any],
        contract_name: str,
        source_filename: str,
    ) -> ForgeExecutionResult | None:
        """Execute a single seed via the worker's ForgeExecutor."""
        try:
            # Use the executor's compile+run cycle
            result = await asyncio.to_thread(
                executor.execute,
                function_name=seed.get("function", ""),
                inputs=seed.get("inputs", {}),
                sender=seed.get("from", ""),
                value=seed.get("value", 0),
            )
            return result
        except Exception as exc:
            logger.debug("Worker %d execution error: %s", worker.worker_id, exc)
            return None

    # ------------------------------------------------------------------
    # Coverage merge loop
    # ------------------------------------------------------------------

    async def _merge_loop(self) -> None:
        """Periodically merge coverage bitmaps across workers."""
        while self._running:
            await asyncio.sleep(self.config.merge_interval_sec)
            self._merge_coverage()
            self._merge_count += 1

    def _merge_coverage(self) -> None:
        """Merge all workers' coverage into the global bitmap and
        distribute novel paths back to workers with smaller coverage.
        """
        # Collect global union
        combined: set[str] = set()
        for w in self._workers:
            combined.update(w.coverage_bitmap)

        new_global = combined - self._global_bitmap
        if new_global:
            logger.info(
                "Coverage merge #%d: +%d new paths (total %d)",
                self._merge_count + 1, len(new_global), len(combined),
            )
            self._global_bitmap = combined

            if self.config.merge_strategy == MergeStrategy.UNION:
                # Broadcast all novel paths to every worker
                for w in self._workers:
                    novel_for_w = combined - w.coverage_bitmap
                    if novel_for_w:
                        w.coverage_bitmap.update(novel_for_w)

            elif self.config.merge_strategy == MergeStrategy.WEIGHTED:
                # Only donate to workers with below-median coverage
                coverage_sizes = sorted(
                    len(w.coverage_bitmap) for w in self._workers
                )
                median = coverage_sizes[len(coverage_sizes) // 2]
                for w in self._workers:
                    if len(w.coverage_bitmap) < median:
                        w.coverage_bitmap.update(combined - w.coverage_bitmap)

    # ------------------------------------------------------------------
    # Result assembly
    # ------------------------------------------------------------------

    def _build_result(self, elapsed: float) -> ParallelFuzzResult:
        """Assemble final result from all workers."""
        merged_bitmap: set[str] = set()
        all_findings: list[dict[str, Any]] = []
        total_iters = 0
        worker_stats: list[dict[str, Any]] = []

        for w in self._workers:
            merged_bitmap.update(w.coverage_bitmap)
            all_findings.extend(w.findings)
            total_iters += w.iterations
            worker_stats.append({
                "worker_id": w.worker_id,
                "iterations": w.iterations,
                "coverage_paths": len(w.coverage_bitmap),
                "findings": len(w.findings),
                "error": w.error,
            })

        return ParallelFuzzResult(
            total_iterations=total_iters,
            total_coverage_paths=len(merged_bitmap),
            merged_coverage_bitmap=merged_bitmap,
            findings=all_findings,
            worker_stats=worker_stats,
            elapsed_sec=elapsed,
            merge_count=self._merge_count,
        )
