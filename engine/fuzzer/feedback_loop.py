"""Coverage-guided feedback loop for Soul Protocol fuzzing.

Tracks code coverage, manages the corpus of interesting inputs,
and implements the core fuzz loop with adaptive mutation selection.

Architecture:
  ┌─────────────────────────────────────────────────────────┐
  │                   FEEDBACK LOOP                         │
  │                                                         │
  │  ┌──────┐    ┌──────────┐    ┌──────────┐    ┌──────┐ │
  │  │Corpus│───►│Mutation  │───►│Execution │───►│Cover-│ │
  │  │      │◄───│Engine    │    │(Forge)   │    │age   │ │
  │  │      │    │          │    │          │    │Track │ │
  │  └──────┘    └──────────┘    └──────────┘    └──┬───┘ │
  │      ▲                                          │      │
  │      │           ┌──────────┐                   │      │
  │      └───────────│Invariant │◄──────────────────┘      │
  │                  │Checker   │                          │
  │                  └──────────┘                          │
  └─────────────────────────────────────────────────────────┘
"""

from __future__ import annotations

import hashlib
import json
import logging
import time
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any

from engine.fuzzer.mutation_engine import (
    FuzzCampaignStats,
    MutationResult,
    MutationSeed,
    MutationType,
    SoulMutationEngine,
)

logger = logging.getLogger(__name__)


# ── Coverage Tracking ────────────────────────────────────────────────────────


@dataclass
class CoverageMap:
    """Tracks code coverage for the fuzzing campaign."""

    # Branch coverage: (file, line, branch_taken) → hit count
    branch_hits: dict[str, int] = field(default_factory=lambda: defaultdict(int))

    # Line coverage: (file, line) → bool
    line_hits: set[str] = field(default_factory=set)

    # Function coverage: (contract, function) → hit count
    function_hits: dict[str, int] = field(default_factory=lambda: defaultdict(int))

    # Path coverage: hash of execution path → count
    path_hashes: set[str] = field(default_factory=set)

    # Revert reason coverage
    revert_reasons: set[str] = field(default_factory=set)

    # Total lines in target
    total_lines: int = 0
    total_branches: int = 0
    total_functions: int = 0

    def record_execution(
        self,
        lines: list[int] | None = None,
        branches: list[tuple[int, bool]] | None = None,
        functions: list[str] | None = None,
        path_hash: str = "",
        revert_reason: str = "",
    ) -> bool:
        """Record coverage from an execution. Returns True if new coverage found."""
        new_coverage = False

        if lines:
            for line in lines:
                key = str(line)
                if key not in self.line_hits:
                    new_coverage = True
                    self.line_hits.add(key)

        if branches:
            for line, taken in branches:
                key = f"{line}:{taken}"
                if self.branch_hits[key] == 0:
                    new_coverage = True
                self.branch_hits[key] += 1

        if functions:
            for func in functions:
                if self.function_hits[func] == 0:
                    new_coverage = True
                self.function_hits[func] += 1

        if path_hash and path_hash not in self.path_hashes:
            new_coverage = True
            self.path_hashes.add(path_hash)

        if revert_reason and revert_reason not in self.revert_reasons:
            new_coverage = True
            self.revert_reasons.add(revert_reason)

        return new_coverage

    @property
    def line_coverage(self) -> float:
        """Percentage of lines covered."""
        if self.total_lines == 0:
            return 0.0
        return len(self.line_hits) / self.total_lines * 100

    @property
    def branch_coverage(self) -> float:
        """Percentage of branches covered."""
        if self.total_branches == 0:
            return 0.0
        covered = sum(1 for v in self.branch_hits.values() if v > 0)
        return covered / self.total_branches * 100

    @property
    def function_coverage(self) -> float:
        """Percentage of functions covered."""
        if self.total_functions == 0:
            return 0.0
        covered = sum(1 for v in self.function_hits.values() if v > 0)
        return covered / self.total_functions * 100

    @property
    def path_count(self) -> int:
        """Number of unique execution paths discovered."""
        return len(self.path_hashes)

    def to_dict(self) -> dict[str, Any]:
        """Serialize coverage data."""
        return {
            "line_coverage": round(self.line_coverage, 2),
            "branch_coverage": round(self.branch_coverage, 2),
            "function_coverage": round(self.function_coverage, 2),
            "unique_paths": self.path_count,
            "lines_covered": len(self.line_hits),
            "total_lines": self.total_lines,
            "branches_covered": sum(1 for v in self.branch_hits.values() if v > 0),
            "total_branches": self.total_branches,
            "functions_covered": sum(1 for v in self.function_hits.values() if v > 0),
            "total_functions": self.total_functions,
            "unique_revert_reasons": len(self.revert_reasons),
            "revert_reasons": list(self.revert_reasons)[:20],
        }


# ── Corpus Management ────────────────────────────────────────────────────────


class FuzzCorpus:
    """Manages the corpus of interesting seeds for fuzzing.

    Seeds are kept if they:
    - Discover new coverage (lines, branches, paths)
    - Trigger new revert reasons
    - Violate invariants
    - Are diverse (different mutation strategies)

    Implements energy-based scheduling (seeds with more potential
    get more mutations).
    """

    def __init__(self, max_size: int = 10000) -> None:
        self.seeds: list[MutationSeed] = []
        self.max_size = max_size
        self._seed_energy: dict[str, float] = {}
        self._seed_results: dict[str, list[MutationResult]] = defaultdict(list)
        self._interesting_seeds: set[str] = set()
        self._coverage_map = CoverageMap()

    @property
    def coverage(self) -> CoverageMap:
        """Access the coverage map."""
        return self._coverage_map

    def add_seed(self, seed: MutationSeed, interesting: bool = False) -> None:
        """Add a seed to the corpus."""
        if len(self.seeds) >= self.max_size:
            self._evict_least_interesting()

        self.seeds.append(seed)
        self._seed_energy[seed.id] = 1.0 + (2.0 if interesting else 0.0)
        if interesting:
            self._interesting_seeds.add(seed.id)

    def record_result(self, result: MutationResult) -> bool:
        """Record a mutation result. Returns True if result is interesting."""
        self._seed_results[result.seed.id].append(result)

        interesting = False

        # New coverage is always interesting
        if result.new_coverage:
            interesting = True
            self._boost_energy(result.seed.id, 2.0)

        # Invariant violations are very interesting
        if result.invariant_violated:
            interesting = True
            self._boost_energy(result.seed.id, 5.0)

        # New revert reasons are interesting
        if result.reverted and result.revert_reason:
            if result.revert_reason not in self._coverage_map.revert_reasons:
                interesting = True
                self._boost_energy(result.seed.id, 1.5)

        # Decay energy for uninteresting results
        if not interesting:
            self._decay_energy(result.seed.id, 0.95)

        return interesting

    def select_seed(self) -> MutationSeed:
        """Select a seed for mutation using energy-based scheduling.

        Higher energy seeds are more likely to be selected.
        """
        if not self.seeds:
            raise ValueError("Corpus is empty")

        # Weighted selection by energy
        energies = [self._seed_energy.get(s.id, 1.0) for s in self.seeds]
        total = sum(energies)
        if total == 0:
            # All seeds have 0 energy — uniform random
            import random
            return random.choice(self.seeds)

        normalized = [e / total for e in energies]
        import random
        return random.choices(self.seeds, weights=normalized, k=1)[0]

    def _boost_energy(self, seed_id: str, factor: float) -> None:
        """Boost energy of a seed (found something interesting)."""
        current = self._seed_energy.get(seed_id, 1.0)
        self._seed_energy[seed_id] = min(current * factor, 100.0)

    def _decay_energy(self, seed_id: str, factor: float) -> None:
        """Decay energy of a seed (nothing interesting)."""
        current = self._seed_energy.get(seed_id, 1.0)
        self._seed_energy[seed_id] = max(current * factor, 0.01)

    def _evict_least_interesting(self) -> None:
        """Remove the least interesting seed when corpus is full."""
        if not self.seeds:
            return

        # Don't evict interesting seeds
        evictable = [
            s for s in self.seeds if s.id not in self._interesting_seeds
        ]
        if not evictable:
            evictable = self.seeds  # Last resort

        # Find lowest energy seed
        min_seed = min(evictable, key=lambda s: self._seed_energy.get(s.id, 0))
        self.seeds.remove(min_seed)
        self._seed_energy.pop(min_seed.id, None)
        self._seed_results.pop(min_seed.id, None)

    def get_stats(self) -> dict[str, Any]:
        """Get corpus statistics."""
        return {
            "total_seeds": len(self.seeds),
            "interesting_seeds": len(self._interesting_seeds),
            "total_executions": sum(
                len(results) for results in self._seed_results.values()
            ),
            "avg_energy": (
                sum(self._seed_energy.values()) / len(self._seed_energy)
                if self._seed_energy else 0
            ),
            "max_generation": max(
                (s.generation for s in self.seeds), default=0
            ),
        }


# ── Invariant Checker ────────────────────────────────────────────────────────


class SoulInvariantChecker:
    """Checks Soul Protocol invariants against execution results.

    Each invariant is a property that must always hold.
    The checker evaluates execution traces against these properties.
    """

    def __init__(self) -> None:
        self._invariant_checks: dict[str, Any] = {}
        self._register_checks()

    def _register_checks(self) -> None:
        """Register all invariant checking functions."""
        self._invariant_checks = {
            "SOUL-INV-001": self._check_nullifier_uniqueness,
            "SOUL-INV-002": self._check_domain_separation,
            "SOUL-INV-003": self._check_batch_atomicity,
            "SOUL-INV-010": self._check_proof_required_for_unlock,
            "SOUL-INV-011": self._check_no_double_unlock,
            "SOUL-INV-012": self._check_owner_only_cancel,
            "SOUL-INV-013": self._check_state_preservation,
            "SOUL-INV-020": self._check_invalid_proof_rejected,
            "SOUL-INV-030": self._check_pool_balance,
            "SOUL-INV-031": self._check_merkle_update,
            "SOUL-INV-032": self._check_valid_root,
            "SOUL-INV-033": self._check_no_inflation,
            "SOUL-INV-040": self._check_no_duplicate_relay,
            "SOUL-INV-041": self._check_swap_fund_safety,
            "SOUL-INV-042": self._check_circuit_breaker,
            "SOUL-INV-060": self._check_access_control,
            "SOUL-INV-070": self._check_rate_limiting,
            "SOUL-INV-080": self._check_flash_loan_guard,
            "SOUL-INV-090": self._check_storage_layout,
        }

    def check_all(
        self,
        result: MutationResult,
        state_before: dict[str, Any],
        state_after: dict[str, Any],
    ) -> list[str]:
        """Check all invariants against an execution result.

        Returns list of violated invariant IDs.
        """
        violations = []

        for inv_id, check_fn in self._invariant_checks.items():
            try:
                violated = check_fn(result, state_before, state_after)
                if violated:
                    violations.append(inv_id)
                    logger.warning(
                        "Invariant %s violated by seed %s (mutation: %s)",
                        inv_id, result.seed.id, result.mutation_type.value,
                    )
            except Exception as e:
                logger.debug("Invariant check %s error: %s", inv_id, e)

        return violations

    def check_specific(
        self,
        invariant_ids: list[str],
        result: MutationResult,
        state_before: dict[str, Any],
        state_after: dict[str, Any],
    ) -> list[str]:
        """Check specific invariants only."""
        violations = []
        for inv_id in invariant_ids:
            check_fn = self._invariant_checks.get(inv_id)
            if check_fn:
                try:
                    if check_fn(result, state_before, state_after):
                        violations.append(inv_id)
                except Exception as e:
                    logger.debug("Invariant check %s failed: %s", inv_id, e)
        return violations

    # ── Invariant check implementations ──────────────────────────────

    def _check_nullifier_uniqueness(
        self, result: MutationResult, before: dict, after: dict
    ) -> bool:
        """SOUL-INV-001: No nullifier registered twice."""
        if result.seed.inputs.get("_nullifier_replay") or result.seed.inputs.get("_double_execute"):
            # If the double-execute succeeded without revert, invariant violated
            if not result.reverted and result.mutation_type in (
                MutationType.REPLAY_NULLIFIER, MutationType.DOUBLE_EXECUTE
            ):
                return True
        return False

    def _check_domain_separation(
        self, result: MutationResult, before: dict, after: dict
    ) -> bool:
        """SOUL-INV-002: Domain-separated nullifiers unique per domain."""
        if result.seed.inputs.get("_cross_domain_test"):
            # Cross-domain test succeeded unexpectedly
            if not result.reverted and result.mutation_type == MutationType.CROSS_DOMAIN_COLLISION:
                # Check if same nullifier was accepted on different domain
                return True
        return False

    def _check_batch_atomicity(
        self, result: MutationResult, before: dict, after: dict
    ) -> bool:
        """SOUL-INV-003: Batch operations must be atomic."""
        if result.mutation_type == MutationType.PARTIAL_BATCH_REPLAY:
            # Partial batch should revert entirely
            if not result.reverted:
                return True
        return False

    def _check_proof_required_for_unlock(
        self, result: MutationResult, before: dict, after: dict
    ) -> bool:
        """SOUL-INV-010: Invalid proofs must not unlock state."""
        if result.mutation_type in (
            MutationType.CORRUPT_PROOF, MutationType.TRUNCATE_PROOF,
            MutationType.WRONG_VERIFIER
        ):
            if not result.reverted and "unlock" in result.seed.function_name.lower():
                return True
        return False

    def _check_no_double_unlock(
        self, result: MutationResult, before: dict, after: dict
    ) -> bool:
        """SOUL-INV-011: State lock cannot be unlocked twice."""
        if result.mutation_type == MutationType.DOUBLE_EXECUTE:
            if "unlock" in result.seed.function_name.lower():
                if not result.reverted:
                    return True
        return False

    def _check_owner_only_cancel(
        self, result: MutationResult, before: dict, after: dict
    ) -> bool:
        """SOUL-INV-012: Only owner can cancel lock."""
        if result.mutation_type == MutationType.INTERESTING_ADDRESS:
            if "cancel" in result.seed.function_name.lower():
                if not result.reverted:
                    return True
        return False

    def _check_state_preservation(
        self, result: MutationResult, before: dict, after: dict
    ) -> bool:
        """SOUL-INV-013: Locked state hash preserved until unlock."""
        if result.mutation_type == MutationType.WRONG_STATE_HASH:
            state_hash_before = before.get("stateHash")
            state_hash_after = after.get("stateHash")
            if state_hash_before and state_hash_after:
                if state_hash_before != state_hash_after and not result.reverted:
                    return True
        return False

    def _check_invalid_proof_rejected(
        self, result: MutationResult, before: dict, after: dict
    ) -> bool:
        """SOUL-INV-020: Invalid proofs must be rejected."""
        if result.mutation_type in (
            MutationType.CORRUPT_PROOF, MutationType.INVALID_PUBLIC_INPUTS
        ):
            if not result.reverted:
                # Proof-dependent functions should revert
                proof_functions = [
                    "verify", "unlock", "withdraw", "submit", "translate",
                ]
                if any(pf in result.seed.function_name.lower() for pf in proof_functions):
                    return True
        return False

    def _check_pool_balance(
        self, result: MutationResult, before: dict, after: dict
    ) -> bool:
        """SOUL-INV-030: Pool balance = deposits - withdrawals."""
        bal_before = before.get("pool_balance", 0)
        bal_after = after.get("pool_balance", 0)
        deposits = after.get("total_deposits", 0)
        withdrawals = after.get("total_withdrawals", 0)

        if deposits > 0 or withdrawals > 0:
            expected = deposits - withdrawals
            if bal_after != expected and abs(bal_after - expected) > 1:
                return True
        return False

    def _check_merkle_update(
        self, result: MutationResult, before: dict, after: dict
    ) -> bool:
        """SOUL-INV-031: Merkle root updates after deposit."""
        if "deposit" in result.seed.function_name.lower() and not result.reverted:
            root_before = before.get("merkle_root")
            root_after = after.get("merkle_root")
            if root_before and root_after and root_before == root_after:
                return True  # Root didn't change after successful deposit
        return False

    def _check_valid_root(
        self, result: MutationResult, before: dict, after: dict
    ) -> bool:
        """SOUL-INV-032: Withdrawal must use valid root."""
        if result.mutation_type == MutationType.STALE_MERKLE_ROOT:
            if "withdraw" in result.seed.function_name.lower():
                if not result.reverted:
                    return True
        return False

    def _check_no_inflation(
        self, result: MutationResult, before: dict, after: dict
    ) -> bool:
        """SOUL-INV-033: Cannot withdraw more than deposited."""
        total_deposits = after.get("total_deposits", 0)
        total_withdrawals = after.get("total_withdrawals", 0)
        if total_withdrawals > total_deposits:
            return True
        return False

    def _check_no_duplicate_relay(
        self, result: MutationResult, before: dict, after: dict
    ) -> bool:
        """SOUL-INV-040: No duplicate proof relay."""
        if result.mutation_type == MutationType.DUPLICATE_RELAY:
            if not result.reverted:
                return True
        return False

    def _check_swap_fund_safety(
        self, result: MutationResult, before: dict, after: dict
    ) -> bool:
        """SOUL-INV-041: Atomic swap must complete or refund."""
        if "swap" in result.seed.function_name.lower():
            swap_state = after.get("swap_state")
            if swap_state and swap_state not in ("completed", "refunded", "active"):
                return True
        return False

    def _check_circuit_breaker(
        self, result: MutationResult, before: dict, after: dict
    ) -> bool:
        """SOUL-INV-042: Circuit breaker must activate on anomalous volume."""
        if result.mutation_type == MutationType.MAX_UINT_AMOUNT:
            if not result.reverted:
                # Large volume should trigger circuit breaker
                volume = result.seed.inputs.get("volume", 0)
                if isinstance(volume, int) and volume > 10**24:
                    return True
        return False

    def _check_access_control(
        self, result: MutationResult, before: dict, after: dict
    ) -> bool:
        """SOUL-INV-060: Privileged functions enforce access control."""
        if result.mutation_type == MutationType.INTERESTING_ADDRESS:
            privileged_functions = [
                "pause", "unpause", "emergencyWithdraw", "registerModule",
                "reset", "upgrade", "setAdmin",
            ]
            if any(pf in result.seed.function_name.lower() for pf in privileged_functions):
                if not result.reverted:
                    return True
        return False

    def _check_rate_limiting(
        self, result: MutationResult, before: dict, after: dict
    ) -> bool:
        """SOUL-INV-070: Rate limiter prevents excessive operations."""
        if result.mutation_type == MutationType.DOUBLE_EXECUTE:
            ops_count = after.get("operations_in_window", 0)
            max_ops = after.get("max_operations", float("inf"))
            if ops_count > max_ops:
                return True
        return False

    def _check_flash_loan_guard(
        self, result: MutationResult, before: dict, after: dict
    ) -> bool:
        """SOUL-INV-080: Flash loan guard prevents same-block deposit+withdraw."""
        if result.seed.inputs.get("_flash_loan_test"):
            if not result.reverted:
                return True
        return False

    def _check_storage_layout(
        self, result: MutationResult, before: dict, after: dict
    ) -> bool:
        """SOUL-INV-090: Storage layout preserved across upgrades."""
        layout_before = before.get("storage_layout")
        layout_after = after.get("storage_layout")
        if layout_before and layout_after and layout_before != layout_after:
            return True
        return False


# ── Feedback-Driven Fuzz Loop ────────────────────────────────────────────────


class SoulFuzzLoop:
    """Main fuzzing loop with mutation-feedback guidance.

    Implements the core algorithm:
    1. Select seed from corpus (energy-weighted)
    2. Select mutation type (weighted by productivity)
    3. Apply mutation to create new seed
    4. Execute mutated input (Forge or simulation)
    5. Check coverage + invariants
    6. If interesting: add to corpus, boost mutation weight
    7. Feed coverage to advanced corpus for power scheduling
    8. Record stats and repeat
    """

    def __init__(
        self,
        mutation_engine: SoulMutationEngine | None = None,
        max_iterations: int = 10000,
        timeout_seconds: float = 300.0,
        advanced_corpus: Any | None = None,
    ) -> None:
        self.mutation_engine = mutation_engine or SoulMutationEngine()
        self.corpus = FuzzCorpus()
        self.invariant_checker = SoulInvariantChecker()
        self.max_iterations = max_iterations
        self.timeout_seconds = timeout_seconds
        self.stats = FuzzCampaignStats()
        self._executor = None  # Set by caller
        self._forge_executor = None  # ForgeExecutor instance
        self._advanced_corpus = advanced_corpus  # AdvancedCorpus from corpus_evolution
        self._adaptive_scheduler = None  # AdaptiveScheduler

    def set_executor(self, executor) -> None:
        """Set the execution backend (Forge sandbox, simulation, etc.)."""
        self._executor = executor

    def set_forge_executor(self, forge_executor) -> None:
        """Set the ForgeExecutor for real EVM execution."""
        self._forge_executor = forge_executor
        self._executor = forge_executor  # Use Forge as primary executor

    def set_advanced_corpus(self, corpus) -> None:
        """Set the AdvancedCorpus for power-scheduled seed selection."""
        self._advanced_corpus = corpus

    def set_adaptive_scheduler(self, scheduler) -> None:
        """Set the AdaptiveScheduler for dynamic schedule switching."""
        self._adaptive_scheduler = scheduler

    def seed_corpus(self, initial_seeds: list[MutationSeed]) -> None:
        """Seed the corpus with initial inputs."""
        for seed in initial_seeds:
            self.corpus.add_seed(seed)

    def run(
        self,
        target_contract: str = "",
        target_invariants: list[str] | None = None,
    ) -> FuzzCampaignStats:
        """Run the fuzzing campaign.

        Args:
            target_contract: Specific contract to fuzz
            target_invariants: Specific invariants to test

        Returns:
            Campaign statistics including violations found
        """
        start_time = time.time()
        target_invariants = target_invariants or []

        logger.info(
            "Starting Soul Protocol fuzz campaign: %d iterations, %.0fs timeout, %d seeds",
            self.max_iterations, self.timeout_seconds, len(self.corpus.seeds),
        )

        iteration = 0
        while iteration < self.max_iterations:
            elapsed = time.time() - start_time
            if elapsed >= self.timeout_seconds:
                logger.info("Fuzz campaign timeout after %.1fs", elapsed)
                break

            try:
                # 1. Select seed
                seed = self.corpus.select_seed()

                # 2. Select mutation
                mutation_type = self.mutation_engine.select_mutation(
                    target_function=seed.function_name,
                    target_invariant=(
                        target_invariants[iteration % len(target_invariants)]
                        if target_invariants else ""
                    ),
                )

                # 3. Apply mutation
                mutated = self.mutation_engine.mutate_seed(seed, mutation_type)

                # 4. Execute
                result = self._execute(mutated, mutation_type)

                # 5. Check coverage
                new_coverage = self.corpus.coverage.record_execution(
                    path_hash=hashlib.md5(
                        f"{result.revert_reason}:{result.gas_used}:{result.reverted}".encode()
                    ).hexdigest(),
                    revert_reason=result.revert_reason,
                )
                result.new_coverage = new_coverage

                # 6. Check invariants
                violations = self.invariant_checker.check_all(
                    result,
                    state_before={},
                    state_after=result.state_changes,
                )
                if violations:
                    result.invariant_violated = ",".join(violations)
                    self.stats.invariant_violations += len(violations)
                    for v in violations:
                        self.stats.violations_by_invariant[v] = (
                            self.stats.violations_by_invariant.get(v, 0) + 1
                        )
                    self.stats.interesting_finds.append({
                        "iteration": iteration,
                        "seed_id": mutated.id,
                        "mutation": mutation_type.value,
                        "violations": violations,
                        "function": mutated.function_name,
                        "contract": mutated.contract_name,
                        "inputs": _serialize_inputs(mutated.inputs),
                        "reverted": result.reverted,
                        "revert_reason": result.revert_reason,
                    })

                # 7. Update corpus
                interesting = self.corpus.record_result(result)
                if interesting:
                    self.corpus.add_seed(mutated, interesting=True)

                # 8. Update mutation weights (feedback loop)
                if new_coverage or violations:
                    self.mutation_engine.update_weights(mutation_type, 1.5)
                else:
                    self.mutation_engine.update_weights(mutation_type, 0.99)

                # 9. Track stats
                self.stats.total_executions += 1
                mt_key = mutation_type.value
                self.stats.mutations_applied[mt_key] = (
                    self.stats.mutations_applied.get(mt_key, 0) + 1
                )

                if result.reverted and result.revert_reason:
                    self.stats.unique_crashes += 1

                # Periodic coverage snapshot
                if iteration % 100 == 0:
                    self.stats.coverage_over_time.append(
                        (iteration, self.corpus.coverage.line_coverage)
                    )
                    logger.info(
                        "Fuzz iteration %d/%d: coverage=%.1f%%, violations=%d, corpus=%d",
                        iteration, self.max_iterations,
                        self.corpus.coverage.line_coverage,
                        self.stats.invariant_violations,
                        len(self.corpus.seeds),
                    )

            except Exception as e:
                logger.debug("Fuzz iteration %d error: %s", iteration, e)

            iteration += 1

        # Final stats
        self.stats.execution_time_seconds = time.time() - start_time
        self.stats.coverage_percentage = self.corpus.coverage.line_coverage
        self.stats.corpus_size = len(self.corpus.seeds)

        logger.info(
            "Fuzz campaign complete: %d executions, %d violations, %.1f%% coverage in %.1fs",
            self.stats.total_executions,
            self.stats.invariant_violations,
            self.stats.coverage_percentage,
            self.stats.execution_time_seconds,
        )

        return self.stats

    def _execute(
        self,
        seed: MutationSeed,
        mutation_type: MutationType,
    ) -> MutationResult:
        """Execute a mutated seed against the target.

        If no executor is set, uses simulation mode.
        """
        start = time.time()

        if self._executor:
            try:
                raw_result = self._executor.execute(seed)
                return MutationResult(
                    seed=seed,
                    mutation_type=mutation_type,
                    reverted=raw_result.get("reverted", False),
                    revert_reason=raw_result.get("revert_reason", ""),
                    new_coverage=False,
                    gas_used=raw_result.get("gas_used", 0),
                    execution_time_ms=(time.time() - start) * 1000,
                    raw_output=raw_result.get("output", b""),
                    state_changes=raw_result.get("state_changes", {}),
                )
            except Exception as e:
                return MutationResult(
                    seed=seed,
                    mutation_type=mutation_type,
                    reverted=True,
                    revert_reason=str(e),
                    execution_time_ms=(time.time() - start) * 1000,
                )

        # Simulation mode — analyze mutation to predict behaviour
        return self._simulate_execution(seed, mutation_type, start)

    def _simulate_execution(
        self,
        seed: MutationSeed,
        mutation_type: MutationType,
        start_time: float,
    ) -> MutationResult:
        """Simulate execution for analysis-only mode (no Forge).

        Uses heuristics based on mutation type and input patterns
        to predict whether the contract would revert.
        """
        reverted = False
        revert_reason = ""

        # Heuristic: most Soul-specific attacks should revert if contract is secure
        should_revert_mutations = {
            MutationType.CORRUPT_PROOF: ("Invalid proof", 0.9),
            MutationType.TRUNCATE_PROOF: ("Proof too short", 0.95),
            MutationType.REPLAY_NULLIFIER: ("Nullifier already used", 0.85),
            MutationType.ZERO_NULLIFIER: ("Zero nullifier", 0.9),
            MutationType.STALE_MERKLE_ROOT: ("Root not known", 0.85),
            MutationType.DOUBLE_EXECUTE: ("Already executed", 0.8),
            MutationType.CROSS_DOMAIN_COLLISION: ("Domain collision", 0.7),
            MutationType.PARTIAL_BATCH_REPLAY: ("Batch contains duplicate", 0.85),
            MutationType.WRONG_VERIFIER: ("Unknown verifier", 0.9),
            MutationType.INVALID_PUBLIC_INPUTS: ("Public input mismatch", 0.9),
            MutationType.DUPLICATE_RELAY: ("Already relayed", 0.85),
            MutationType.FLASH_LOAN_SEQUENCE: ("Flash loan detected", 0.7),
            MutationType.INTERESTING_ADDRESS: ("Unauthorized", 0.6),
            MutationType.MAX_UINT_AMOUNT: ("Amount exceeds limit", 0.7),
        }

        if mutation_type in should_revert_mutations:
            reason, probability = should_revert_mutations[mutation_type]
            # In simulation: assume well-coded contract reverts
            import random
            if random.random() < probability:
                reverted = True
                revert_reason = reason
            else:
                # Potential vulnerability — didn't revert when it should have
                pass

        return MutationResult(
            seed=seed,
            mutation_type=mutation_type,
            reverted=reverted,
            revert_reason=revert_reason,
            gas_used=21000 + hash(seed.id) % 200000,  # simulated gas
            execution_time_ms=(time.time() - start_time) * 1000,
        )

    def get_results_summary(self) -> dict[str, Any]:
        """Get comprehensive results summary."""
        return {
            "campaign_stats": {
                "total_executions": self.stats.total_executions,
                "unique_crashes": self.stats.unique_crashes,
                "invariant_violations": self.stats.invariant_violations,
                "coverage_percentage": round(self.stats.coverage_percentage, 2),
                "corpus_size": self.stats.corpus_size,
                "execution_time_seconds": round(self.stats.execution_time_seconds, 2),
            },
            "violations": {
                "total": self.stats.invariant_violations,
                "by_invariant": self.stats.violations_by_invariant,
                "details": self.stats.interesting_finds[:50],  # Top 50
            },
            "mutations": {
                "applied": self.stats.mutations_applied,
                "most_productive": sorted(
                    self.stats.mutations_applied.items(),
                    key=lambda x: x[1],
                    reverse=True,
                )[:10],
            },
            "coverage": self.corpus.coverage.to_dict(),
            "coverage_over_time": self.stats.coverage_over_time,
            "corpus": self.corpus.get_stats(),
        }


def _serialize_inputs(inputs: dict[str, Any]) -> dict[str, Any]:
    """Serialize inputs for JSON storage."""
    result = {}
    for key, val in inputs.items():
        if key.startswith("_"):
            result[key] = val
        elif isinstance(val, bytes):
            result[key] = f"0x{val.hex()[:64]}..."
        elif isinstance(val, int) and val > 2**64:
            result[key] = hex(val)
        elif isinstance(val, list):
            result[key] = f"[{len(val)} items]"
        else:
            result[key] = val
    return result
