"""Advanced Corpus Evolution for Soul Protocol Fuzzer.

Implements coverage-guided power schedules (inspired by the AFL++ paper), genetic algorithm crossover,
structure-aware seed trimming, rare branch boosting, and adaptive
scheduling — replacing the simple energy-based scheduling in FuzzCorpus.

Power Schedules:
  FAST     — Favour seeds that haven't been fuzzed much (default)
  COE      — Cut-Off Exponential: aggressively favour rare paths
  LIN      — Linear growth: steadily increase energy per fuzz
  QUAD     — Quadratic growth: accelerate energy over time
  EXPLOIT  — Focus on seeds near known violation regions
  EXPLORE  — Uniform coverage of unexplored paths
  MMOPT    — MOpt-style adaptive mutation operator scheduling

Genetic Operators:
  - Single-point crossover between seeds
  - Multi-point crossover for complex structures
  - Uniform crossover for diverse exploration
  - Havoc-style stacked mutations
  - Structure-aware splice

Seed Management:
  - Delta-debugging minimizer for violation-triggering inputs
  - Structure-aware trimming (preserve tx sequence structure)
  - Coverage-based deduplication
  - Age-based expiration (evict stale non-productive seeds)
"""

from __future__ import annotations

import hashlib
import logging
import math
import os
import random
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

logger = logging.getLogger(__name__)


# ── Types ────────────────────────────────────────────────────────────────────


class PowerSchedule(Enum):
    """Power schedules for seed energy allocation (inspired by AFL++ paper)."""
    FAST = "fast"
    COE = "coe"
    LIN = "lin"
    QUAD = "quad"
    EXPLOIT = "exploit"
    EXPLORE = "explore"
    MMOPT = "mmopt"
    RARE = "rare"


class GeneticOp(Enum):
    """Genetic algorithm crossover/mutation operators."""
    SINGLE_CROSSOVER = "single_crossover"
    MULTI_CROSSOVER = "multi_crossover"
    UNIFORM_CROSSOVER = "uniform_crossover"
    HAVOC_SPLICE = "havoc_splice"
    STRUCTURE_SPLICE = "structure_splice"
    ARITHMETIC_CROSSOVER = "arithmetic_crossover"


@dataclass
class SeedMetrics:
    """Detailed metrics for a seed in the corpus."""
    # Execution metrics
    exec_count: int = 0
    last_exec_time: float = 0.0
    avg_exec_us: float = 0.0

    # Coverage metrics
    new_coverage_count: int = 0        # How many times this seed found new coverage
    unique_branches: int = 0            # Branches hit uniquely by this seed
    path_frequency: int = 1             # How many seeds share this seed's path

    # Mutation metrics
    mutation_depth: int = 0             # How many mutations from original seed
    parent_id: str | None = None        # Parent seed
    children_count: int = 0
    useful_children: int = 0            # Children that found new coverage

    # Violation metrics
    violations_triggered: int = 0
    near_violation_count: int = 0       # Executions that nearly violated invariants

    # Energy
    base_energy: float = 1.0
    computed_energy: float = 1.0
    schedule_energy: float = 1.0
    fuzz_level: int = 0                 # Number of times selected for fuzzing

    # Timestamps
    created_at: float = field(default_factory=time.time)
    last_new_coverage_at: float = 0.0

    @property
    def age_seconds(self) -> float:
        return time.time() - self.created_at

    @property
    def productivity(self) -> float:
        if self.exec_count == 0:
            return 0.0
        return (self.new_coverage_count + self.violations_triggered * 5) / self.exec_count

    @property
    def coverage_ratio(self) -> float:
        if self.exec_count == 0:
            return 0.0
        return self.new_coverage_count / self.exec_count


@dataclass
class CorpusSeed:
    """A seed in the advanced corpus."""
    id: str
    data: dict[str, Any]
    coverage_bitmap: bytes = b""
    metrics: SeedMetrics = field(default_factory=SeedMetrics)
    tags: set[str] = field(default_factory=set)
    favoured: bool = False
    minimized: bool = False
    disabled: bool = False

    @property
    def energy(self) -> float:
        return self.metrics.computed_energy * self.metrics.schedule_energy

    def bitmap_hash(self) -> str:
        return hashlib.md5(self.coverage_bitmap).hexdigest()


@dataclass
class EvolutionStats:
    """Statistics for corpus evolution."""
    total_seeds: int = 0
    favoured_seeds: int = 0
    disabled_seeds: int = 0
    minimized_seeds: int = 0
    avg_energy: float = 0.0
    avg_productivity: float = 0.0
    crossovers_performed: int = 0
    trims_performed: int = 0
    evictions: int = 0
    schedule_switches: int = 0
    coverage_plateaus: int = 0


# ── Power Schedule Calculator ────────────────────────────────────────────────


class PowerScheduleCalculator:
    """Computes seed energy using coverage-guided power schedules.

    Reference: AFL++ paper (https://www.usenix.org/conference/woot20/presentation/fioraldi)
    """

    PERF_SCORE_MAX = 6400
    PERF_SCORE_MIN = 1

    def __init__(self, schedule: PowerSchedule = PowerSchedule.FAST) -> None:
        self.schedule = schedule
        self._avg_exec_us: float = 50.0
        self._avg_bitmap_size: float = 100.0
        self._global_coverage_count: int = 1

    def compute_energy(self, seed: CorpusSeed) -> float:
        """Compute energy for a seed based on the selected power schedule."""
        m = seed.metrics
        base = self._compute_base_energy(seed)

        schedule_mult = self._schedule_multiplier(seed)
        rarity_mult = self._rarity_multiplier(seed)
        perf_mult = self._performance_multiplier(seed)

        energy = base * schedule_mult * rarity_mult * perf_mult

        # Clamp
        energy = max(self.PERF_SCORE_MIN, min(self.PERF_SCORE_MAX, energy))

        seed.metrics.computed_energy = energy
        return energy

    def _compute_base_energy(self, seed: CorpusSeed) -> float:
        """Base energy from execution speed and coverage."""
        m = seed.metrics

        # Speed factor: faster seeds get more energy
        speed_factor = 1.0
        if m.avg_exec_us > 0 and self._avg_exec_us > 0:
            speed_factor = min(3.0, self._avg_exec_us / max(1.0, m.avg_exec_us))

        # Coverage factor: unique coverage → more energy
        coverage_factor = 1.0 + min(5.0, m.unique_branches * 0.5)

        # Depth factor: shallow seeds preferred for speed
        depth_factor = max(0.5, 1.0 / (1.0 + m.mutation_depth * 0.1))

        return speed_factor * coverage_factor * depth_factor

    def _schedule_multiplier(self, seed: CorpusSeed) -> float:
        """Apply the power schedule formula."""
        m = seed.metrics
        fuzz = max(1, m.fuzz_level)

        if self.schedule == PowerSchedule.FAST:
            # FAST: factor = 2^(log2(fuzz_level) if fuzz_level ≤ f(coverage))
            if m.fuzz_level == 0:
                return 1.0
            log_fuzz = math.log2(max(1, fuzz))
            if fuzz <= self._global_coverage_count:
                return min(16.0, 2.0 ** log_fuzz)
            return min(16.0, 2.0 ** (log_fuzz - 1))

        elif self.schedule == PowerSchedule.COE:
            # Cut-Off Exponential: aggressively penalise over-fuzzed seeds
            avg_fuzz = max(1, self._global_coverage_count)
            if fuzz > avg_fuzz * 2:
                return 0.1
            return min(16.0, 2.0 ** (fuzz / max(1, avg_fuzz)))

        elif self.schedule == PowerSchedule.LIN:
            return min(16.0, 1.0 + fuzz * 0.1)

        elif self.schedule == PowerSchedule.QUAD:
            return min(16.0, 1.0 + (fuzz ** 2) * 0.01)

        elif self.schedule == PowerSchedule.EXPLOIT:
            violation_bonus = 1.0 + m.violations_triggered * 3.0
            near_bonus = 1.0 + m.near_violation_count * 0.5
            return min(16.0, violation_bonus * near_bonus)

        elif self.schedule == PowerSchedule.EXPLORE:
            # Favour seeds with low execution count
            return min(16.0, max(1.0, 8.0 / math.sqrt(fuzz)))

        elif self.schedule == PowerSchedule.MMOPT:
            # MOpt: balance between mutation effectiveness
            child_ratio = m.useful_children / max(1, m.children_count)
            return min(16.0, 1.0 + child_ratio * 8.0)

        elif self.schedule == PowerSchedule.RARE:
            # Favour rare paths
            return min(16.0, max(1.0, 8.0 / math.sqrt(max(1, m.path_frequency))))

        return 1.0

    def _rarity_multiplier(self, seed: CorpusSeed) -> float:
        """Boost energy for seeds hitting rare branches."""
        m = seed.metrics
        if m.path_frequency <= 1:
            return 4.0  # Unique path: 4x boost
        elif m.path_frequency <= 3:
            return 2.0
        elif m.path_frequency <= 10:
            return 1.5
        return 1.0

    def _performance_multiplier(self, seed: CorpusSeed) -> float:
        """Multiply based on seed performance."""
        m = seed.metrics
        if m.productivity > 0.5:
            return 3.0
        elif m.productivity > 0.1:
            return 2.0
        elif m.productivity > 0.01:
            return 1.5
        return 1.0

    def update_globals(
        self,
        avg_exec_us: float,
        avg_bitmap_size: float,
        coverage_count: int,
    ) -> None:
        """Update global statistics used for schedule calculations."""
        self._avg_exec_us = max(1.0, avg_exec_us)
        self._avg_bitmap_size = max(1.0, avg_bitmap_size)
        self._global_coverage_count = max(1, coverage_count)


# ── Genetic Operators ────────────────────────────────────────────────────────


class GeneticOperators:
    """Genetic algorithm operators for seed evolution.

    Supports crossover, splice, and structure-aware mutations
    specifically designed for multi-transaction fuzz inputs.
    """

    def crossover(
        self,
        parent_a: CorpusSeed,
        parent_b: CorpusSeed,
        op: GeneticOp = GeneticOp.SINGLE_CROSSOVER,
    ) -> CorpusSeed:
        """Create a child seed from two parents."""
        operators = {
            GeneticOp.SINGLE_CROSSOVER: self._single_crossover,
            GeneticOp.MULTI_CROSSOVER: self._multi_crossover,
            GeneticOp.UNIFORM_CROSSOVER: self._uniform_crossover,
            GeneticOp.HAVOC_SPLICE: self._havoc_splice,
            GeneticOp.STRUCTURE_SPLICE: self._structure_splice,
            GeneticOp.ARITHMETIC_CROSSOVER: self._arithmetic_crossover,
        }
        operator = operators.get(op, self._single_crossover)
        child_data = operator(parent_a.data, parent_b.data)

        child_id = hashlib.md5(
            f"{parent_a.id}x{parent_b.id}:{time.time_ns()}".encode()
        ).hexdigest()[:12]

        return CorpusSeed(
            id=child_id,
            data=child_data,
            metrics=SeedMetrics(
                parent_id=parent_a.id,
                mutation_depth=max(
                    parent_a.metrics.mutation_depth,
                    parent_b.metrics.mutation_depth,
                ) + 1,
            ),
            tags=parent_a.tags | parent_b.tags | {"crossover"},
        )

    def _single_crossover(
        self, a: dict[str, Any], b: dict[str, Any]
    ) -> dict[str, Any]:
        """Single-point crossover on transaction sequences."""
        seq_a = a.get("tx_sequence", [a])
        seq_b = b.get("tx_sequence", [b])

        if len(seq_a) < 2 or len(seq_b) < 2:
            return dict(a)

        crossover_point = random.randint(1, min(len(seq_a), len(seq_b)) - 1)
        child_seq = seq_a[:crossover_point] + seq_b[crossover_point:]

        child = dict(a)
        child["tx_sequence"] = child_seq
        return child

    def _multi_crossover(
        self, a: dict[str, Any], b: dict[str, Any]
    ) -> dict[str, Any]:
        """Multi-point crossover with 2-3 crossover points."""
        seq_a = a.get("tx_sequence", [a])
        seq_b = b.get("tx_sequence", [b])

        min_len = min(len(seq_a), len(seq_b))
        if min_len < 3:
            return self._single_crossover(a, b)

        n_points = min(3, min_len - 1)
        points = sorted(random.sample(range(1, min_len), n_points))

        result: list = []
        use_a = True
        prev = 0
        for pt in points:
            result.extend((seq_a if use_a else seq_b)[prev:pt])
            use_a = not use_a
            prev = pt
        result.extend((seq_a if use_a else seq_b)[prev:])

        child = dict(a)
        child["tx_sequence"] = result
        return child

    def _uniform_crossover(
        self, a: dict[str, Any], b: dict[str, Any]
    ) -> dict[str, Any]:
        """Uniform crossover: each field independently chosen from parent."""
        child: dict[str, Any] = {}
        all_keys = set(a.keys()) | set(b.keys())

        for key in all_keys:
            if key in a and key in b:
                child[key] = a[key] if random.random() < 0.5 else b[key]
            elif key in a:
                child[key] = a[key]
            else:
                child[key] = b[key]

        return child

    def _havoc_splice(
        self, a: dict[str, Any], b: dict[str, Any]
    ) -> dict[str, Any]:
        """Havoc splice: take random chunks from both parents."""
        child = dict(a)

        # Splice numeric fields from b with random perturbation
        for key, val in b.items():
            if isinstance(val, int) and random.random() < 0.3:
                if key in child and isinstance(child[key], int):
                    child[key] = val ^ random.getrandbits(8)
                else:
                    child[key] = val

        # Splice byte fields from b
        for key, val in b.items():
            if isinstance(val, (bytes, bytearray)) and random.random() < 0.2:
                if key in child and isinstance(child[key], (bytes, bytearray)):
                    # Splice at random point
                    pt = random.randint(0, min(len(child[key]), len(val)))
                    child[key] = child[key][:pt] + val[pt:]

        return child

    def _structure_splice(
        self, a: dict[str, Any], b: dict[str, Any]
    ) -> dict[str, Any]:
        """Structure-aware splice: preserve valid Solidity call structure."""
        child = dict(a)

        # If both have function_name, keep a's function but try b's inputs
        if "function_name" in a and "function_name" in a:
            child["function_name"] = a["function_name"]
            a_inputs = a.get("inputs", {})
            b_inputs = b.get("inputs", {})

            merged: dict[str, Any] = {}
            for k in a_inputs:
                if k in b_inputs and random.random() < 0.5:
                    merged[k] = b_inputs[k]
                else:
                    merged[k] = a_inputs[k]
            child["inputs"] = merged

        return child

    def _arithmetic_crossover(
        self, a: dict[str, Any], b: dict[str, Any]
    ) -> dict[str, Any]:
        """Arithmetic crossover: blend numeric values with weight."""
        alpha = random.random()
        child = dict(a)

        for key in a:
            a_val = a.get(key)
            b_val = b.get(key)
            if isinstance(a_val, int) and isinstance(b_val, int):
                blended = int(a_val * alpha + b_val * (1 - alpha))
                child[key] = max(0, blended)

        return child


# ── Seed Trimmer ─────────────────────────────────────────────────────────────


class SeedTrimmer:
    """Structure-aware seed trimming and minimization.

    Uses delta debugging to minimize seeds while preserving
    interesting behaviour (coverage or violations).
    """

    def __init__(self, max_trim_steps: int = 64) -> None:
        self.max_trim_steps = max_trim_steps

    def trim_seed(
        self,
        seed: CorpusSeed,
        checker: Any,  # Callable that returns True if seed still interesting
    ) -> CorpusSeed:
        """Minimize seed data while keeping it interesting."""
        original = seed.data
        current = dict(original)
        trimmed = False

        # Phase 1: Remove unused keys
        for key in list(current.keys()):
            candidate = {k: v for k, v in current.items() if k != key}
            if candidate and checker(candidate):
                current = candidate
                trimmed = True

        # Phase 2: Shrink numeric values
        for key, value in list(current.items()):
            if isinstance(value, int) and value > 0:
                smaller = self._binary_shrink_int(value, key, current, checker)
                if smaller < value:
                    current[key] = smaller
                    trimmed = True

        # Phase 3: Trim byte sequences
        for key, value in list(current.items()):
            if isinstance(value, (bytes, bytearray)) and len(value) > 0:
                shorter = self._binary_shrink_bytes(value, key, current, checker)
                if len(shorter) < len(value):
                    current[key] = shorter
                    trimmed = True

        # Phase 4: Trim transaction sequences
        if "tx_sequence" in current:
            shorter = self._trim_sequence(current["tx_sequence"], current, checker)
            if len(shorter) < len(current.get("tx_sequence", [])):
                current["tx_sequence"] = shorter
                trimmed = True

        if trimmed:
            result = CorpusSeed(
                id=seed.id,
                data=current,
                coverage_bitmap=seed.coverage_bitmap,
                metrics=seed.metrics,
                tags=seed.tags | {"minimized"},
                minimized=True,
            )
            return result

        seed.minimized = True
        return seed

    def _binary_shrink_int(
        self,
        value: int,
        key: str,
        data: dict[str, Any],
        checker: Any,
    ) -> int:
        """Binary search for smallest interesting int value."""
        lo, hi = 0, value
        best = value

        steps = 0
        while lo < hi and steps < self.max_trim_steps:
            mid = (lo + hi) // 2
            candidate = dict(data)
            candidate[key] = mid
            if checker(candidate):
                best = mid
                hi = mid
            else:
                lo = mid + 1
            steps += 1

        return best

    def _binary_shrink_bytes(
        self,
        value: bytes,
        key: str,
        data: dict[str, Any],
        checker: Any,
    ) -> bytes:
        """Binary search for shortest interesting byte sequence."""
        n = len(value)
        lo, hi = 0, n
        best = value

        steps = 0
        while lo < hi and steps < self.max_trim_steps:
            mid = (lo + hi) // 2
            candidate = dict(data)
            candidate[key] = value[:mid]
            if checker(candidate):
                best = value[:mid]
                hi = mid
            else:
                lo = mid + 1
            steps += 1

        return best

    def _trim_sequence(
        self,
        seq: list[Any],
        data: dict[str, Any],
        checker: Any,
    ) -> list[Any]:
        """Delta debugging on transaction sequence."""
        if len(seq) <= 1:
            return seq

        # Try removing each element
        for i in reversed(range(len(seq))):
            shorter = seq[:i] + seq[i+1:]
            candidate = dict(data)
            candidate["tx_sequence"] = shorter
            if shorter and checker(candidate):
                return self._trim_sequence(shorter, data, checker)

        return seq


# ── Advanced Corpus ──────────────────────────────────────────────────────────


class AdvancedCorpus:
    """Advanced corpus with power scheduling, genetic evolution,
    and structure-aware seed management.

    Replace the basic FuzzCorpus with this for production-quality fuzzing.
    """

    DEFAULT_MAX_SIZE = 20000
    CULL_INTERVAL = 500  # Re-cull every N additions
    RECALC_INTERVAL = 200  # Recalculate energies every N selections

    def __init__(
        self,
        max_size: int = DEFAULT_MAX_SIZE,
        schedule: PowerSchedule = PowerSchedule.FAST,
        enable_genetic: bool = True,
        crossover_rate: float = 0.15,
    ) -> None:
        self.max_size = max_size
        self.enable_genetic = enable_genetic
        self.crossover_rate = crossover_rate

        self._seeds: dict[str, CorpusSeed] = {}
        self._favoured: set[str] = set()
        self._bitmap_to_seeds: dict[str, list[str]] = {}  # bitmap hash → seed IDs

        self._power_calc = PowerScheduleCalculator(schedule)
        self._genetic = GeneticOperators()
        self._trimmer = SeedTrimmer()

        self._selection_count = 0
        self._add_count = 0
        self._stats = EvolutionStats()

    @property
    def size(self) -> int:
        return len(self._seeds)

    @property
    def active_size(self) -> int:
        return sum(1 for s in self._seeds.values() if not s.disabled)

    def add_seed(
        self,
        seed_id: str,
        data: dict[str, Any],
        coverage_bitmap: bytes = b"",
        tags: set[str] | None = None,
        parent_id: str | None = None,
    ) -> bool:
        """Add a seed to the corpus. Returns True if seed was added."""
        if seed_id in self._seeds:
            return False

        seed = CorpusSeed(
            id=seed_id,
            data=data,
            coverage_bitmap=coverage_bitmap,
            tags=tags or set(),
            metrics=SeedMetrics(parent_id=parent_id),
        )

        # Check for duplicate coverage
        bmp_hash = seed.bitmap_hash()
        if bmp_hash in self._bitmap_to_seeds and len(self._bitmap_to_seeds[bmp_hash]) > 5:
            # Too many seeds with same coverage — only add if it's smaller
            existing = self._bitmap_to_seeds[bmp_hash]
            smallest = min(
                (self._seeds[sid] for sid in existing if sid in self._seeds),
                key=lambda s: len(str(s.data)),
                default=None,
            )
            if smallest and len(str(data)) >= len(str(smallest.data)):
                return False

        # Add seed
        self._seeds[seed_id] = seed
        self._bitmap_to_seeds.setdefault(bmp_hash, []).append(seed_id)

        # Update parent metrics
        if parent_id and parent_id in self._seeds:
            self._seeds[parent_id].metrics.children_count += 1

        self._add_count += 1

        # Periodic cull
        if self._add_count % self.CULL_INTERVAL == 0:
            self._cull_corpus()

        # Evict if over capacity
        if len(self._seeds) > self.max_size:
            self._evict()

        return True

    def record_execution(
        self,
        seed_id: str,
        new_coverage: bool,
        exec_time_us: float = 0.0,
        violation: bool = False,
        near_violation: bool = False,
    ) -> None:
        """Record execution result for a seed."""
        if seed_id not in self._seeds:
            return

        m = self._seeds[seed_id].metrics
        m.exec_count += 1
        m.last_exec_time = time.time()

        if exec_time_us > 0:
            m.avg_exec_us = (m.avg_exec_us * (m.exec_count - 1) + exec_time_us) / m.exec_count

        if new_coverage:
            m.new_coverage_count += 1
            m.last_new_coverage_at = time.time()
            # Boost parent
            if m.parent_id and m.parent_id in self._seeds:
                self._seeds[m.parent_id].metrics.useful_children += 1

        if violation:
            m.violations_triggered += 1

        if near_violation:
            m.near_violation_count += 1

    def select_seed(self) -> CorpusSeed | None:
        """Select a seed for fuzzing using power schedule."""
        active = [s for s in self._seeds.values() if not s.disabled]
        if not active:
            return None

        self._selection_count += 1

        # Periodic energy recalculation
        if self._selection_count % self.RECALC_INTERVAL == 0:
            self._recalculate_energies()

        # Genetic crossover with probability
        if (
            self.enable_genetic
            and random.random() < self.crossover_rate
            and len(active) >= 2
        ):
            parents = random.sample(active, 2)
            op = random.choice(list(GeneticOp))
            child = self._genetic.crossover(parents[0], parents[1], op)
            self.add_seed(child.id, child.data, parent_id=parents[0].id)
            self._stats.crossovers_performed += 1

        # Prefer favoured seeds 80% of the time
        if self._favoured and random.random() < 0.8:
            favoured = [
                self._seeds[sid] for sid in self._favoured
                if sid in self._seeds and not self._seeds[sid].disabled
            ]
            if favoured:
                active = favoured

        # Weighted random selection by energy
        energies = [max(0.001, s.energy) for s in active]
        total = sum(energies)
        if total == 0:
            return random.choice(active)

        r = random.random() * total
        cumulative = 0.0
        for seed, energy in zip(active, energies):
            cumulative += energy
            if cumulative >= r:
                seed.metrics.fuzz_level += 1
                return seed

        active[-1].metrics.fuzz_level += 1
        return active[-1]

    def mark_favoured(self, seed_id: str) -> None:
        """Mark a seed as favoured (cmin-like)."""
        if seed_id in self._seeds:
            self._seeds[seed_id].favoured = True
            self._favoured.add(seed_id)

    def trim_seed(self, seed_id: str, checker: Any) -> bool:
        """Minimize a seed while preserving interesting behaviour."""
        if seed_id not in self._seeds:
            return False

        seed = self._seeds[seed_id]
        if seed.minimized:
            return False

        trimmed = self._trimmer.trim_seed(seed, checker)
        self._seeds[seed_id] = trimmed
        self._stats.trims_performed += 1
        return trimmed.minimized

    def switch_schedule(self, schedule: PowerSchedule) -> None:
        """Switch the power schedule."""
        self._power_calc.schedule = schedule
        self._recalculate_energies()
        self._stats.schedule_switches += 1

    def _recalculate_energies(self) -> None:
        """Recalculate all seed energies."""
        active = [s for s in self._seeds.values() if not s.disabled]
        if not active:
            return

        avg_exec = sum(s.metrics.avg_exec_us for s in active) / len(active) if active else 50.0
        avg_bmp = sum(len(s.coverage_bitmap) for s in active) / len(active) if active else 100.0

        self._power_calc.update_globals(avg_exec, avg_bmp, len(active))

        for seed in active:
            self._power_calc.compute_energy(seed)

    def _cull_corpus(self) -> None:
        """Corpus culling — select minimum set of seeds
        that maximise coverage (greedy set cover)."""
        if not self._seeds:
            return

        # Group seeds by coverage bitmap
        bitmap_groups: dict[str, list[CorpusSeed]] = {}
        for seed in self._seeds.values():
            bh = seed.bitmap_hash()
            bitmap_groups.setdefault(bh, []).append(seed)

        # For each bitmap group, keep the best seed as favoured
        new_favoured: set[str] = set()
        for group in bitmap_groups.values():
            # Best = smallest data with most coverage
            best = min(
                group,
                key=lambda s: (
                    -s.metrics.violations_triggered,
                    -s.metrics.new_coverage_count,
                    len(str(s.data)),
                ),
            )
            new_favoured.add(best.id)
            best.favoured = True

        # Unfavour previous
        for sid in self._favoured - new_favoured:
            if sid in self._seeds:
                self._seeds[sid].favoured = False

        self._favoured = new_favoured
        self._stats.favoured_seeds = len(new_favoured)

    def _evict(self) -> None:
        """Evict least productive seeds."""
        target = self.max_size * 9 // 10
        excess = len(self._seeds) - target

        if excess <= 0:
            return

        # Never evict favoured seeds
        candidates = sorted(
            [s for s in self._seeds.values() if not s.favoured and not s.disabled],
            key=lambda s: (
                s.metrics.violations_triggered,
                s.metrics.productivity,
                -s.metrics.age_seconds,
            ),
        )

        for seed in candidates[:excess]:
            del self._seeds[seed.id]
            self._stats.evictions += 1

    def get_stats(self) -> dict[str, Any]:
        """Get corpus statistics."""
        active = [s for s in self._seeds.values() if not s.disabled]
        self._stats.total_seeds = len(self._seeds)
        self._stats.disabled_seeds = len(self._seeds) - len(active)
        self._stats.minimized_seeds = sum(1 for s in self._seeds.values() if s.minimized)

        if active:
            self._stats.avg_energy = sum(s.energy for s in active) / len(active)
            self._stats.avg_productivity = sum(
                s.metrics.productivity for s in active
            ) / len(active)

        return {
            "total_seeds": self._stats.total_seeds,
            "active_seeds": len(active),
            "favoured_seeds": self._stats.favoured_seeds,
            "minimized_seeds": self._stats.minimized_seeds,
            "evictions": self._stats.evictions,
            "crossovers": self._stats.crossovers_performed,
            "trims": self._stats.trims_performed,
            "avg_energy": round(self._stats.avg_energy, 2),
            "avg_productivity": round(self._stats.avg_productivity, 4),
            "schedule": self._power_calc.schedule.value,
            "schedule_switches": self._stats.schedule_switches,
        }


# ── Adaptive Schedule Switcher ───────────────────────────────────────────────


class AdaptiveScheduler:
    """Dynamically switches power schedules based on coverage progress.

    Monitors coverage plateau detection and switches between
    exploration/exploitation phases automatically.
    """

    PLATEAU_WINDOW = 300  # 5 minutes
    PLATEAU_THRESHOLD = 0.02  # <2% new coverage in window → plateau

    def __init__(self, corpus: AdvancedCorpus) -> None:
        self.corpus = corpus
        self._coverage_history: list[tuple[float, float]] = []  # (timestamp, coverage%)
        self._current_phase: str = "explore"
        self._phase_start: float = time.time()

    def record_coverage(self, coverage_pct: float) -> None:
        """Record coverage measurement."""
        self._coverage_history.append((time.time(), coverage_pct))

        # Keep last 1000 entries
        if len(self._coverage_history) > 1000:
            self._coverage_history = self._coverage_history[-500:]

    def maybe_switch(self) -> PowerSchedule | None:
        """Check if schedule should be switched. Returns new schedule or None."""
        if len(self._coverage_history) < 10:
            return None

        now = time.time()
        window_start = now - self.PLATEAU_WINDOW

        recent = [
            (t, c) for t, c in self._coverage_history
            if t >= window_start
        ]

        if len(recent) < 5:
            return None

        coverage_delta = recent[-1][1] - recent[0][1]

        if coverage_delta < self.PLATEAU_THRESHOLD:
            # Coverage plateau detected
            if self._current_phase == "explore":
                # Switch to exploitation
                self._current_phase = "exploit"
                self._phase_start = now
                schedule = random.choice([
                    PowerSchedule.EXPLOIT,
                    PowerSchedule.COE,
                    PowerSchedule.RARE,
                ])
                self.corpus.switch_schedule(schedule)
                return schedule
            else:
                # Switch to exploration
                self._current_phase = "explore"
                self._phase_start = now
                schedule = random.choice([
                    PowerSchedule.EXPLORE,
                    PowerSchedule.FAST,
                    PowerSchedule.MMOPT,
                ])
                self.corpus.switch_schedule(schedule)
                return schedule

        return None
