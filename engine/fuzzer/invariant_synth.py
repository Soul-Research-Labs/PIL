"""Invariant Synthesis Engine — Daikon-style dynamic invariant discovery.

Automatically discovers new invariants from execution traces using
template-based synthesis, state relationship mining, and counter-
example-guided refinement.

Architecture:
  ┌──────────────────────────────────────────────────────────────────┐
  │                INVARIANT  SYNTHESIS  ENGINE                     │
  │                                                                  │
  │  ┌──────────┐  ┌────────────┐  ┌──────────────┐  ┌──────────┐ │
  │  │Trace     │─►│Template    │─►│Candidate     │─►│Counter-  │ │
  │  │Collector │  │Library     │  │Generator     │  │Example   │ │
  │  │          │  │            │  │              │  │Pruner    │ │
  │  └──────────┘  └────────────┘  └──────────────┘  └──────────┘ │
  │       │              │               │                   │      │
  │       ▼              ▼               ▼                   ▼      │
  │  ┌──────────┐  ┌────────────┐  ┌──────────────┐  ┌──────────┐ │
  │  │State     │  │Relationship│  │Statistical   │  │Invariant │ │
  │  │Differ    │  │Miner       │  │Validator     │  │Ranker    │ │
  │  │          │  │            │  │              │  │          │ │
  │  └──────────┘  └────────────┘  └──────────────┘  └──────────┘ │
  │                                                                  │
  │  ┌──────────────────────────────────────────────────────────┐   │
  │  │ Soul Protocol Invariant Templates (ZK, nullifier,        │   │
  │  │ privacy-pool, bridge, access-control, economic)          │   │
  │  └──────────────────────────────────────────────────────────┘   │
  └──────────────────────────────────────────────────────────────────┘
"""

from __future__ import annotations

import hashlib
import logging
import math
import time
from collections import defaultdict
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable

logger = logging.getLogger(__name__)


# ── Enums ────────────────────────────────────────────────────────────────────

class InvariantCategory(Enum):
    """Categories of synthesized invariants."""
    UNARY = "unary"                      # single variable
    BINARY = "binary"                    # two variable relationship
    ORDERING = "ordering"                # variable ordering
    IMPLICATION = "implication"          # if-then relationship
    CONSERVATION = "conservation"        # conservation law
    MONOTONIC = "monotonic"              # monotonically increasing/decreasing
    BOUNDED = "bounded"                  # bounded range
    MEMBERSHIP = "membership"            # set membership
    TEMPORAL = "temporal"                # temporal ordering
    FUNCTIONAL = "functional"            # functional dependency
    CROSS_CONTRACT = "cross_contract"    # cross-contract relationship
    ZK_SPECIFIC = "zk_specific"          # ZK proof-related
    PRIVACY_POOL = "privacy_pool"        # privacy pool balance
    BRIDGE = "bridge"                    # cross-chain bridge
    ACCESS_CONTROL = "access_control"    # permission-based


class InvariantStrength(Enum):
    """Confidence strength of synthesized invariant."""
    HYPOTHESIS = "hypothesis"    # observed but unconfirmed
    LIKELY = "likely"            # statistically likely (>90% confidence)
    STRONG = "strong"            # very strong (>99% confidence, many traces)
    PROVEN = "proven"            # formally verified or never violated


class TemplateKind(Enum):
    """Kinds of invariant templates."""
    # Unary
    NON_ZERO = "non_zero"
    NON_NEGATIVE = "non_negative"
    BOUNDED_ABOVE = "bounded_above"
    BOUNDED_BELOW = "bounded_below"
    CONSTANT = "constant"
    POWER_OF_TWO = "power_of_two"
    EVEN = "even"
    MODULAR = "modular"

    # Binary
    EQUAL = "equal"
    NOT_EQUAL = "not_equal"
    LESS_THAN = "less_than"
    LESS_EQUAL = "less_equal"
    DIVIDES = "divides"
    LINEAR = "linear"            # y = a*x + b

    # Ordering
    SORTED = "sorted"
    STRICTLY_INCREASING = "strictly_increasing"
    STRICTLY_DECREASING = "strictly_decreasing"

    # Implication
    IF_THEN = "if_then"          # P(x) => Q(y)
    IFF = "iff"                  # P(x) <=> Q(y)

    # Conservation
    SUM_CONSTANT = "sum_constant"       # x + y = C
    PRODUCT_CONSTANT = "product_constant"  # x * y = C
    BALANCE_EQUATION = "balance_equation"  # deposits - withdrawals = balance

    # Set/Membership
    ONE_OF = "one_of"            # x ∈ {v1, v2, ...}
    SUBSET = "subset"

    # Temporal
    HAPPENS_BEFORE = "happens_before"
    NEVER_AFTER = "never_after"
    ALWAYS_FOLLOWED = "always_followed"

    # Soul-specific
    NULLIFIER_UNIQUE = "nullifier_unique"
    PROOF_REQUIRED = "proof_required"
    MERKLE_UPDATED = "merkle_updated"
    NO_INFLATION = "no_inflation"
    RATE_LIMITED = "rate_limited"
    ACCESS_RESTRICTED = "access_restricted"


# ── Data Classes ─────────────────────────────────────────────────────────────

@dataclass
class ExecutionTrace:
    """A single execution trace with pre/post state."""
    trace_id: str = ""
    function_name: str = ""
    contract_name: str = ""
    caller: str = ""
    msg_value: int = 0
    inputs: dict[str, Any] = field(default_factory=dict)
    state_before: dict[str, Any] = field(default_factory=dict)
    state_after: dict[str, Any] = field(default_factory=dict)
    return_value: Any = None
    reverted: bool = False
    revert_reason: str = ""
    gas_used: int = 0
    events: list[dict[str, Any]] = field(default_factory=list)
    timestamp: float = 0.0
    block_number: int = 0


@dataclass
class InvariantTemplate:
    """A template for synthesizing invariants."""
    kind: TemplateKind
    category: InvariantCategory
    variables: list[str]           # variable names that fill template slots
    parameters: dict[str, Any] = field(default_factory=dict)  # e.g., bound values
    expression: str = ""           # human-readable expression
    check_fn: Callable[..., bool] | None = None  # executable check
    soul_relevance: float = 0.0    # 0.0-1.0 relevance to Soul Protocol


@dataclass
class SynthesizedInvariant:
    """An invariant discovered through synthesis."""
    id: str = ""
    template_kind: TemplateKind = TemplateKind.NON_ZERO
    category: InvariantCategory = InvariantCategory.UNARY
    expression: str = ""
    variables: list[str] = field(default_factory=list)
    parameters: dict[str, Any] = field(default_factory=dict)
    strength: InvariantStrength = InvariantStrength.HYPOTHESIS
    confidence: float = 0.0        # 0.0-1.0
    support: int = 0               # number of traces supporting
    counter_examples: int = 0      # number of traces violating
    first_seen_trace: str = ""
    soul_relevance: float = 0.0
    description: str = ""
    check_expression: str = ""     # Solidity-like check
    fuzz_strategy: str = ""        # recommended fuzz strategy

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "template": self.template_kind.value,
            "category": self.category.value,
            "expression": self.expression,
            "variables": self.variables,
            "parameters": self.parameters,
            "strength": self.strength.value,
            "confidence": round(self.confidence, 4),
            "support": self.support,
            "counter_examples": self.counter_examples,
            "soul_relevance": round(self.soul_relevance, 2),
            "description": self.description,
            "check_expression": self.check_expression,
            "fuzz_strategy": self.fuzz_strategy,
        }


@dataclass
class SynthesisResult:
    """Result of invariant synthesis campaign."""
    invariants: list[SynthesizedInvariant] = field(default_factory=list)
    traces_analyzed: int = 0
    templates_tried: int = 0
    candidates_generated: int = 0
    candidates_pruned: int = 0
    synthesis_time_sec: float = 0.0
    variables_tracked: int = 0
    relationships_found: int = 0

    # By category
    by_category: dict[str, int] = field(default_factory=dict)
    by_strength: dict[str, int] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "invariants": [inv.to_dict() for inv in self.invariants],
            "traces_analyzed": self.traces_analyzed,
            "templates_tried": self.templates_tried,
            "candidates_generated": self.candidates_generated,
            "candidates_pruned": self.candidates_pruned,
            "synthesis_time_sec": round(self.synthesis_time_sec, 2),
            "variables_tracked": self.variables_tracked,
            "relationships_found": self.relationships_found,
            "by_category": self.by_category,
            "by_strength": self.by_strength,
            "summary": {
                "total": len(self.invariants),
                "proven": sum(1 for i in self.invariants if i.strength == InvariantStrength.PROVEN),
                "strong": sum(1 for i in self.invariants if i.strength == InvariantStrength.STRONG),
                "likely": sum(1 for i in self.invariants if i.strength == InvariantStrength.LIKELY),
                "hypothesis": sum(1 for i in self.invariants if i.strength == InvariantStrength.HYPOTHESIS),
            },
        }


# ── Trace Collector ──────────────────────────────────────────────────────────

class TraceCollector:
    """Collects and preprocesses execution traces for invariant mining."""

    def __init__(self, max_traces: int = 50000) -> None:
        self.traces: list[ExecutionTrace] = []
        self.max_traces = max_traces
        self._variable_values: dict[str, list[Any]] = defaultdict(list)
        self._variable_types: dict[str, str] = {}
        self._state_diffs: list[dict[str, tuple[Any, Any]]] = []

    def add_trace(self, trace: ExecutionTrace) -> None:
        """Add an execution trace."""
        if len(self.traces) >= self.max_traces:
            # Reservoir sampling to keep representative set
            import random
            idx = random.randint(0, len(self.traces))
            if idx < self.max_traces:
                self.traces[idx] = trace
            return

        self.traces.append(trace)
        self._extract_variables(trace)

    def _extract_variables(self, trace: ExecutionTrace) -> None:
        """Extract variable values from trace for mining."""
        # Input variables
        for name, value in trace.inputs.items():
            var_name = f"input.{trace.function_name}.{name}"
            self._variable_values[var_name].append(value)
            self._infer_type(var_name, value)

        # State before
        for name, value in trace.state_before.items():
            var_name = f"state.{name}"
            self._variable_values[f"pre.{var_name}"].append(value)
            self._infer_type(f"pre.{var_name}", value)

        # State after
        for name, value in trace.state_after.items():
            var_name = f"state.{name}"
            self._variable_values[f"post.{var_name}"].append(value)
            self._infer_type(f"post.{var_name}", value)

        # State diff
        diff: dict[str, tuple[Any, Any]] = {}
        all_keys = set(trace.state_before.keys()) | set(trace.state_after.keys())
        for key in all_keys:
            before = trace.state_before.get(key)
            after = trace.state_after.get(key)
            if before != after:
                diff[key] = (before, after)
        self._state_diffs.append(diff)

        # Derived values
        if trace.msg_value > 0:
            self._variable_values["msg.value"].append(trace.msg_value)
        self._variable_values["gas_used"].append(trace.gas_used)
        self._variable_values["reverted"].append(trace.reverted)

    def _infer_type(self, var_name: str, value: Any) -> None:
        """Infer variable type from observed values."""
        if isinstance(value, bool):
            self._variable_types[var_name] = "bool"
        elif isinstance(value, int):
            if 0 <= value < 2**256:
                self._variable_types[var_name] = "uint256"
            else:
                self._variable_types[var_name] = "int256"
        elif isinstance(value, str):
            if value.startswith("0x") and len(value) == 42:
                self._variable_types[var_name] = "address"
            elif value.startswith("0x"):
                self._variable_types[var_name] = "bytes32"
            else:
                self._variable_types[var_name] = "string"
        elif isinstance(value, bytes):
            self._variable_types[var_name] = "bytes"
        elif isinstance(value, list):
            self._variable_types[var_name] = "array"

    def get_numeric_variables(self) -> dict[str, list[int | float]]:
        """Get all numeric variable series."""
        return {
            name: values
            for name, values in self._variable_values.items()
            if values and isinstance(values[0], (int, float))
            and self._variable_types.get(name, "") in ("uint256", "int256", "")
        }

    def get_boolean_variables(self) -> dict[str, list[bool]]:
        """Get all boolean variable series."""
        return {
            name: values
            for name, values in self._variable_values.items()
            if values and isinstance(values[0], bool)
        }

    def get_set_variables(self) -> dict[str, list[Any]]:
        """Get variables with small value domains (potential enums)."""
        return {
            name: values
            for name, values in self._variable_values.items()
            if values and len(set(values)) <= min(10, len(values) * 0.3 + 1)
        }

    @property
    def variable_count(self) -> int:
        return len(self._variable_values)


# ── Template Library ─────────────────────────────────────────────────────────

class InvariantTemplateLibrary:
    """Library of invariant templates for synthesis."""

    def __init__(self) -> None:
        self._templates: list[InvariantTemplate] = []
        self._register_all()

    def _register_all(self) -> None:
        """Register all invariant templates."""
        self._register_unary_templates()
        self._register_binary_templates()
        self._register_conservation_templates()
        self._register_implication_templates()
        self._register_temporal_templates()
        self._register_soul_templates()

    def _register_unary_templates(self) -> None:
        """Register single-variable templates."""
        self._templates.extend([
            InvariantTemplate(
                kind=TemplateKind.NON_ZERO,
                category=InvariantCategory.UNARY,
                variables=["x"],
                expression="x != 0",
            ),
            InvariantTemplate(
                kind=TemplateKind.NON_NEGATIVE,
                category=InvariantCategory.UNARY,
                variables=["x"],
                expression="x >= 0",
            ),
            InvariantTemplate(
                kind=TemplateKind.BOUNDED_ABOVE,
                category=InvariantCategory.BOUNDED,
                variables=["x"],
                parameters={"bound": None},
                expression="x <= BOUND",
            ),
            InvariantTemplate(
                kind=TemplateKind.BOUNDED_BELOW,
                category=InvariantCategory.BOUNDED,
                variables=["x"],
                parameters={"bound": None},
                expression="x >= BOUND",
            ),
            InvariantTemplate(
                kind=TemplateKind.CONSTANT,
                category=InvariantCategory.UNARY,
                variables=["x"],
                parameters={"value": None},
                expression="x == CONST",
            ),
            InvariantTemplate(
                kind=TemplateKind.POWER_OF_TWO,
                category=InvariantCategory.UNARY,
                variables=["x"],
                expression="x is power of 2",
            ),
            InvariantTemplate(
                kind=TemplateKind.ONE_OF,
                category=InvariantCategory.MEMBERSHIP,
                variables=["x"],
                parameters={"values": None},
                expression="x ∈ {v1, v2, ...}",
            ),
        ])

    def _register_binary_templates(self) -> None:
        """Register two-variable relationship templates."""
        self._templates.extend([
            InvariantTemplate(
                kind=TemplateKind.EQUAL,
                category=InvariantCategory.BINARY,
                variables=["x", "y"],
                expression="x == y",
            ),
            InvariantTemplate(
                kind=TemplateKind.NOT_EQUAL,
                category=InvariantCategory.BINARY,
                variables=["x", "y"],
                expression="x != y",
            ),
            InvariantTemplate(
                kind=TemplateKind.LESS_THAN,
                category=InvariantCategory.ORDERING,
                variables=["x", "y"],
                expression="x < y",
            ),
            InvariantTemplate(
                kind=TemplateKind.LESS_EQUAL,
                category=InvariantCategory.ORDERING,
                variables=["x", "y"],
                expression="x <= y",
            ),
            InvariantTemplate(
                kind=TemplateKind.DIVIDES,
                category=InvariantCategory.BINARY,
                variables=["x", "y"],
                expression="x divides y",
            ),
            InvariantTemplate(
                kind=TemplateKind.LINEAR,
                category=InvariantCategory.FUNCTIONAL,
                variables=["x", "y"],
                parameters={"a": None, "b": None},
                expression="y = a*x + b",
            ),
        ])

    def _register_conservation_templates(self) -> None:
        """Register conservation law templates."""
        self._templates.extend([
            InvariantTemplate(
                kind=TemplateKind.SUM_CONSTANT,
                category=InvariantCategory.CONSERVATION,
                variables=["x", "y"],
                parameters={"constant": None},
                expression="x + y == C",
                soul_relevance=0.9,
            ),
            InvariantTemplate(
                kind=TemplateKind.BALANCE_EQUATION,
                category=InvariantCategory.CONSERVATION,
                variables=["deposits", "withdrawals", "balance"],
                expression="deposits - withdrawals == balance",
                soul_relevance=1.0,
            ),
            InvariantTemplate(
                kind=TemplateKind.NO_INFLATION,
                category=InvariantCategory.CONSERVATION,
                variables=["total_supply", "max_supply"],
                expression="total_supply <= max_supply",
                soul_relevance=1.0,
            ),
        ])

    def _register_implication_templates(self) -> None:
        """Register implication templates."""
        self._templates.extend([
            InvariantTemplate(
                kind=TemplateKind.IF_THEN,
                category=InvariantCategory.IMPLICATION,
                variables=["P", "Q"],
                expression="P => Q",
            ),
            InvariantTemplate(
                kind=TemplateKind.IFF,
                category=InvariantCategory.IMPLICATION,
                variables=["P", "Q"],
                expression="P <=> Q",
            ),
        ])

    def _register_temporal_templates(self) -> None:
        """Register temporal ordering templates."""
        self._templates.extend([
            InvariantTemplate(
                kind=TemplateKind.HAPPENS_BEFORE,
                category=InvariantCategory.TEMPORAL,
                variables=["event_a", "event_b"],
                expression="A always happens before B",
                soul_relevance=0.8,
            ),
            InvariantTemplate(
                kind=TemplateKind.NEVER_AFTER,
                category=InvariantCategory.TEMPORAL,
                variables=["event_a", "event_b"],
                expression="A never happens after B",
                soul_relevance=0.8,
            ),
            InvariantTemplate(
                kind=TemplateKind.ALWAYS_FOLLOWED,
                category=InvariantCategory.TEMPORAL,
                variables=["event_a", "event_b"],
                expression="A is always followed by B",
                soul_relevance=0.7,
            ),
        ])

    def _register_soul_templates(self) -> None:
        """Register Soul Protocol-specific invariant templates."""
        self._templates.extend([
            InvariantTemplate(
                kind=TemplateKind.NULLIFIER_UNIQUE,
                category=InvariantCategory.ZK_SPECIFIC,
                variables=["nullifier"],
                expression="∀ n: nullifier[n] used at most once",
                soul_relevance=1.0,
            ),
            InvariantTemplate(
                kind=TemplateKind.PROOF_REQUIRED,
                category=InvariantCategory.ZK_SPECIFIC,
                variables=["function", "proof"],
                expression="function requires valid proof",
                soul_relevance=1.0,
            ),
            InvariantTemplate(
                kind=TemplateKind.MERKLE_UPDATED,
                category=InvariantCategory.ZK_SPECIFIC,
                variables=["merkle_root", "operation"],
                expression="merkle_root updated after state change",
                soul_relevance=1.0,
            ),
            InvariantTemplate(
                kind=TemplateKind.NO_INFLATION,
                category=InvariantCategory.PRIVACY_POOL,
                variables=["pool_balance", "deposits", "withdrawals"],
                expression="pool_balance == deposits - withdrawals",
                soul_relevance=1.0,
            ),
            InvariantTemplate(
                kind=TemplateKind.RATE_LIMITED,
                category=InvariantCategory.ACCESS_CONTROL,
                variables=["operations", "window", "max_rate"],
                expression="operations / window <= max_rate",
                soul_relevance=0.9,
            ),
            InvariantTemplate(
                kind=TemplateKind.ACCESS_RESTRICTED,
                category=InvariantCategory.ACCESS_CONTROL,
                variables=["caller", "function", "role"],
                expression="caller must have role for function",
                soul_relevance=0.9,
            ),
        ])

    def get_templates(
        self,
        category: InvariantCategory | None = None,
        min_soul_relevance: float = 0.0,
    ) -> list[InvariantTemplate]:
        """Get templates, optionally filtered."""
        templates = self._templates
        if category:
            templates = [t for t in templates if t.category == category]
        if min_soul_relevance > 0:
            templates = [t for t in templates if t.soul_relevance >= min_soul_relevance]
        return templates

    @property
    def template_count(self) -> int:
        return len(self._templates)


# ── Candidate Generator ─────────────────────────────────────────────────────

class CandidateGenerator:
    """Generates invariant candidates by instantiating templates with variables."""

    def __init__(
        self,
        templates: InvariantTemplateLibrary,
        max_candidates: int = 100000,
    ) -> None:
        self._templates = templates
        self._max_candidates = max_candidates

    def generate(
        self,
        collector: TraceCollector,
    ) -> list[SynthesizedInvariant]:
        """Generate candidate invariants from traces and templates."""
        candidates: list[SynthesizedInvariant] = []

        numeric_vars = collector.get_numeric_variables()
        bool_vars = collector.get_boolean_variables()
        set_vars = collector.get_set_variables()

        # 1. Unary candidates
        candidates.extend(self._generate_unary(numeric_vars))

        # 2. Binary candidates (limit pairs to avoid explosion)
        candidates.extend(self._generate_binary(numeric_vars))

        # 3. Conservation candidates
        candidates.extend(self._generate_conservation(numeric_vars))

        # 4. Implication candidates
        candidates.extend(self._generate_implications(bool_vars, numeric_vars))

        # 5. Membership candidates
        candidates.extend(self._generate_membership(set_vars))

        # 6. Soul-specific candidates
        candidates.extend(self._generate_soul_specific(collector))

        # Truncate
        if len(candidates) > self._max_candidates:
            candidates.sort(key=lambda c: c.soul_relevance, reverse=True)
            candidates = candidates[:self._max_candidates]

        return candidates

    def _generate_unary(
        self, numeric_vars: dict[str, list[int | float]],
    ) -> list[SynthesizedInvariant]:
        """Generate unary invariant candidates."""
        candidates: list[SynthesizedInvariant] = []

        for var_name, values in numeric_vars.items():
            if not values:
                continue

            int_values = [v for v in values if isinstance(v, int)]
            if not int_values:
                continue

            min_val = min(int_values)
            max_val = max(int_values)
            unique = set(int_values)

            # Constant invariant
            if len(unique) == 1:
                candidates.append(SynthesizedInvariant(
                    id=self._gen_id("const", var_name),
                    template_kind=TemplateKind.CONSTANT,
                    category=InvariantCategory.UNARY,
                    expression=f"{var_name} == {int_values[0]}",
                    variables=[var_name],
                    parameters={"value": int_values[0]},
                    confidence=1.0,
                    support=len(values),
                    description=f"{var_name} is always {int_values[0]}",
                    check_expression=f"assert({var_name} == {int_values[0]});",
                ))

            # Non-zero
            if all(v != 0 for v in int_values):
                candidates.append(SynthesizedInvariant(
                    id=self._gen_id("nz", var_name),
                    template_kind=TemplateKind.NON_ZERO,
                    category=InvariantCategory.UNARY,
                    expression=f"{var_name} != 0",
                    variables=[var_name],
                    confidence=1.0,
                    support=len(values),
                    description=f"{var_name} is never zero",
                    check_expression=f"assert({var_name} != 0);",
                ))

            # Non-negative (relevant for int256)
            if all(v >= 0 for v in int_values) and min_val >= 0:
                candidates.append(SynthesizedInvariant(
                    id=self._gen_id("nn", var_name),
                    template_kind=TemplateKind.NON_NEGATIVE,
                    category=InvariantCategory.UNARY,
                    expression=f"{var_name} >= 0",
                    variables=[var_name],
                    confidence=1.0,
                    support=len(values),
                    description=f"{var_name} is never negative",
                    check_expression=f"assert(int256({var_name}) >= 0);",
                ))

            # Bounded above
            if max_val < 2**256 - 1:
                candidates.append(SynthesizedInvariant(
                    id=self._gen_id("bnd", var_name),
                    template_kind=TemplateKind.BOUNDED_ABOVE,
                    category=InvariantCategory.BOUNDED,
                    expression=f"{var_name} <= {max_val}",
                    variables=[var_name],
                    parameters={"bound": max_val},
                    confidence=0.9,
                    support=len(values),
                    description=f"{var_name} never exceeds {max_val}",
                    check_expression=f"assert({var_name} <= {max_val});",
                ))

            # Power of two
            if all(v > 0 and (v & (v - 1)) == 0 for v in int_values if v > 0):
                if all(v > 0 for v in int_values):
                    candidates.append(SynthesizedInvariant(
                        id=self._gen_id("pow2", var_name),
                        template_kind=TemplateKind.POWER_OF_TWO,
                        category=InvariantCategory.UNARY,
                        expression=f"{var_name} is power of 2",
                        variables=[var_name],
                        confidence=0.8,
                        support=len(values),
                        description=f"{var_name} is always a power of 2",
                    ))

            # Small domain (membership)
            if 2 <= len(unique) <= 5 and len(values) >= 10:
                candidates.append(SynthesizedInvariant(
                    id=self._gen_id("mem", var_name),
                    template_kind=TemplateKind.ONE_OF,
                    category=InvariantCategory.MEMBERSHIP,
                    expression=f"{var_name} ∈ {{{', '.join(str(v) for v in sorted(unique))}}}",
                    variables=[var_name],
                    parameters={"values": sorted(unique)},
                    confidence=0.95,
                    support=len(values),
                    description=f"{var_name} is always one of {sorted(unique)}",
                ))

        return candidates

    def _generate_binary(
        self, numeric_vars: dict[str, list[int | float]],
    ) -> list[SynthesizedInvariant]:
        """Generate binary relationship candidates."""
        candidates: list[SynthesizedInvariant] = []
        var_names = list(numeric_vars.keys())

        # Limit pairs to avoid O(n^2) explosion
        max_pairs = 500
        pair_count = 0

        for i in range(len(var_names)):
            for j in range(i + 1, len(var_names)):
                if pair_count >= max_pairs:
                    break

                name_a = var_names[i]
                name_b = var_names[j]
                vals_a = numeric_vars[name_a]
                vals_b = numeric_vars[name_b]

                # Align by trace index
                n = min(len(vals_a), len(vals_b))
                if n < 3:
                    continue

                a = [v for v in vals_a[:n] if isinstance(v, (int, float))]
                b = [v for v in vals_b[:n] if isinstance(v, (int, float))]
                if len(a) != n or len(b) != n:
                    continue

                pair_count += 1

                # Equal
                if all(a[k] == b[k] for k in range(n)):
                    candidates.append(SynthesizedInvariant(
                        id=self._gen_id("eq", name_a, name_b),
                        template_kind=TemplateKind.EQUAL,
                        category=InvariantCategory.BINARY,
                        expression=f"{name_a} == {name_b}",
                        variables=[name_a, name_b],
                        confidence=1.0,
                        support=n,
                        description=f"{name_a} always equals {name_b}",
                        check_expression=f"assert({name_a} == {name_b});",
                    ))

                # Less-equal
                if all(a[k] <= b[k] for k in range(n)):
                    candidates.append(SynthesizedInvariant(
                        id=self._gen_id("le", name_a, name_b),
                        template_kind=TemplateKind.LESS_EQUAL,
                        category=InvariantCategory.ORDERING,
                        expression=f"{name_a} <= {name_b}",
                        variables=[name_a, name_b],
                        confidence=1.0,
                        support=n,
                        description=f"{name_a} always <= {name_b}",
                        check_expression=f"assert({name_a} <= {name_b});",
                    ))

                # Sum constant
                sums = [a[k] + b[k] for k in range(n)]
                if len(set(sums)) == 1:
                    c = sums[0]
                    candidates.append(SynthesizedInvariant(
                        id=self._gen_id("sum", name_a, name_b),
                        template_kind=TemplateKind.SUM_CONSTANT,
                        category=InvariantCategory.CONSERVATION,
                        expression=f"{name_a} + {name_b} == {c}",
                        variables=[name_a, name_b],
                        parameters={"constant": c},
                        confidence=1.0,
                        support=n,
                        soul_relevance=0.9,
                        description=f"Sum of {name_a} and {name_b} is always {c}",
                        check_expression=f"assert({name_a} + {name_b} == {c});",
                        fuzz_strategy="conservation_break",
                    ))

                # Linear relationship: try y = a*x + b using first two distinct points
                if len(set(a)) >= 2:
                    # Find two distinct x values
                    idx1 = 0
                    idx2 = next((k for k in range(1, n) if a[k] != a[idx1]), None)
                    if idx2 is not None:
                        x1, y1 = a[idx1], b[idx1]
                        x2, y2 = a[idx2], b[idx2]
                        dx = x2 - x1
                        if dx != 0:
                            slope = (y2 - y1) / dx
                            intercept = y1 - slope * x1
                            # Check if relationship holds for all points
                            fits = all(
                                abs(b[k] - (slope * a[k] + intercept)) < 1e-6
                                for k in range(n)
                            )
                            if fits and slope != 0:
                                candidates.append(SynthesizedInvariant(
                                    id=self._gen_id("lin", name_a, name_b),
                                    template_kind=TemplateKind.LINEAR,
                                    category=InvariantCategory.FUNCTIONAL,
                                    expression=f"{name_b} = {slope}*{name_a} + {intercept}",
                                    variables=[name_a, name_b],
                                    parameters={"a": slope, "b": intercept},
                                    confidence=1.0,
                                    support=n,
                                    description=f"Linear relationship between {name_a} and {name_b}",
                                ))

        return candidates

    def _generate_conservation(
        self, numeric_vars: dict[str, list[int | float]],
    ) -> list[SynthesizedInvariant]:
        """Generate conservation law candidates (deposits - withdrawals = balance)."""
        candidates: list[SynthesizedInvariant] = []

        # Look for variable triplets with conservation pattern
        deposit_vars = [n for n in numeric_vars if "deposit" in n.lower() or "in" in n.lower()]
        withdraw_vars = [n for n in numeric_vars if "withdraw" in n.lower() or "out" in n.lower()]
        balance_vars = [n for n in numeric_vars if "balance" in n.lower() or "pool" in n.lower()]

        for d_name in deposit_vars:
            for w_name in withdraw_vars:
                for b_name in balance_vars:
                    d_vals = numeric_vars[d_name]
                    w_vals = numeric_vars[w_name]
                    b_vals = numeric_vars[b_name]

                    n = min(len(d_vals), len(w_vals), len(b_vals))
                    if n < 3:
                        continue

                    # Check deposits - withdrawals == balance
                    holds = all(
                        isinstance(d_vals[k], (int, float))
                        and isinstance(w_vals[k], (int, float))
                        and isinstance(b_vals[k], (int, float))
                        and abs(d_vals[k] - w_vals[k] - b_vals[k]) < 1e-6
                        for k in range(n)
                    )

                    if holds:
                        candidates.append(SynthesizedInvariant(
                            id=self._gen_id("bal", d_name, w_name, b_name),
                            template_kind=TemplateKind.BALANCE_EQUATION,
                            category=InvariantCategory.CONSERVATION,
                            expression=f"{d_name} - {w_name} == {b_name}",
                            variables=[d_name, w_name, b_name],
                            confidence=1.0,
                            support=n,
                            soul_relevance=1.0,
                            description=f"Balance conservation: {d_name} - {w_name} = {b_name}",
                            check_expression=f"assert({d_name} - {w_name} == {b_name});",
                            fuzz_strategy="balance_break",
                        ))

        return candidates

    def _generate_implications(
        self,
        bool_vars: dict[str, list[bool]],
        numeric_vars: dict[str, list[int | float]],
    ) -> list[SynthesizedInvariant]:
        """Generate implication candidates (P => Q)."""
        candidates: list[SynthesizedInvariant] = []
        bool_names = list(bool_vars.keys())

        for i in range(len(bool_names)):
            for j in range(len(bool_names)):
                if i == j:
                    continue

                name_p = bool_names[i]
                name_q = bool_names[j]
                p_vals = bool_vars[name_p]
                q_vals = bool_vars[name_q]

                n = min(len(p_vals), len(q_vals))
                if n < 5:
                    continue

                # P => Q: whenever P is true, Q is also true
                implies = all(
                    (not p_vals[k]) or q_vals[k]
                    for k in range(n)
                )

                if implies and any(p_vals[k] for k in range(n)):
                    candidates.append(SynthesizedInvariant(
                        id=self._gen_id("impl", name_p, name_q),
                        template_kind=TemplateKind.IF_THEN,
                        category=InvariantCategory.IMPLICATION,
                        expression=f"{name_p} => {name_q}",
                        variables=[name_p, name_q],
                        confidence=1.0,
                        support=n,
                        description=f"Whenever {name_p}, then {name_q}",
                    ))

        return candidates

    def _generate_membership(
        self, set_vars: dict[str, list[Any]],
    ) -> list[SynthesizedInvariant]:
        """Generate set membership candidates."""
        candidates: list[SynthesizedInvariant] = []

        for var_name, values in set_vars.items():
            if not values:
                continue
            unique = sorted(set(str(v) for v in values))
            if 2 <= len(unique) <= 8:
                candidates.append(SynthesizedInvariant(
                    id=self._gen_id("set", var_name),
                    template_kind=TemplateKind.ONE_OF,
                    category=InvariantCategory.MEMBERSHIP,
                    expression=f"{var_name} ∈ {{{', '.join(unique)}}}",
                    variables=[var_name],
                    parameters={"values": unique},
                    confidence=0.9,
                    support=len(values),
                    description=f"{var_name} is always one of {unique}",
                ))

        return candidates

    def _generate_soul_specific(
        self, collector: TraceCollector,
    ) -> list[SynthesizedInvariant]:
        """Generate Soul Protocol-specific invariant candidates."""
        candidates: list[SynthesizedInvariant] = []

        # Analyze traces for Soul patterns
        nullifier_uses: dict[str, int] = defaultdict(int)
        proof_functions: set[str] = set()
        state_changes_after_deposit: list[bool] = []

        for trace in collector.traces:
            # Nullifier uniqueness
            for key, val in trace.inputs.items():
                if "nullifier" in key.lower():
                    nullifier_uses[str(val)] += 1

            # Proof requirement
            has_proof = any("proof" in k.lower() for k in trace.inputs)
            if has_proof:
                proof_functions.add(trace.function_name)

            # State changes after deposit
            if "deposit" in trace.function_name.lower():
                merkle_before = trace.state_before.get("merkle_root")
                merkle_after = trace.state_after.get("merkle_root")
                if merkle_before and merkle_after:
                    state_changes_after_deposit.append(merkle_before != merkle_after)

        # Nullifier uniqueness invariant
        duplicate_nullifiers = {n: c for n, c in nullifier_uses.items() if c > 1}
        if nullifier_uses and not duplicate_nullifiers:
            candidates.append(SynthesizedInvariant(
                id=self._gen_id("soul", "nullifier_unique"),
                template_kind=TemplateKind.NULLIFIER_UNIQUE,
                category=InvariantCategory.ZK_SPECIFIC,
                expression="∀ n: nullifier_registry[n] used at most once",
                variables=["nullifier"],
                confidence=1.0,
                support=len(nullifier_uses),
                soul_relevance=1.0,
                description="No nullifier is registered more than once",
                check_expression="assert(!nullifierUsed[nullifier]);",
                fuzz_strategy="replay_nullifier",
            ))

        # Proof requirement invariant
        for fn in proof_functions:
            candidates.append(SynthesizedInvariant(
                id=self._gen_id("soul", "proof_req", fn),
                template_kind=TemplateKind.PROOF_REQUIRED,
                category=InvariantCategory.ZK_SPECIFIC,
                expression=f"{fn} requires valid proof",
                variables=["proof", fn],
                confidence=0.9,
                support=sum(1 for t in collector.traces if t.function_name == fn),
                soul_relevance=1.0,
                description=f"Function {fn} requires valid ZK proof",
                check_expression=f"assert(verifyProof(proof)); // in {fn}",
                fuzz_strategy="corrupt_proof",
            ))

        # Merkle update after deposit
        if state_changes_after_deposit and all(state_changes_after_deposit):
            candidates.append(SynthesizedInvariant(
                id=self._gen_id("soul", "merkle_update"),
                template_kind=TemplateKind.MERKLE_UPDATED,
                category=InvariantCategory.ZK_SPECIFIC,
                expression="merkle_root changes after deposit",
                variables=["merkle_root", "deposit"],
                confidence=1.0,
                support=len(state_changes_after_deposit),
                soul_relevance=1.0,
                description="Merkle root is always updated after a successful deposit",
                check_expression="assert(post.merkleRoot != pre.merkleRoot); // after deposit",
                fuzz_strategy="stale_merkle_root",
            ))

        return candidates

    def _gen_id(self, *parts: str) -> str:
        """Generate a unique invariant ID."""
        raw = ":".join(parts)
        return f"SYNTH-{hashlib.sha256(raw.encode()).hexdigest()[:12]}"


# ── Counter-Example Pruner ───────────────────────────────────────────────────

class CounterExamplePruner:
    """Prunes candidate invariants using counter-examples from traces."""

    def __init__(self, min_support: int = 5, min_confidence: float = 0.9) -> None:
        self._min_support = min_support
        self._min_confidence = min_confidence

    def prune(
        self,
        candidates: list[SynthesizedInvariant],
        collector: TraceCollector,
    ) -> list[SynthesizedInvariant]:
        """Test candidates against all traces, prune those that fail."""
        surviving: list[SynthesizedInvariant] = []

        for candidate in candidates:
            support, violations = self._test_candidate(candidate, collector)
            candidate.support = support
            candidate.counter_examples = violations

            total = support + violations
            if total == 0:
                continue

            candidate.confidence = support / total

            # Determine strength
            if violations == 0 and support >= 100:
                candidate.strength = InvariantStrength.PROVEN
            elif violations == 0 and support >= 20:
                candidate.strength = InvariantStrength.STRONG
            elif candidate.confidence >= 0.95 and support >= self._min_support:
                candidate.strength = InvariantStrength.LIKELY
            elif candidate.confidence >= self._min_confidence and support >= self._min_support:
                candidate.strength = InvariantStrength.HYPOTHESIS
            else:
                continue  # Too weak — prune

            surviving.append(candidate)

        return surviving

    def _test_candidate(
        self,
        candidate: SynthesizedInvariant,
        collector: TraceCollector,
    ) -> tuple[int, int]:
        """Test a candidate invariant against traces. Returns (support, violations)."""
        support = 0
        violations = 0

        for trace in collector.traces:
            result = self._evaluate_candidate(candidate, trace)
            if result is None:
                continue  # Not applicable
            elif result:
                support += 1
            else:
                violations += 1

        return support, violations

    def _evaluate_candidate(
        self,
        candidate: SynthesizedInvariant,
        trace: ExecutionTrace,
    ) -> bool | None:
        """Evaluate a candidate invariant against a single trace.

        Returns True (holds), False (violated), or None (not applicable).
        """
        kind = candidate.template_kind
        vars_ = candidate.variables
        params = candidate.parameters

        # Resolve variable values from trace
        values = {}
        for var in vars_:
            val = self._resolve_variable(var, trace)
            if val is None:
                return None  # Variable not present
            values[var] = val

        try:
            if kind == TemplateKind.CONSTANT:
                return values[vars_[0]] == params.get("value")

            elif kind == TemplateKind.NON_ZERO:
                return values[vars_[0]] != 0

            elif kind == TemplateKind.NON_NEGATIVE:
                return values[vars_[0]] >= 0

            elif kind == TemplateKind.BOUNDED_ABOVE:
                return values[vars_[0]] <= params.get("bound", float("inf"))

            elif kind == TemplateKind.BOUNDED_BELOW:
                return values[vars_[0]] >= params.get("bound", float("-inf"))

            elif kind == TemplateKind.EQUAL:
                return values[vars_[0]] == values[vars_[1]]

            elif kind == TemplateKind.LESS_EQUAL:
                return values[vars_[0]] <= values[vars_[1]]

            elif kind == TemplateKind.LESS_THAN:
                return values[vars_[0]] < values[vars_[1]]

            elif kind == TemplateKind.SUM_CONSTANT:
                c = params.get("constant", 0)
                return abs(values[vars_[0]] + values[vars_[1]] - c) < 1e-6

            elif kind == TemplateKind.BALANCE_EQUATION:
                if len(vars_) >= 3:
                    return abs(values[vars_[0]] - values[vars_[1]] - values[vars_[2]]) < 1e-6
                return None

            elif kind in (
                TemplateKind.NULLIFIER_UNIQUE,
                TemplateKind.PROOF_REQUIRED,
                TemplateKind.MERKLE_UPDATED,
            ):
                # Soul-specific — already validated during generation
                return True

            elif kind == TemplateKind.ONE_OF:
                allowed = params.get("values", [])
                return values[vars_[0]] in allowed or str(values[vars_[0]]) in allowed

        except (TypeError, KeyError, IndexError, ValueError):
            return None

        return None

    def _resolve_variable(
        self, var_name: str, trace: ExecutionTrace,
    ) -> Any | None:
        """Resolve a variable name to its value in a trace."""
        # Direct input
        if var_name.startswith("input."):
            parts = var_name.split(".", 2)
            if len(parts) == 3 and parts[1] == trace.function_name:
                return trace.inputs.get(parts[2])
            return None

        # Pre-state
        if var_name.startswith("pre.state."):
            key = var_name[len("pre.state."):]
            return trace.state_before.get(key)

        # Post-state
        if var_name.startswith("post.state."):
            key = var_name[len("post.state."):]
            return trace.state_after.get(key)

        # Built-in
        if var_name == "msg.value":
            return trace.msg_value
        if var_name == "gas_used":
            return trace.gas_used
        if var_name == "reverted":
            return trace.reverted

        # Try state before/after directly
        if var_name in trace.state_before:
            return trace.state_before[var_name]
        if var_name in trace.state_after:
            return trace.state_after[var_name]
        if var_name in trace.inputs:
            return trace.inputs[var_name]

        return None


# ── Statistical Validator ────────────────────────────────────────────────────

class StatisticalValidator:
    """Validates invariants using statistical tests."""

    def validate(
        self,
        invariants: list[SynthesizedInvariant],
        collector: TraceCollector,
    ) -> list[SynthesizedInvariant]:
        """Apply statistical validation to refine confidence estimates."""
        for inv in invariants:
            # Wilson score interval for confidence
            n = inv.support + inv.counter_examples
            if n > 0:
                p = inv.support / n
                z = 1.96  # 95% confidence
                denominator = 1 + z**2 / n
                center = (p + z**2 / (2 * n)) / denominator
                spread = z * math.sqrt(p * (1 - p) / n + z**2 / (4 * n**2)) / denominator
                inv.confidence = max(0, center - spread)  # lower bound

            # Adjust strength based on statistical confidence
            if inv.confidence >= 0.99 and n >= 50:
                inv.strength = InvariantStrength.PROVEN
            elif inv.confidence >= 0.95 and n >= 20:
                inv.strength = InvariantStrength.STRONG
            elif inv.confidence >= 0.90 and n >= 10:
                inv.strength = InvariantStrength.LIKELY

        return invariants


# ── Invariant Ranker ─────────────────────────────────────────────────────────

class InvariantRanker:
    """Ranks synthesized invariants by importance for fuzzing."""

    def rank(
        self, invariants: list[SynthesizedInvariant],
    ) -> list[SynthesizedInvariant]:
        """Sort invariants by importance score."""
        for inv in invariants:
            score = self._compute_score(inv)
            inv.parameters["importance_score"] = score

        invariants.sort(
            key=lambda i: i.parameters.get("importance_score", 0),
            reverse=True,
        )
        return invariants

    def _compute_score(self, inv: SynthesizedInvariant) -> float:
        """Compute importance score for an invariant."""
        score = 0.0

        # Strength weight
        strength_weights = {
            InvariantStrength.PROVEN: 4.0,
            InvariantStrength.STRONG: 3.0,
            InvariantStrength.LIKELY: 2.0,
            InvariantStrength.HYPOTHESIS: 1.0,
        }
        score += strength_weights.get(inv.strength, 0)

        # Soul relevance (high boost for protocol-specific)
        score += inv.soul_relevance * 5.0

        # Category weight (security-critical categories get higher score)
        category_weights = {
            InvariantCategory.CONSERVATION: 3.0,
            InvariantCategory.ZK_SPECIFIC: 4.0,
            InvariantCategory.PRIVACY_POOL: 3.5,
            InvariantCategory.BRIDGE: 3.0,
            InvariantCategory.ACCESS_CONTROL: 2.5,
            InvariantCategory.IMPLICATION: 1.5,
            InvariantCategory.ORDERING: 1.0,
            InvariantCategory.UNARY: 0.5,
        }
        score += category_weights.get(inv.category, 1.0)

        # Support bonus (more evidence = more trusted)
        score += min(math.log2(max(inv.support, 1)), 5)

        # Confidence
        score += inv.confidence * 2.0

        # Has fuzz strategy (actionable)
        if inv.fuzz_strategy:
            score += 2.0

        return round(score, 2)


# ── Main Synthesis Engine ────────────────────────────────────────────────────

class InvariantSynthesisEngine:
    """Complete Daikon-style invariant synthesis engine.

    Discovers new invariants from execution traces using template-based
    synthesis, counter-example pruning, and statistical validation.

    Usage:
        engine = InvariantSynthesisEngine()
        # Add traces from fuzzing
        for trace in execution_traces:
            engine.add_trace(trace)
        # Synthesize invariants
        result = engine.synthesize()
    """

    def __init__(
        self,
        max_traces: int = 50000,
        min_support: int = 5,
        min_confidence: float = 0.9,
    ) -> None:
        self._collector = TraceCollector(max_traces=max_traces)
        self._template_library = InvariantTemplateLibrary()
        self._candidate_generator = CandidateGenerator(self._template_library)
        self._pruner = CounterExamplePruner(
            min_support=min_support,
            min_confidence=min_confidence,
        )
        self._validator = StatisticalValidator()
        self._ranker = InvariantRanker()
        self._known_invariants: list[SynthesizedInvariant] = []

    def add_trace(self, trace: ExecutionTrace) -> None:
        """Add an execution trace for analysis."""
        self._collector.add_trace(trace)

    def add_traces_from_results(
        self, results: list[dict[str, Any]],
    ) -> None:
        """Add execution traces from fuzzing results (dict format)."""
        for r in results:
            trace = ExecutionTrace(
                trace_id=r.get("trace_id", ""),
                function_name=r.get("function", ""),
                contract_name=r.get("contract", ""),
                caller=r.get("caller", ""),
                msg_value=r.get("msg_value", 0),
                inputs=r.get("inputs", {}),
                state_before=r.get("state_before", {}),
                state_after=r.get("state_after", {}),
                return_value=r.get("return_value"),
                reverted=r.get("reverted", False),
                revert_reason=r.get("revert_reason", ""),
                gas_used=r.get("gas_used", 0),
                events=r.get("events", []),
                timestamp=r.get("timestamp", time.time()),
            )
            self._collector.add_trace(trace)

    def synthesize(self) -> SynthesisResult:
        """Run complete invariant synthesis pipeline.

        Steps:
        1. Generate candidates from templates + traces
        2. Prune with counter-examples
        3. Validate statistically
        4. Rank by importance
        5. De-duplicate against known invariants
        """
        start = time.time()
        result = SynthesisResult()
        result.traces_analyzed = len(self._collector.traces)
        result.variables_tracked = self._collector.variable_count
        result.templates_tried = self._template_library.template_count

        if result.traces_analyzed < 3:
            logger.warning("Too few traces for synthesis (%d)", result.traces_analyzed)
            return result

        logger.info(
            "Starting invariant synthesis: %d traces, %d variables, %d templates",
            result.traces_analyzed,
            result.variables_tracked,
            result.templates_tried,
        )

        # 1. Generate candidates
        candidates = self._candidate_generator.generate(self._collector)
        result.candidates_generated = len(candidates)
        logger.info("Generated %d candidates", len(candidates))

        # 2. Prune with counter-examples
        surviving = self._pruner.prune(candidates, self._collector)
        result.candidates_pruned = len(candidates) - len(surviving)
        logger.info(
            "Pruned %d candidates, %d surviving",
            result.candidates_pruned, len(surviving),
        )

        # 3. Validate statistically
        validated = self._validator.validate(surviving, self._collector)

        # 4. Rank
        ranked = self._ranker.rank(validated)

        # 5. De-duplicate
        final = self._deduplicate(ranked)

        result.invariants = final
        result.relationships_found = len(final)
        result.synthesis_time_sec = time.time() - start

        # Summary stats
        for inv in final:
            cat = inv.category.value
            result.by_category[cat] = result.by_category.get(cat, 0) + 1
            strength = inv.strength.value
            result.by_strength[strength] = result.by_strength.get(strength, 0) + 1

        # Update known invariants
        self._known_invariants.extend(final)

        logger.info(
            "Synthesis complete: %d invariants found in %.1fs (proven=%d, strong=%d, likely=%d)",
            len(final),
            result.synthesis_time_sec,
            result.by_strength.get("proven", 0),
            result.by_strength.get("strong", 0),
            result.by_strength.get("likely", 0),
        )

        return result

    def get_fuzz_targets(self) -> list[dict[str, Any]]:
        """Get fuzz targets based on synthesized invariants."""
        targets: list[dict[str, Any]] = []

        for inv in self._known_invariants:
            if inv.fuzz_strategy:
                targets.append({
                    "invariant_id": inv.id,
                    "expression": inv.expression,
                    "strength": inv.strength.value,
                    "fuzz_strategy": inv.fuzz_strategy,
                    "variables": inv.variables,
                    "soul_relevance": inv.soul_relevance,
                    "check_expression": inv.check_expression,
                })

        return targets

    def get_invariants_for_contract(
        self, contract_name: str,
    ) -> list[SynthesizedInvariant]:
        """Get invariants relevant to a specific contract."""
        return [
            inv for inv in self._known_invariants
            if any(contract_name.lower() in v.lower() for v in inv.variables)
        ]

    def _deduplicate(
        self, invariants: list[SynthesizedInvariant],
    ) -> list[SynthesizedInvariant]:
        """Remove duplicate or subsumed invariants."""
        seen_expressions: set[str] = set()
        unique: list[SynthesizedInvariant] = []

        for inv in invariants:
            # Normalize expression for comparison
            normalized = inv.expression.replace(" ", "").lower()
            if normalized in seen_expressions:
                continue

            # Check against known invariants
            known_match = False
            for known in self._known_invariants:
                if (
                    known.template_kind == inv.template_kind
                    and set(known.variables) == set(inv.variables)
                ):
                    known_match = True
                    break

            if not known_match:
                seen_expressions.add(normalized)
                unique.append(inv)

        return unique

    @property
    def known_invariant_count(self) -> int:
        return len(self._known_invariants)

    @property
    def trace_count(self) -> int:
        return len(self._collector.traces)
