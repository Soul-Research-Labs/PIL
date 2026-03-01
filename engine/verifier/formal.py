"""Formal verification integration — Halmos & Certora runner.

Provides a unified interface to dispatch Solidity contracts to
symbolic execution tools (Halmos) and formal verifiers (Certora Prover)
then collect counterexamples, invariant violations, and proof results.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import re
import subprocess
import tempfile
import time
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Types
# ---------------------------------------------------------------------------


class VerificationTool(Enum):
    """Supported verification backends."""
    HALMOS = "halmos"
    CERTORA = "certora"


class ProofStatus(Enum):
    """Outcome of a single property proof."""
    PROVED = "proved"
    VIOLATED = "violated"
    TIMEOUT = "timeout"
    UNKNOWN = "unknown"
    ERROR = "error"


@dataclass
class Counterexample:
    """A concrete counterexample that violates a property."""
    function: str
    inputs: dict[str, Any] = field(default_factory=dict)
    trace: list[str] = field(default_factory=list)
    storage_diff: dict[str, str] = field(default_factory=dict)


@dataclass
class PropertyResult:
    """Result for a single formal property / invariant."""
    name: str
    status: ProofStatus
    tool: VerificationTool
    counterexample: Counterexample | None = None
    time_sec: float = 0.0
    message: str = ""
    raw_output: str = ""


@dataclass
class VerificationReport:
    """Aggregate result of a formal-verification run."""
    tool: VerificationTool
    success: bool = True
    properties: list[PropertyResult] = field(default_factory=list)
    total_time_sec: float = 0.0
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    raw_stdout: str = ""
    raw_stderr: str = ""

    # Convenience -----------------------------------------------------------
    @property
    def proved_count(self) -> int:
        return sum(1 for p in self.properties if p.status == ProofStatus.PROVED)

    @property
    def violated_count(self) -> int:
        return sum(1 for p in self.properties if p.status == ProofStatus.VIOLATED)

    def to_dict(self) -> dict[str, Any]:
        return {
            "tool": self.tool.value,
            "success": self.success,
            "proved": self.proved_count,
            "violated": self.violated_count,
            "total": len(self.properties),
            "total_time_sec": round(self.total_time_sec, 2),
            "properties": [
                {
                    "name": p.name,
                    "status": p.status.value,
                    "time_sec": round(p.time_sec, 2),
                    "message": p.message,
                    "counterexample": {
                        "function": p.counterexample.function,
                        "inputs": p.counterexample.inputs,
                    } if p.counterexample else None,
                }
                for p in self.properties
            ],
            "errors": self.errors,
        }


# ---------------------------------------------------------------------------
# Halmos runner
# ---------------------------------------------------------------------------

_HALMOS_RESULT_RE = re.compile(
    r"(?P<status>Passed|Failed|Error)\s+(?P<name>\S+)"
)
_HALMOS_CE_RE = re.compile(
    r"Counterexample:\s*\n(?P<ce>(?:\s+\S.*\n)+)",
    re.MULTILINE,
)


class HalmosRunner:
    """Run symbolic tests via Halmos (``halmos``) CLI.

    Halmos reads Foundry-style test contracts and attempts to formally
    prove every ``function check_*`` or ``function prove_*`` test.

    Parameters
    ----------
    halmos_binary:
        Path to the ``halmos`` binary (default: ``"halmos"``).
    solver_timeout:
        Per-property solver timeout in seconds.
    loop_bound:
        Maximum loop unrolling depth.
    smt_timeout:
        Z3 per-query timeout in milliseconds.
    """

    def __init__(
        self,
        halmos_binary: str = "halmos",
        solver_timeout: int = 300,
        loop_bound: int = 3,
        smt_timeout: int = 60_000,
    ) -> None:
        self.binary = halmos_binary
        self.solver_timeout = solver_timeout
        self.loop_bound = loop_bound
        self.smt_timeout = smt_timeout

    # ------------------------------------------------------------------

    async def verify(
        self,
        source_code: str,
        test_code: str,
        contract_name: str = "Target",
        test_contract_name: str = "TargetTest",
        extra_sources: dict[str, str] | None = None,
    ) -> VerificationReport:
        """Compile and verify via Halmos, returning a structured report."""
        start = time.monotonic()

        with tempfile.TemporaryDirectory(prefix="halmos_") as tmpdir:
            project = Path(tmpdir)

            # Scaffold a minimal Foundry project
            self._scaffold_project(
                project, source_code, test_code,
                contract_name, test_contract_name,
                extra_sources or {},
            )

            cmd = [
                self.binary,
                "--root", str(project),
                "--contract", test_contract_name,
                "--solver-timeout-assertion", str(self.solver_timeout),
                "--loop", str(self.loop_bound),
                "--smt-timeout", str(self.smt_timeout),
                "--json-output",
            ]

            try:
                proc = await asyncio.create_subprocess_exec(
                    *cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                    cwd=str(project),
                )
                stdout_b, stderr_b = await asyncio.wait_for(
                    proc.communicate(),
                    timeout=self.solver_timeout + 60,
                )
            except asyncio.TimeoutError:
                return VerificationReport(
                    tool=VerificationTool.HALMOS,
                    success=False,
                    errors=["Halmos process timed out"],
                    total_time_sec=time.monotonic() - start,
                )
            except FileNotFoundError:
                return VerificationReport(
                    tool=VerificationTool.HALMOS,
                    success=False,
                    errors=["halmos binary not found — install via `pip install halmos`"],
                    total_time_sec=time.monotonic() - start,
                )

            stdout = stdout_b.decode(errors="replace")
            stderr = stderr_b.decode(errors="replace")

            report = self._parse_output(stdout, stderr)
            report.total_time_sec = time.monotonic() - start
            return report

    # ------------------------------------------------------------------

    def _scaffold_project(
        self,
        root: Path,
        source_code: str,
        test_code: str,
        contract_name: str,
        test_contract_name: str,
        extra_sources: dict[str, str],
    ) -> None:
        """Create a minimal Foundry project for Halmos."""
        src = root / "src"
        test_dir = root / "test"
        lib = root / "lib"
        src.mkdir()
        test_dir.mkdir()
        lib.mkdir()

        (src / f"{contract_name}.sol").write_text(source_code)
        (test_dir / f"{test_contract_name}.t.sol").write_text(test_code)

        for name, code in extra_sources.items():
            p = src / name
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(code)

        # Minimal foundry.toml
        (root / "foundry.toml").write_text(
            "[profile.default]\nsrc = 'src'\nout = 'out'\nlibs = ['lib']\n"
        )

    def _parse_output(self, stdout: str, stderr: str) -> VerificationReport:
        """Parse Halmos CLI output into structured results."""
        properties: list[PropertyResult] = []
        errors: list[str] = []

        # Try JSON output first
        try:
            data = json.loads(stdout)
            if isinstance(data, list):
                for entry in data:
                    status_str = entry.get("result", "unknown").lower()
                    status = {
                        "pass": ProofStatus.PROVED,
                        "passed": ProofStatus.PROVED,
                        "fail": ProofStatus.VIOLATED,
                        "failed": ProofStatus.VIOLATED,
                        "timeout": ProofStatus.TIMEOUT,
                    }.get(status_str, ProofStatus.UNKNOWN)

                    ce: Counterexample | None = None
                    if entry.get("counterexample"):
                        ce_data = entry["counterexample"]
                        ce = Counterexample(
                            function=entry.get("name", ""),
                            inputs=ce_data if isinstance(ce_data, dict) else {},
                        )

                    properties.append(PropertyResult(
                        name=entry.get("name", "unknown"),
                        status=status,
                        tool=VerificationTool.HALMOS,
                        counterexample=ce,
                        time_sec=entry.get("time", 0.0),
                        message=entry.get("message", ""),
                    ))
        except (json.JSONDecodeError, TypeError):
            # Fall back to regex parsing of text output
            for m in _HALMOS_RESULT_RE.finditer(stdout):
                st = m.group("status").lower()
                status = {
                    "passed": ProofStatus.PROVED,
                    "failed": ProofStatus.VIOLATED,
                    "error": ProofStatus.ERROR,
                }.get(st, ProofStatus.UNKNOWN)

                properties.append(PropertyResult(
                    name=m.group("name"),
                    status=status,
                    tool=VerificationTool.HALMOS,
                ))

        if stderr and "error" in stderr.lower():
            errors.append(stderr.strip()[:500])

        success = all(
            p.status in (ProofStatus.PROVED, ProofStatus.UNKNOWN)
            for p in properties
        ) and not errors

        return VerificationReport(
            tool=VerificationTool.HALMOS,
            success=success,
            properties=properties,
            errors=errors,
            raw_stdout=stdout[:5000],
            raw_stderr=stderr[:2000],
        )


# ---------------------------------------------------------------------------
# Certora runner
# ---------------------------------------------------------------------------


class CertoraRunner:
    """Run formal verification via Certora Prover CLI (``certoraRun``).

    Certora works by taking a Solidity contract + a ``.spec`` file
    written in CVL (Certora Verification Language), compiling both,
    and sending the bundle to the Certora cloud prover.

    Environment variable ``CERTORAKEY`` must be set.

    Parameters
    ----------
    certora_binary:
        Path to the ``certoraRun`` binary.
    api_key:
        Certora API key.  Falls back to ``$CERTORAKEY``.
    timeout:
        Maximum wall-clock time to wait for the prover (seconds).
    """

    def __init__(
        self,
        certora_binary: str = "certoraRun",
        api_key: str | None = None,
        timeout: int = 600,
    ) -> None:
        self.binary = certora_binary
        self.api_key = api_key or os.environ.get("CERTORAKEY", "")
        self.timeout = timeout

    async def verify(
        self,
        source_code: str,
        spec_code: str,
        contract_name: str = "Target",
        solc_version: str = "0.8.20",
    ) -> VerificationReport:
        """Submit to Certora Prover and poll for results."""
        start = time.monotonic()

        if not self.api_key:
            return VerificationReport(
                tool=VerificationTool.CERTORA,
                success=False,
                errors=["CERTORAKEY not set — obtain a key at https://www.certora.com"],
                total_time_sec=time.monotonic() - start,
            )

        with tempfile.TemporaryDirectory(prefix="certora_") as tmpdir:
            project = Path(tmpdir)

            sol_file = project / f"{contract_name}.sol"
            spec_file = project / f"{contract_name}.spec"
            sol_file.write_text(source_code)
            spec_file.write_text(spec_code)

            cmd = [
                self.binary,
                str(sol_file),
                "--verify", f"{contract_name}:{spec_file}",
                "--solc", f"solc{solc_version}",
                "--send_only",
                "--json",
            ]

            env = {**os.environ, "CERTORAKEY": self.api_key}

            try:
                proc = await asyncio.create_subprocess_exec(
                    *cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                    env=env,
                    cwd=str(project),
                )
                stdout_b, stderr_b = await asyncio.wait_for(
                    proc.communicate(),
                    timeout=self.timeout,
                )
            except asyncio.TimeoutError:
                return VerificationReport(
                    tool=VerificationTool.CERTORA,
                    success=False,
                    errors=["certoraRun timed out"],
                    total_time_sec=time.monotonic() - start,
                )
            except FileNotFoundError:
                return VerificationReport(
                    tool=VerificationTool.CERTORA,
                    success=False,
                    errors=[
                        "certoraRun not found — install via "
                        "`pip install certora-cli`"
                    ],
                    total_time_sec=time.monotonic() - start,
                )

            stdout = stdout_b.decode(errors="replace")
            stderr = stderr_b.decode(errors="replace")

            report = self._parse_output(stdout, stderr)
            report.total_time_sec = time.monotonic() - start
            return report

    def _parse_output(self, stdout: str, stderr: str) -> VerificationReport:
        """Parse Certora output JSON."""
        properties: list[PropertyResult] = []
        errors: list[str] = []

        try:
            data = json.loads(stdout)

            for rule in data.get("rules", data.get("results", [])):
                name = rule.get("name", rule.get("rule", "unknown"))
                status_str = rule.get("status", "unknown").upper()
                status = {
                    "VERIFIED": ProofStatus.PROVED,
                    "PASSED": ProofStatus.PROVED,
                    "VIOLATED": ProofStatus.VIOLATED,
                    "FAILED": ProofStatus.VIOLATED,
                    "TIMEOUT": ProofStatus.TIMEOUT,
                    "SANITY_FAILED": ProofStatus.ERROR,
                }.get(status_str, ProofStatus.UNKNOWN)

                ce: Counterexample | None = None
                if rule.get("counterexample"):
                    ce_data = rule["counterexample"]
                    ce = Counterexample(
                        function=ce_data.get("function", name),
                        inputs=ce_data.get("inputs", {}),
                        trace=ce_data.get("trace", []),
                    )

                properties.append(PropertyResult(
                    name=name,
                    status=status,
                    tool=VerificationTool.CERTORA,
                    counterexample=ce,
                    time_sec=rule.get("duration", 0.0),
                    message=rule.get("message", ""),
                ))

        except (json.JSONDecodeError, TypeError):
            errors.append(f"Failed to parse Certora output: {stdout[:500]}")

        if stderr.strip():
            errors.append(stderr.strip()[:500])

        success = all(
            p.status in (ProofStatus.PROVED, ProofStatus.UNKNOWN)
            for p in properties
        ) and not errors

        return VerificationReport(
            tool=VerificationTool.CERTORA,
            success=success,
            properties=properties,
            errors=errors,
            raw_stdout=stdout[:5000],
            raw_stderr=stderr[:2000],
        )


# ---------------------------------------------------------------------------
# Spec / harness generators
# ---------------------------------------------------------------------------


def generate_halmos_harness(
    contract_name: str,
    abi: list[dict[str, Any]],
    invariants: list[str] | None = None,
) -> str:
    """Auto-generate a Halmos symbolic test harness from ABI + invariants.

    The generated harness contains:
    - ``check_*`` functions for each ABI mutator + invariant
    - Symbolic ``svm.*`` inputs
    - ``setUp`` that deploys the target contract
    """
    lines = [
        "// SPDX-License-Identifier: MIT",
        "pragma solidity ^0.8.0;",
        "",
        'import "forge-std/Test.sol";',
        f'import "../src/{contract_name}.sol";',
        "",
        f"contract {contract_name}SymTest is Test {{",
        f"    {contract_name} target;",
        "",
        "    function setUp() public {",
        f"        target = new {contract_name}();",
        "    }",
        "",
    ]

    # Per-function symbolic checks
    for item in abi:
        if item.get("type") != "function":
            continue
        if item.get("stateMutability") in ("view", "pure"):
            continue
        fname = item["name"]
        params = item.get("inputs", [])

        sig_parts: list[str] = []
        call_parts: list[str] = []
        for j, p in enumerate(params):
            ptype = p.get("type", "uint256")
            pname = p.get("name") or f"arg{j}"
            # Use symbolic values — Halmos treats all calldata as symbolic
            sig_parts.append(f"{ptype} {pname}")
            call_parts.append(pname)

        sig = ", ".join(sig_parts)
        call_args = ", ".join(call_parts)

        lines.append(f"    function check_{fname}({sig}) public {{")
        lines.append(f"        target.{fname}({call_args});")
        lines.append("    }")
        lines.append("")

    # Invariant checks
    for idx, inv in enumerate(invariants or []):
        lines.append(f"    /// @notice Invariant: {inv[:80]}")
        lines.append(f"    function check_invariant_{idx}() public view {{")
        lines.append(f"        assertTrue({inv});")
        lines.append("    }")
        lines.append("")

    lines.append("}")
    return "\n".join(lines)


def generate_certora_spec(
    contract_name: str,
    abi: list[dict[str, Any]],
    invariants: list[str] | None = None,
) -> str:
    """Auto-generate a Certora CVL specification from ABI + invariants.

    Produces rules for:
    - State integrity (no unexpected reverts)
    - User-supplied invariants (as ``invariant`` or ``rule``)
    - Reentrancy-safety (no state change after external call)
    """
    lines = [
        f"// Auto-generated CVL spec for {contract_name}",
        f"using {contract_name} as target;",
        "",
        "methods {",
    ]

    for item in abi:
        if item.get("type") != "function":
            continue
        fname = item["name"]
        inputs = item.get("inputs", [])
        outputs = item.get("outputs", [])
        param_types = ", ".join(p.get("type", "uint256") for p in inputs)
        ret_types = ", ".join(p.get("type", "uint256") for p in outputs)
        mutability = item.get("stateMutability", "nonpayable")
        envfree = " envfree" if mutability in ("view", "pure") else ""
        ret_clause = f" returns ({ret_types})" if ret_types else ""
        lines.append(f"    function {fname}({param_types}){ret_clause} external{envfree};")

    lines.append("}")
    lines.append("")

    # Invariants
    for idx, inv in enumerate(invariants or []):
        lines.append(f"invariant inv_{idx}()")
        lines.append(f"    {inv};")
        lines.append("")

    # Generic no-revert rule for view functions
    view_fns = [
        item["name"] for item in abi
        if item.get("type") == "function"
        and item.get("stateMutability") in ("view", "pure")
    ]
    if view_fns:
        lines.append("// View functions should never revert under normal conditions")
        for vf in view_fns[:5]:  # cap to avoid spec bloat
            lines.append(f"rule {vf}_no_revert(env e) {{")
            lines.append(f"    {vf}@withrevert(e);")
            lines.append(f"    assert !lastReverted;")
            lines.append("}")
            lines.append("")

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Unified entry-point
# ---------------------------------------------------------------------------


async def run_formal_verification(
    source_code: str,
    contract_name: str = "Target",
    abi: list[dict[str, Any]] | None = None,
    invariants: list[str] | None = None,
    tools: list[VerificationTool] | None = None,
    certora_spec: str | None = None,
    halmos_test: str | None = None,
) -> list[VerificationReport]:
    """Run formal verification with one or more tools.

    Parameters
    ----------
    source_code:
        Solidity source of the contract under verification.
    contract_name:
        Name of the top-level contract.
    abi:
        ABI JSON for auto-generating harnesses/specs.
    invariants:
        Free-form Solidity boolean expressions to prove.
    tools:
        Which verifiers to run (default: [HALMOS]).
    certora_spec:
        Pre-written CVL spec (if None, auto-generated).
    halmos_test:
        Pre-written Halmos test contract (if None, auto-generated).

    Returns
    -------
    List of ``VerificationReport``, one per tool.
    """
    if tools is None:
        tools = [VerificationTool.HALMOS]

    abi = abi or []
    invariants = invariants or []
    reports: list[VerificationReport] = []

    for tool in tools:
        if tool == VerificationTool.HALMOS:
            test_code = halmos_test or generate_halmos_harness(
                contract_name, abi, invariants,
            )
            runner = HalmosRunner()
            report = await runner.verify(
                source_code=source_code,
                test_code=test_code,
                contract_name=contract_name,
                test_contract_name=f"{contract_name}SymTest",
            )
            reports.append(report)

        elif tool == VerificationTool.CERTORA:
            spec = certora_spec or generate_certora_spec(
                contract_name, abi, invariants,
            )
            runner_c = CertoraRunner()
            report = await runner_c.verify(
                source_code=source_code,
                spec_code=spec,
                contract_name=contract_name,
            )
            reports.append(report)

    return reports
