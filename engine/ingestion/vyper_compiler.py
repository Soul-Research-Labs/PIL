"""Vyper compiler integration for smart-contract analysis.

Mirrors the ``SolidityCompiler`` API so callers can transparently swap
between languages.  Supports both the Vyper CLI (``vyper``) and the
``vyper`` Python package.
"""

from __future__ import annotations

import json
import logging
import re
import subprocess
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from engine.ingestion.solidity_compiler import CompilationResult, CompiledContract

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_VYPER_VERSION_RE = re.compile(r"#\s*@version\s+([\d.]+)")
_VYPER_PRAGMA_RE = re.compile(r"#\s*pragma\s+version\s+[\^~>=<]*([\d.]+)")


def detect_vyper_version(source: str) -> str | None:
    """Extract version from ``# @version 0.3.10`` or ``# pragma version ^0.4.0``."""
    for pattern in (_VYPER_VERSION_RE, _VYPER_PRAGMA_RE):
        m = pattern.search(source)
        if m:
            return m.group(1)
    return None


def is_vyper_source(filename: str) -> bool:
    """Return True if *filename* looks like a Vyper file."""
    return filename.endswith(".vy") or filename.endswith(".vyper")


# ---------------------------------------------------------------------------
# Compiler
# ---------------------------------------------------------------------------


class VyperCompiler:
    """Compile Vyper source code using the ``vyper`` CLI or library.

    Parameters
    ----------
    version:
        Explicit compiler version.  If *None* the version is detected from
        the ``# @version`` / ``# pragma version`` directive.
    vyper_binary:
        Path to the ``vyper`` binary.  Defaults to ``"vyper"``.
    """

    def __init__(
        self,
        version: str | None = None,
        vyper_binary: str = "vyper",
    ) -> None:
        self.version = version
        self.vyper_binary = vyper_binary

    # ------------------------------------------------------------------
    # Public
    # ------------------------------------------------------------------

    def compile_source(
        self,
        source_code: str,
        filename: str = "Contract.vy",
    ) -> CompilationResult:
        """Compile a single Vyper source file.

        Tries the Python library first; falls back to CLI invocation.
        """
        try:
            return self._compile_via_library(source_code, filename)
        except ImportError:
            logger.debug("vyper Python package not available – falling back to CLI")
        except Exception as exc:
            logger.debug("Library compile failed: %s – falling back to CLI", exc)

        return self._compile_via_cli(source_code, filename)

    def compile_files(
        self,
        source_files: dict[str, str],
    ) -> CompilationResult:
        """Compile multiple Vyper files, merging results.

        Each file is compiled independently — Vyper does not support
        multi-file standard-JSON input the way ``solc`` does.
        """
        merged = CompilationResult(success=True)

        for fname, code in source_files.items():
            result = self.compile_source(code, filename=fname)
            merged.errors.extend(result.errors)
            merged.warnings.extend(result.warnings)
            merged.contracts.update(result.contracts)
            merged.sources_ast.update(result.sources_ast)
            if not result.success:
                merged.success = False

        return merged

    # ------------------------------------------------------------------
    # Python library path
    # ------------------------------------------------------------------

    def _compile_via_library(
        self,
        source_code: str,
        filename: str,
    ) -> CompilationResult:
        """Compile using the ``vyper`` Python package."""
        import vyper  # type: ignore[import-untyped]
        from vyper.compiler import compile_code  # type: ignore[import-untyped]

        errors: list[str] = []
        warnings: list[str] = []

        try:
            output_formats = [
                "abi",
                "bytecode",
                "bytecode_runtime",
                "method_identifiers",
                "ast_dict",
                "layout",
            ]
            compiled = compile_code(
                source_code,
                output_formats=output_formats,
                source_id=0,
                no_optimize=False,
            )

            contract_name = Path(filename).stem

            abi = compiled.get("abi", [])
            bytecode = compiled.get("bytecode", "")
            deployed = compiled.get("bytecode_runtime", "")
            method_ids = compiled.get("method_identifiers", {})
            ast_dict = compiled.get("ast_dict", {})
            storage_layout = compiled.get("layout", {})

            # Normalise bytecode (vyper returns 0x-prefixed hex)
            if isinstance(bytecode, bytes):
                bytecode = bytecode.hex()
            elif isinstance(bytecode, str) and bytecode.startswith("0x"):
                bytecode = bytecode[2:]

            if isinstance(deployed, bytes):
                deployed = deployed.hex()
            elif isinstance(deployed, str) and deployed.startswith("0x"):
                deployed = deployed[2:]

            contract = CompiledContract(
                name=contract_name,
                abi=abi if isinstance(abi, list) else [],
                bytecode=bytecode,
                deployed_bytecode=deployed,
                storage_layout=storage_layout if isinstance(storage_layout, dict) else {},
                ast=ast_dict if isinstance(ast_dict, dict) else {},
                method_identifiers=method_ids if isinstance(method_ids, dict) else {},
            )

            return CompilationResult(
                success=True,
                warnings=warnings,
                contracts={f"{filename}:{contract_name}": contract},
                sources_ast={filename: ast_dict} if ast_dict else {},
            )

        except Exception as exc:
            return CompilationResult(success=False, errors=[str(exc)])

    # ------------------------------------------------------------------
    # CLI path
    # ------------------------------------------------------------------

    def _compile_via_cli(
        self,
        source_code: str,
        filename: str,
    ) -> CompilationResult:
        """Compile by invoking the ``vyper`` CLI in a temp directory."""
        with tempfile.TemporaryDirectory(prefix="vyper_") as tmpdir:
            src_path = Path(tmpdir) / filename
            src_path.write_text(source_code, encoding="utf-8")

            contract_name = src_path.stem

            # --- ABI ---
            abi_json: list[dict[str, Any]] = []
            abi_result = self._run_vyper(src_path, "-f", "abi")
            if abi_result.returncode != 0:
                return CompilationResult(
                    success=False,
                    errors=[abi_result.stderr.strip()],
                )
            try:
                abi_json = json.loads(abi_result.stdout)
            except json.JSONDecodeError:
                pass

            # --- bytecode ---
            bytecode = ""
            bc_result = self._run_vyper(src_path, "-f", "bytecode")
            if bc_result.returncode == 0:
                bytecode = bc_result.stdout.strip()
                if bytecode.startswith("0x"):
                    bytecode = bytecode[2:]

            # --- deployed bytecode ---
            deployed = ""
            rt_result = self._run_vyper(src_path, "-f", "bytecode_runtime")
            if rt_result.returncode == 0:
                deployed = rt_result.stdout.strip()
                if deployed.startswith("0x"):
                    deployed = deployed[2:]

            # --- method identifiers ---
            method_ids: dict[str, str] = {}
            mi_result = self._run_vyper(src_path, "-f", "method_identifiers")
            if mi_result.returncode == 0:
                try:
                    method_ids = json.loads(mi_result.stdout)
                except json.JSONDecodeError:
                    # Sometimes returned as non-JSON; parse manually
                    for line in mi_result.stdout.strip().splitlines():
                        if ":" in line:
                            sig, sel = line.rsplit(":", 1)
                            method_ids[sig.strip()] = sel.strip()

            # --- AST ---
            ast_dict: dict[str, Any] = {}
            ast_result = self._run_vyper(src_path, "-f", "ast")
            if ast_result.returncode == 0:
                try:
                    ast_dict = json.loads(ast_result.stdout)
                except json.JSONDecodeError:
                    pass

            # --- storage layout ---
            layout: dict[str, Any] = {}
            layout_result = self._run_vyper(src_path, "-f", "layout")
            if layout_result.returncode == 0:
                try:
                    layout = json.loads(layout_result.stdout)
                except json.JSONDecodeError:
                    pass

            contract = CompiledContract(
                name=contract_name,
                abi=abi_json,
                bytecode=bytecode,
                deployed_bytecode=deployed,
                storage_layout=layout,
                ast=ast_dict,
                method_identifiers=method_ids,
            )

            return CompilationResult(
                success=True,
                contracts={f"{filename}:{contract_name}": contract},
                sources_ast={filename: ast_dict} if ast_dict else {},
            )

    def _run_vyper(
        self,
        source_path: Path,
        *extra_args: str,
    ) -> subprocess.CompletedProcess[str]:
        """Execute the ``vyper`` CLI and return the result."""
        cmd = [self.vyper_binary, str(source_path), *extra_args]
        logger.debug("Running: %s", " ".join(cmd))
        return subprocess.run(  # noqa: S603
            cmd,
            capture_output=True,
            text=True,
            timeout=120,
        )

    # ------------------------------------------------------------------
    # Version detection
    # ------------------------------------------------------------------

    @staticmethod
    def detect_version(source_code: str) -> str | None:
        """Detect Vyper compiler version from ``# @version`` pragma."""
        return detect_vyper_version(source_code)


# ---------------------------------------------------------------------------
# Vyper-specific detectors (basic set)
# ---------------------------------------------------------------------------

@dataclass
class VyperDetectorContext:
    """Lightweight context passed to Vyper-specific detectors."""

    source_code: str
    filename: str
    abi: list[dict[str, Any]] = field(default_factory=list)
    ast: dict[str, Any] = field(default_factory=dict)
    vyper_version: tuple[int, ...] = (0, 3, 0)


@dataclass
class VyperFinding:
    """A single Vyper-specific finding."""

    detector_id: str
    title: str
    severity: str  # CRITICAL | HIGH | MEDIUM | LOW | INFO
    confidence: str  # HIGH | MEDIUM | LOW
    description: str
    line: int | None = None
    snippet: str | None = None


class VyperDetectorBase:
    """Abstract base for Vyper source detectors."""

    DETECTOR_ID: str = ""
    TITLE: str = ""
    SEVERITY: str = "MEDIUM"
    CONFIDENCE: str = "MEDIUM"

    def run(self, ctx: VyperDetectorContext) -> list[VyperFinding]:
        raise NotImplementedError


# ---------------------------------------------------------------------------
# Built-in Vyper detectors
# ---------------------------------------------------------------------------


class DefaultReturnValueDetector(VyperDetectorBase):
    """Detect external calls whose return value is silently discarded.

    Vyper's ``raw_call`` returns ``Bytes[max_outsize]`` when ``max_outsize``
    is set. If the return is not captured, a failure could go unnoticed.
    """

    DETECTOR_ID = "VYP-001"
    TITLE = "Unchecked raw_call return value"
    SEVERITY = "HIGH"
    CONFIDENCE = "MEDIUM"

    _RAW_CALL_RE = re.compile(
        r"^\s*raw_call\s*\(",
        re.MULTILINE,
    )

    def run(self, ctx: VyperDetectorContext) -> list[VyperFinding]:
        findings: list[VyperFinding] = []
        for i, line in enumerate(ctx.source_code.splitlines(), 1):
            stripped = line.strip()
            # raw_call at statement level (no assignment)
            if stripped.startswith("raw_call(") and "=" not in line.split("raw_call")[0]:
                findings.append(VyperFinding(
                    detector_id=self.DETECTOR_ID,
                    title=self.TITLE,
                    severity=self.SEVERITY,
                    confidence=self.CONFIDENCE,
                    description=(
                        "raw_call() return value is discarded. If the callee "
                        "reverts, the failure is silently ignored."
                    ),
                    line=i,
                    snippet=line.rstrip(),
                ))
        return findings


class ReentrancyLockDetector(VyperDetectorBase):
    """Detect external calls in functions missing the ``@nonreentrant`` decorator.

    Vyper natively supports ``@nonreentrant("lock")`` decorators.  If a
    public function performs an external call without this decorator it
    may be vulnerable to reentrancy.
    """

    DETECTOR_ID = "VYP-002"
    TITLE = "External call without @nonreentrant"
    SEVERITY = "HIGH"
    CONFIDENCE = "MEDIUM"

    _FUNC_DEF_RE = re.compile(r"^@(external|public)")
    _NONREENTRANT_RE = re.compile(r"^@nonreentrant")
    _DEF_RE = re.compile(r"^def\s+(\w+)")
    _EXTERNAL_CALL_RE = re.compile(
        r"(raw_call|send\s*\(|\.transfer\s*\(|extcall\s+)",
    )

    def run(self, ctx: VyperDetectorContext) -> list[VyperFinding]:
        findings: list[VyperFinding] = []
        lines = ctx.source_code.splitlines()
        in_func = False
        has_nonreentrant = False
        is_external = False
        func_name = ""
        func_line = 0

        for i, line in enumerate(lines, 1):
            stripped = line.strip()

            # Detect decorator accumulation
            if self._FUNC_DEF_RE.match(stripped):
                is_external = True
                continue
            if self._NONREENTRANT_RE.match(stripped):
                has_nonreentrant = True
                continue

            # Function definition
            m = self._DEF_RE.match(stripped)
            if m:
                in_func = True
                func_name = m.group(1)
                func_line = i
                # Decorators already accumulated
                continue

            # End of function (next non-indented, non-empty line)
            if in_func and stripped and not line[0].isspace():
                # Reset
                in_func = False
                is_external = False
                has_nonreentrant = False
                func_name = ""
                continue

            # Inside function – look for external calls
            if in_func and is_external and not has_nonreentrant:
                if self._EXTERNAL_CALL_RE.search(stripped):
                    findings.append(VyperFinding(
                        detector_id=self.DETECTOR_ID,
                        title=self.TITLE,
                        severity=self.SEVERITY,
                        confidence=self.CONFIDENCE,
                        description=(
                            f"Function `{func_name}` performs an external call "
                            f"but is not protected with @nonreentrant."
                        ),
                        line=i,
                        snippet=line.rstrip(),
                    ))

        return findings


class SelfDestructDetector(VyperDetectorBase):
    """Detect usage of ``selfdestruct`` / ``SELFDESTRUCT`` opcode.

    ``selfdestruct`` is deprecated post-Dencun (EIP-6780), and Vyper ≥ 0.4.0
    no longer supports it natively.  Flag any residual usage.
    """

    DETECTOR_ID = "VYP-003"
    TITLE = "selfdestruct usage detected"
    SEVERITY = "HIGH"
    CONFIDENCE = "HIGH"

    _SELFDESTRUCT_RE = re.compile(r"\bselfdestruct\s*\(", re.IGNORECASE)

    def run(self, ctx: VyperDetectorContext) -> list[VyperFinding]:
        findings: list[VyperFinding] = []
        for i, line in enumerate(ctx.source_code.splitlines(), 1):
            if self._SELFDESTRUCT_RE.search(line):
                findings.append(VyperFinding(
                    detector_id=self.DETECTOR_ID,
                    title=self.TITLE,
                    severity=self.SEVERITY,
                    confidence=self.CONFIDENCE,
                    description=(
                        "selfdestruct is deprecated after Dencun (EIP-6780). "
                        "After the fork it no longer destroys the contract, only "
                        "sends Ether, which may break assumptions."
                    ),
                    line=i,
                    snippet=line.rstrip(),
                ))
        return findings


class DelegateCallDetector(VyperDetectorBase):
    """Detect ``raw_call`` with ``is_delegate_call=True``.

    Delegatecall in Vyper is performed via raw_call with an explicit flag.
    This is inherently dangerous and should be audited.
    """

    DETECTOR_ID = "VYP-004"
    TITLE = "Delegatecall via raw_call"
    SEVERITY = "HIGH"
    CONFIDENCE = "HIGH"

    _DELEGATE_RE = re.compile(r"raw_call\s*\(.*is_delegate_call\s*=\s*True", re.DOTALL)

    def run(self, ctx: VyperDetectorContext) -> list[VyperFinding]:
        findings: list[VyperFinding] = []
        for i, line in enumerate(ctx.source_code.splitlines(), 1):
            if "is_delegate_call" in line and "True" in line:
                findings.append(VyperFinding(
                    detector_id=self.DETECTOR_ID,
                    title=self.TITLE,
                    severity=self.SEVERITY,
                    confidence=self.CONFIDENCE,
                    description=(
                        "raw_call with is_delegate_call=True allows the callee "
                        "to modify this contract's storage. Ensure the target is "
                        "trusted and immutable."
                    ),
                    line=i,
                    snippet=line.rstrip(),
                ))
        return findings


class UnsafeExternalCallDetector(VyperDetectorBase):
    """Detect ``raw_call`` with ``is_static_call=False`` (default).

    Static calls are safe by default. Non-static raw_call can alter
    external state and should be audited.
    """

    DETECTOR_ID = "VYP-005"
    TITLE = "Non-static raw_call"
    SEVERITY = "MEDIUM"
    CONFIDENCE = "LOW"

    def run(self, ctx: VyperDetectorContext) -> list[VyperFinding]:
        findings: list[VyperFinding] = []
        for i, line in enumerate(ctx.source_code.splitlines(), 1):
            stripped = line.strip()
            if "raw_call(" in stripped and "is_static_call" not in stripped:
                findings.append(VyperFinding(
                    detector_id=self.DETECTOR_ID,
                    title=self.TITLE,
                    severity=self.SEVERITY,
                    confidence=self.CONFIDENCE,
                    description=(
                        "raw_call without is_static_call=True performs a "
                        "state-changing external call. Verify the target and "
                        "return value."
                    ),
                    line=i,
                    snippet=line.rstrip(),
                ))
        return findings


class UnprotectedInitDetector(VyperDetectorBase):
    """Detect ``__init__`` that doesn't set an owner-type variable.

    Many upgradeable patterns require the initializer to set ownership.
    If ``__init__`` doesn't write to any *owner*-like variable, flag it.
    """

    DETECTOR_ID = "VYP-006"
    TITLE = "Initializer may lack access control setup"
    SEVERITY = "MEDIUM"
    CONFIDENCE = "LOW"

    _OWNER_RE = re.compile(r"\b(owner|admin|governance|authority)\b", re.IGNORECASE)

    def run(self, ctx: VyperDetectorContext) -> list[VyperFinding]:
        findings: list[VyperFinding] = []
        lines = ctx.source_code.splitlines()
        in_init = False
        init_line = 0
        sets_owner = False

        for i, line in enumerate(lines, 1):
            stripped = line.strip()
            if stripped.startswith("def __init__"):
                in_init = True
                init_line = i
                sets_owner = False
                continue

            if in_init:
                if stripped and not line[0].isspace():
                    # End of __init__
                    if not sets_owner:
                        findings.append(VyperFinding(
                            detector_id=self.DETECTOR_ID,
                            title=self.TITLE,
                            severity=self.SEVERITY,
                            confidence=self.CONFIDENCE,
                            description=(
                                "__init__ does not appear to set an owner/admin "
                                "variable. Verify that access control is properly "
                                "initialised."
                            ),
                            line=init_line,
                        ))
                    in_init = False
                elif self._OWNER_RE.search(stripped):
                    sets_owner = True

        # Handle __init__ at end of file
        if in_init and not sets_owner:
            findings.append(VyperFinding(
                detector_id=self.DETECTOR_ID,
                title=self.TITLE,
                severity=self.SEVERITY,
                confidence=self.CONFIDENCE,
                description=(
                    "__init__ does not appear to set an owner/admin variable."
                ),
                line=init_line,
            ))

        return findings


# ---------------------------------------------------------------------------
# Registry & runner
# ---------------------------------------------------------------------------

VYPER_DETECTORS: list[type[VyperDetectorBase]] = [
    DefaultReturnValueDetector,
    ReentrancyLockDetector,
    SelfDestructDetector,
    DelegateCallDetector,
    UnsafeExternalCallDetector,
    UnprotectedInitDetector,
]


def run_vyper_detectors(
    source_code: str,
    filename: str = "Contract.vy",
    abi: list[dict[str, Any]] | None = None,
    ast: dict[str, Any] | None = None,
) -> list[VyperFinding]:
    """Run all Vyper detectors on a single source file.

    Returns a list of ``VyperFinding`` ordered by line number.
    """
    version_str = detect_vyper_version(source_code)
    version_tuple = (0, 3, 0)
    if version_str:
        try:
            version_tuple = tuple(int(p) for p in version_str.split("."))
        except ValueError:
            pass

    ctx = VyperDetectorContext(
        source_code=source_code,
        filename=filename,
        abi=abi or [],
        ast=ast or {},
        vyper_version=version_tuple,
    )

    all_findings: list[VyperFinding] = []
    for detector_cls in VYPER_DETECTORS:
        try:
            detector = detector_cls()
            all_findings.extend(detector.run(ctx))
        except Exception:
            logger.exception("Vyper detector %s failed", detector_cls.DETECTOR_ID)

    all_findings.sort(key=lambda f: f.line or 0)
    return all_findings


# ---------------------------------------------------------------------------
# Convenience: compile + detect
# ---------------------------------------------------------------------------


def compile_and_analyse_vyper(
    source_code: str,
    filename: str = "Contract.vy",
) -> tuple[CompilationResult, list[VyperFinding]]:
    """Compile a Vyper source file and run all detectors.

    Returns a ``(CompilationResult, list[VyperFinding])`` tuple.
    """
    compiler = VyperCompiler()
    result = compiler.compile_source(source_code, filename=filename)

    abi: list[dict[str, Any]] = []
    ast: dict[str, Any] = {}
    for contract in result.contracts.values():
        abi = contract.abi
        ast = contract.ast
        break

    findings = run_vyper_detectors(
        source_code=source_code,
        filename=filename,
        abi=abi,
        ast=ast,
    )

    return result, findings
