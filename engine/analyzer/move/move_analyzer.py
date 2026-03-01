"""Move module analyzer — parses Aptos/Sui Move programs
and detects common vulnerabilities specific to the Move runtime.

Detectors:
    MOVE-001  Missing acquires annotation on global storage access
    MOVE-002  Unchecked signer in public entry functions
    MOVE-003  Resource leak — created resource never moved or dropped
    MOVE-004  Flash-loan-like pattern — borrow without repay check
    MOVE-005  Unprotected module initializer (init_module / init)
    MOVE-006  Type confusion in generic functions with phantom types
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

from engine.core.types import FindingSchema, Location, Severity


# ── Types ────────────────────────────────────────────────────────────────────


@dataclass
class MoveFunction:
    """Parsed Move function definition."""
    name: str
    line: int
    visibility: str = ""  # public, public(friend), entry, ""
    is_entry: bool = False
    has_signer_param: bool = False
    acquires: list[str] = field(default_factory=list)
    borrows_global: list[str] = field(default_factory=list)
    moves_to: list[str] = field(default_factory=list)
    body_start: int = 0
    body_end: int = 0


@dataclass
class MoveStruct:
    """Parsed Move struct / resource definition."""
    name: str
    line: int
    has_key: bool = False
    has_store: bool = False
    has_drop: bool = False
    has_copy: bool = False
    fields: list[tuple[str, str]] = field(default_factory=list)


@dataclass
class MoveAnalysisResult:
    """Result of analysing a Move module."""
    module_name: str = ""
    module_address: str = ""
    functions: list[MoveFunction] = field(default_factory=list)
    structs: list[MoveStruct] = field(default_factory=list)
    findings: list[FindingSchema] = field(default_factory=list)
    lines_analyzed: int = 0
    framework: str = "aptos"  # "aptos" or "sui"


# ── Patterns ─────────────────────────────────────────────────────────────────

_MODULE_RE = re.compile(
    r"module\s+(?:(\w+)::)?(\w+)\s*\{", re.MULTILINE,
)
_FUNCTION_RE = re.compile(
    r"(public(?:\(friend\))?\s+)?(entry\s+)?fun\s+(\w+)"
    r"(?:<[^>]*>)?\s*\(([^)]*)\)"
    r"(?:\s*:\s*[^{]+?)?"
    r"(?:\s+acquires\s+([\w,\s]+))?"
    r"\s*\{",
    re.MULTILINE,
)
_STRUCT_RE = re.compile(
    r"struct\s+(\w+)(?:<[^>]*>)?\s+has\s+([\w,\s]+)\s*\{",
    re.MULTILINE,
)
_BORROW_GLOBAL_RE = re.compile(
    r"borrow_global(?:_mut)?\s*<\s*(\w+)\s*>",
)
_MOVE_TO_RE = re.compile(
    r"move_to\s*<?\s*(\w+)\s*>?",
)
_MOVE_FROM_RE = re.compile(
    r"move_from\s*<\s*(\w+)\s*>",
)
_EXISTS_RE = re.compile(
    r"exists\s*<\s*(\w+)\s*>",
)
# Sui-specific
_SUI_TRANSFER_RE = re.compile(
    r"transfer::(?:public_)?transfer\s*\(",
)
_SUI_INIT_RE = re.compile(
    r"fun\s+init\s*\(",
)


def parse_move_module(
    source: str, file_path: str = "sources/module.move", framework: str = "aptos",
) -> MoveAnalysisResult:
    """Parse a Move module and run built-in detectors."""
    result = MoveAnalysisResult(
        lines_analyzed=source.count("\n") + 1,
        framework=framework,
    )

    # Module header
    mod_match = _MODULE_RE.search(source)
    if mod_match:
        result.module_address = mod_match.group(1) or ""
        result.module_name = mod_match.group(2) or ""

    # Parse structs
    for m in _STRUCT_RE.finditer(source):
        name = m.group(1)
        abilities = [a.strip() for a in m.group(2).split(",")]
        line = source[:m.start()].count("\n") + 1

        result.structs.append(MoveStruct(
            name=name,
            line=line,
            has_key="key" in abilities,
            has_store="store" in abilities,
            has_drop="drop" in abilities,
            has_copy="copy" in abilities,
        ))

    # Parse functions
    for m in _FUNCTION_RE.finditer(source):
        vis = (m.group(1) or "").strip()
        is_entry = bool(m.group(2))
        name = m.group(3)
        params = m.group(4)
        acquires_str = m.group(5) or ""
        line = source[:m.start()].count("\n") + 1

        func = MoveFunction(
            name=name,
            line=line,
            visibility=vis,
            is_entry=is_entry,
            has_signer_param="signer" in params.lower() or "&signer" in params,
            acquires=[a.strip() for a in acquires_str.split(",") if a.strip()],
        )

        # Parse body
        body_start = m.end() - 1  # the opening brace
        depth = 1
        pos = body_start + 1
        while pos < len(source) and depth > 0:
            if source[pos] == "{":
                depth += 1
            elif source[pos] == "}":
                depth -= 1
            pos += 1
        func.body_start = source[:body_start].count("\n") + 1
        func.body_end = source[:pos].count("\n") + 1
        body = source[body_start:pos]

        func.borrows_global = [m2.group(1) for m2 in _BORROW_GLOBAL_RE.finditer(body)]
        func.moves_to = [m2.group(1) for m2 in _MOVE_TO_RE.finditer(body)]

        result.functions.append(func)

    # ── Detectors ────────────────────────────────────────────────────────
    result.findings.extend(_detect_missing_acquires(result, file_path))
    result.findings.extend(_detect_unchecked_signer(result, file_path))
    result.findings.extend(_detect_resource_leak(result, source, file_path))
    result.findings.extend(_detect_flash_loan_pattern(result, source, file_path))
    result.findings.extend(_detect_unprotected_init(result, source, file_path, framework))
    result.findings.extend(_detect_phantom_type_confusion(source, file_path))

    return result


# ── Detectors ────────────────────────────────────────────────────────────────


def _detect_missing_acquires(
    result: MoveAnalysisResult, file_path: str,
) -> list[FindingSchema]:
    """MOVE-001: Missing acquires annotation on global storage access."""
    findings = []
    resource_names = {s.name for s in result.structs if s.has_key}

    for func in result.functions:
        for borrowed in func.borrows_global:
            if borrowed in resource_names and borrowed not in func.acquires:
                findings.append(FindingSchema(
                    title="Missing acquires annotation",
                    description=(
                        f"Function `{func.name}` accesses global resource `{borrowed}` "
                        f"but does not include it in the `acquires` clause."
                    ),
                    severity=Severity.HIGH,
                    confidence=0.9,
                    category="resource_safety",
                    scwe_id="MOVE-001",
                    location=Location(file_path=file_path, start_line=func.line, end_line=func.body_end, snippet=""),
                    remediation=f"Add `acquires {borrowed}` to the function signature.",
                ))
    return findings


def _detect_unchecked_signer(
    result: MoveAnalysisResult, file_path: str,
) -> list[FindingSchema]:
    """MOVE-002: Public entry function without signer parameter."""
    findings = []
    for func in result.functions:
        if func.is_entry and not func.has_signer_param and func.moves_to:
            findings.append(FindingSchema(
                title="Missing signer check in entry function",
                description=(
                    f"Entry function `{func.name}` modifies global state via `move_to` "
                    f"but does not accept a `&signer` parameter for authorization."
                ),
                severity=Severity.CRITICAL,
                confidence=0.85,
                category="access_control",
                scwe_id="MOVE-002",
                location=Location(file_path=file_path, start_line=func.line, end_line=func.body_end, snippet=""),
                remediation="Add a `signer: &signer` parameter and validate the sender address.",
            ))
    return findings


def _detect_resource_leak(
    result: MoveAnalysisResult, source: str, file_path: str,
) -> list[FindingSchema]:
    """MOVE-003: Resource created but never stored or destroyed."""
    findings = []
    # Look for struct instantiation patterns that aren't followed by move_to or transfer
    for struct in result.structs:
        if struct.has_key and not struct.has_drop:
            # Resources without `drop` that are created must be explicitly stored
            instantiation = re.search(
                rf"\b{struct.name}\s*\{{", source,
            )
            if instantiation:
                line = source[:instantiation.start()].count("\n") + 1
                # Check if move_to appears nearby
                rest = source[instantiation.end():]
                if f"move_to" not in rest[:500] and "transfer" not in rest[:500]:
                    findings.append(FindingSchema(
                        title="Potential resource leak",
                        description=(
                            f"Resource `{struct.name}` (has `key` but not `drop`) is instantiated "
                            f"but may not be properly stored via `move_to`. Leaked resources are "
                            f"silently lost in the Move VM."
                        ),
                        severity=Severity.MEDIUM,
                        confidence=0.55,
                        category="resource_safety",
                        scwe_id="MOVE-003",
                        location=Location(file_path=file_path, start_line=line, end_line=line, snippet=""),
                        remediation="Ensure the resource is stored with `move_to` or explicitly destroyed.",
                    ))
    return findings


def _detect_flash_loan_pattern(
    result: MoveAnalysisResult, source: str, file_path: str,
) -> list[FindingSchema]:
    """MOVE-004: Borrow pattern without repay validation (flash loan risk)."""
    findings = []
    for func in result.functions:
        if func.borrows_global and func.is_entry:
            body = source[func.body_start:func.body_end] if func.body_end > func.body_start else ""
            has_borrow_mut = "borrow_global_mut" in body
            has_value_check = "assert!" in body or "abort" in body
            if has_borrow_mut and not has_value_check:
                findings.append(FindingSchema(
                    title="Flash-loan-like pattern without repay check",
                    description=(
                        f"Function `{func.name}` borrows mutable global state but does not "
                        f"assert invariants before returning. This could allow flash-loan style "
                        f"attacks where borrowed value is not repaid."
                    ),
                    severity=Severity.HIGH,
                    confidence=0.6,
                    category="economic",
                    scwe_id="MOVE-004",
                    location=Location(file_path=file_path, start_line=func.line, end_line=func.body_end, snippet=""),
                    remediation="Add `assert!` checks to verify state invariants (e.g., balance >= borrowed) before the function returns.",
                ))
    return findings


def _detect_unprotected_init(
    result: MoveAnalysisResult, source: str, file_path: str, framework: str,
) -> list[FindingSchema]:
    """MOVE-005: Unprotected module initializer."""
    findings = []
    init_name = "init" if framework == "sui" else "init_module"
    for func in result.functions:
        if func.name == init_name:
            if func.visibility and "public" in func.visibility:
                findings.append(FindingSchema(
                    title="Publicly visible module initializer",
                    description=(
                        f"Module initializer `{func.name}` has public visibility. "
                        f"It should be private to prevent external re-initialization."
                    ),
                    severity=Severity.CRITICAL,
                    confidence=0.95,
                    category="initialization",
                    scwe_id="MOVE-005",
                    location=Location(file_path=file_path, start_line=func.line, end_line=func.body_end, snippet=""),
                    remediation=f"Remove `public` visibility from `{func.name}`. The runtime calls it automatically.",
                ))
    return findings


def _detect_phantom_type_confusion(source: str, file_path: str) -> list[FindingSchema]:
    """MOVE-006: Type confusion with phantom type parameters."""
    findings = []
    phantom_structs = re.finditer(
        r"struct\s+(\w+)\s*<\s*phantom\s+(\w+)\s*>",
        source,
    )
    for m in phantom_structs:
        struct_name = m.group(1)
        phantom_param = m.group(2)
        line = source[:m.start()].count("\n") + 1
        # Check if this phantom type is used in access control decisions
        rest = source[m.end():]
        if f"borrow_global<{struct_name}" in rest or f"exists<{struct_name}" in rest:
            findings.append(FindingSchema(
                title="Phantom type parameter used in access control",
                description=(
                    f"Struct `{struct_name}` uses phantom type parameter `{phantom_param}` "
                    f"and is accessed via global storage. Phantom types are erased at runtime, "
                    f"meaning different instantiations share the same storage slot."
                ),
                severity=Severity.MEDIUM,
                confidence=0.55,
                category="type_safety",
                scwe_id="MOVE-006",
                location=Location(file_path=file_path, start_line=line, end_line=line, snippet=""),
                remediation="Use a non-phantom type parameter or separate storage for different type instantiations.",
            ))
    return findings
