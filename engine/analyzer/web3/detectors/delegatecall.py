"""Delegatecall-related vulnerability detectors — SCWE-035."""

from __future__ import annotations

import re
from enum import Enum, auto

from engine.analyzer.web3.base_detector import BaseDetector, DetectorContext
from engine.core.types import FindingSchema, Severity


# ── Scope-aware brace tracker ────────────────────────────────────────────────

class _ScopeKind(Enum):
    """Kind of brace-delimited scope."""
    FUNCTION = auto()
    FOR_LOOP = auto()
    WHILE_LOOP = auto()
    DO_WHILE = auto()
    IF_BLOCK = auto()
    ELSE_BLOCK = auto()
    STRUCT = auto()
    ENUM = auto()
    CONTRACT = auto()
    ASSEMBLY = auto()
    UNCHECKED = auto()
    OTHER = auto()


class _ScopeTracker:
    """Full-context brace/scope tracker for Solidity source.

    Handles string/comment stripping, nested structs/enums inside loops,
    assembly blocks, ``do { … } while(…)`` loops, and multi-line
    brace expressions correctly.
    """

    _LOOP_KINDS = {_ScopeKind.FOR_LOOP, _ScopeKind.WHILE_LOOP, _ScopeKind.DO_WHILE}

    def __init__(self) -> None:
        # Stack of (ScopeKind, brace_depth_at_entry)
        self._scope_stack: list[tuple[_ScopeKind, int]] = []
        self._brace_depth: int = 0
        # Flags for cross-line state
        self._in_block_comment: bool = False
        self._pending_do_while: bool = False

    @property
    def inside_loop(self) -> bool:
        """True when the current position is inside any loop body."""
        return any(kind in self._LOOP_KINDS for kind, _ in self._scope_stack)

    def feed_line(self, raw_line: str) -> str:
        """Process one source line.  Returns the *code-only* content
        (strings and comments stripped) for downstream pattern matching.
        """
        code = self._strip_strings_and_comments(raw_line)
        stripped = code.strip()

        # --- Detect scope openers BEFORE counting braces ---------------
        if not self._in_block_comment:
            self._detect_scope_start(stripped)

        # --- Count braces on code-only content -------------------------
        for ch in code:
            if ch == "{":
                self._brace_depth += 1
            elif ch == "}":
                self._brace_depth -= 1
                # Pop scopes whose opening brace has been closed
                while (
                    self._scope_stack
                    and self._brace_depth <= self._scope_stack[-1][1]
                ):
                    closed_kind, _ = self._scope_stack.pop()
                    # If we just closed a 'do' body, mark that we need
                    # to see the trailing `while(...)` on a later line
                    if closed_kind == _ScopeKind.DO_WHILE:
                        self._pending_do_while = True

        # Consume trailing `while(...)` after `do { } while(…);`
        if self._pending_do_while and re.search(r"\bwhile\s*\(", stripped):
            self._pending_do_while = False

        return code

    # ------------------------------------------------------------------

    def _detect_scope_start(self, stripped: str) -> None:
        """Push a scope onto the stack when a block-introducing keyword
        is detected.  Called *before* braces on this line are counted so
        that ``brace_depth`` still equals the value at the block entry.
        """
        # struct / enum (not loops — avoid false-positive nesting)
        if re.match(r"\bstruct\b", stripped):
            self._scope_stack.append((_ScopeKind.STRUCT, self._brace_depth))
            return
        if re.match(r"\benum\b", stripped):
            self._scope_stack.append((_ScopeKind.ENUM, self._brace_depth))
            return
        if re.match(r"\bassembly\b", stripped):
            self._scope_stack.append((_ScopeKind.ASSEMBLY, self._brace_depth))
            return
        if re.match(r"\bunchecked\b", stripped):
            self._scope_stack.append((_ScopeKind.UNCHECKED, self._brace_depth))
            return

        # do { … } while (…);
        if re.match(r"\bdo\b\s*\{?", stripped):
            self._scope_stack.append((_ScopeKind.DO_WHILE, self._brace_depth))
            return

        # for / while loops
        if re.match(r"\bfor\s*\(", stripped):
            self._scope_stack.append((_ScopeKind.FOR_LOOP, self._brace_depth))
            return
        if re.match(r"\bwhile\s*\(", stripped) and not self._pending_do_while:
            self._scope_stack.append((_ScopeKind.WHILE_LOOP, self._brace_depth))
            return

    # ------------------------------------------------------------------

    def _strip_strings_and_comments(self, line: str) -> str:
        """Remove string literals and comments, preserving braces outside them."""
        result: list[str] = []
        i = 0
        n = len(line)

        if self._in_block_comment:
            end = line.find("*/")
            if end == -1:
                return ""
            self._in_block_comment = False
            i = end + 2

        while i < n:
            ch = line[i]

            # Single-line comment
            if ch == "/" and i + 1 < n and line[i + 1] == "/":
                break  # rest of line is comment

            # Block comment start
            if ch == "/" and i + 1 < n and line[i + 1] == "*":
                end = line.find("*/", i + 2)
                if end == -1:
                    self._in_block_comment = True
                    break
                i = end + 2
                continue

            # String literal (single or double quotes)
            if ch in ('"', "'"):
                quote = ch
                i += 1
                while i < n:
                    if line[i] == "\\" and i + 1 < n:
                        i += 2
                        continue
                    if line[i] == quote:
                        i += 1
                        break
                    i += 1
                continue

            result.append(ch)
            i += 1

        return "".join(result)


class UnprotectedDelegatecallDetector(BaseDetector):
    """Detect unprotected delegatecall usage."""

    DETECTOR_ID = "SCWE-035-001"
    NAME = "Unprotected Delegatecall"
    DESCRIPTION = "delegatecall to user-controlled address allows state hijacking"
    SCWE_ID = "SCWE-035"
    CWE_ID = "CWE-829"
    SEVERITY = Severity.CRITICAL
    CATEGORY = "delegatecall"

    def detect(self, context: DetectorContext) -> list[FindingSchema]:
        findings: list[FindingSchema] = []
        lines = context.source_code.split("\n")

        for i, line in enumerate(lines, 1):
            if ".delegatecall(" in line:
                # Check if the target is a parameter / storage variable
                match = re.search(r"(\w+)\.delegatecall\(", line)
                if match:
                    target = match.group(1)
                    # Check if target is function parameter or user-controllable
                    func_context = self._get_function_context(lines, i)
                    if self._is_user_controlled(target, func_context):
                        findings.append(self._make_finding(
                            title="Unprotected delegatecall to user-controlled address",
                            description=(
                                f"The address `{target}` used in delegatecall may be user-controlled. "
                                "An attacker can supply a malicious contract to overwrite storage."
                            ),
                            file_path=context.contract_name or "Contract.sol",
                            start_line=i,
                            end_line=i,
                            snippet=line.strip(),
                            remediation="Validate the delegatecall target against a whitelist of trusted implementation addresses.",
                        ))
        return findings

    def _get_function_context(self, lines: list[str], current_line: int) -> str:
        start = max(0, current_line - 20)
        end = min(len(lines), current_line + 5)
        return "\n".join(lines[start:end])

    def _is_user_controlled(self, target: str, func_context: str) -> bool:
        # Check if target is a function parameter
        param_pattern = rf"function\s+\w+\s*\([^)]*\b{re.escape(target)}\b"
        if re.search(param_pattern, func_context):
            return True
        # Check if set via external call
        setter_pattern = rf"{re.escape(target)}\s*=\s*\w+\s*;"
        if re.search(setter_pattern, func_context):
            return True
        return False


class DelegatecallInLoopDetector(BaseDetector):
    """Detect delegatecall inside loops."""

    DETECTOR_ID = "SCWE-035-002"
    NAME = "Delegatecall in Loop"
    DESCRIPTION = "delegatecall inside a loop can lead to unexpected state changes"
    SCWE_ID = "SCWE-035"
    CWE_ID = "CWE-829"
    SEVERITY = Severity.HIGH
    CATEGORY = "delegatecall"

    def detect(self, context: DetectorContext) -> list[FindingSchema]:
        findings: list[FindingSchema] = []
        lines = context.source_code.split("\n")

        # Use the full scope tracker for correct brace/scope handling
        tracker = _ScopeTracker()

        for i, raw_line in enumerate(lines, 1):
            code = tracker.feed_line(raw_line)
            stripped = code.strip()

            if tracker.inside_loop and ".delegatecall(" in stripped:
                findings.append(self._make_finding(
                    title="delegatecall inside a loop",
                    description=(
                        "Using delegatecall inside a loop makes each iteration execute "
                        "in the context of the calling contract, compounding state changes. "
                        "Nested structs, enums, and assembly blocks are correctly excluded."
                    ),
                    file_path=context.contract_name or "Contract.sol",
                    start_line=i,
                    end_line=i,
                    snippet=raw_line.strip(),
                    remediation="Avoid delegatecall inside loops. Execute each call individually with proper state checks.",
                ))
        return findings


class DelegatecallReturnValueDetector(BaseDetector):
    """Detect unchecked delegatecall return values."""

    DETECTOR_ID = "SCWE-035-003"
    NAME = "Unchecked Delegatecall Return"
    DESCRIPTION = "Delegatecall return value not checked, silent failures possible"
    SCWE_ID = "SCWE-035"
    CWE_ID = "CWE-252"
    SEVERITY = Severity.HIGH
    CATEGORY = "delegatecall"

    def detect(self, context: DetectorContext) -> list[FindingSchema]:
        findings: list[FindingSchema] = []
        lines = context.source_code.split("\n")

        for i, line in enumerate(lines, 1):
            stripped = line.strip()
            if ".delegatecall(" in stripped:
                # Check if return value is captured
                if not re.match(r"\(?\s*bool\s+\w+", stripped) and "require(" not in stripped:
                    if not stripped.startswith("(bool"):
                        findings.append(self._make_finding(
                            title="Unchecked delegatecall return value",
                            description=(
                                "The return value of delegatecall is not checked. "
                                "If the call fails, execution continues silently."
                            ),
                            file_path=context.contract_name or "Contract.sol",
                            start_line=i,
                            end_line=i,
                            snippet=stripped,
                            remediation="Capture the return value: `(bool success, ) = target.delegatecall(data);` and require success.",
                        ))
        return findings
