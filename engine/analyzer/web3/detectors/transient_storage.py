"""EIP-1153 Transient Storage vulnerability detectors.

Solidity ≥ 0.8.24 supports tstore/tload opcodes for transient storage
that is cleared at the end of each transaction. Common vulnerabilities:

  - Using transient storage for reentrancy guards that reset within the
    same tx (still safe in most cases, but dangerous if combined with
    internal calls to untrusted contracts within the same tx)
  - Relying on transient storage to persist across transactions (it does not)
  - Missing tstore cleanup in assembly blocks before cross-contract calls
  - Unvalidated tload values used in access control decisions
  - Slot collision between transient and regular storage
"""

from __future__ import annotations

import re

from engine.analyzer.web3.base_detector import BaseDetector, DetectorContext
from engine.core.types import FindingSchema, Location, Severity


class TransientStoragePersistenceDetector(BaseDetector):
    """Detect misuse of transient storage as if it persists across transactions."""

    DETECTOR_ID = "EIP1153-001"
    NAME = "Transient Storage Persistence Assumption"
    DESCRIPTION = (
        "Contract writes to transient storage (tstore) in one function "
        "and reads it (tload) in another without same-transaction guarantee, "
        "suggesting the developer may assume cross-transaction persistence."
    )
    SCWE_ID = "SCWE-070"
    CWE_ID = "CWE-664"
    SEVERITY = Severity.HIGH
    CATEGORY = "transient-storage"

    _TSTORE_RE = re.compile(r"\btstore\s*\(\s*(\w+)\s*,")
    _TLOAD_RE = re.compile(r"\btload\s*\(\s*(\w+)\s*\)")

    def detect(self, context: DetectorContext) -> list[FindingSchema]:
        findings: list[FindingSchema] = []
        lines = context.source_code.split("\n")
        ver = context.solidity_version
        if ver < (0, 8, 24):
            return findings

        # Collect tstore slots per function, tload slots per function
        current_func = ""
        tstore_funcs: dict[str, list[tuple[str, int]]] = {}  # slot -> [(func, line)]
        tload_funcs: dict[str, list[tuple[str, int]]] = {}

        for i, line in enumerate(lines, 1):
            func_match = re.match(r"\s*function\s+(\w+)", line)
            if func_match:
                current_func = func_match.group(1)

            for m in self._TSTORE_RE.finditer(line):
                slot = m.group(1)
                tstore_funcs.setdefault(slot, []).append((current_func, i))

            for m in self._TLOAD_RE.finditer(line):
                slot = m.group(1)
                tload_funcs.setdefault(slot, []).append((current_func, i))

        # Flag slots written in one function and read in a different function
        for slot, stores in tstore_funcs.items():
            loads = tload_funcs.get(slot, [])
            store_funcs_set = {f for f, _ in stores}
            for load_func, load_line in loads:
                if load_func and load_func not in store_funcs_set:
                    findings.append(self._make_finding(
                        title=f"Transient slot '{slot}' written in {', '.join(store_funcs_set)} but read in {load_func}",
                        description=(
                            f"Transient storage slot `{slot}` is set via tstore in "
                            f"{', '.join(store_funcs_set)} but read via tload in `{load_func}`. "
                            "Transient storage is cleared at the end of each transaction — "
                            "this value will be zero if read in a separate transaction."
                        ),
                        file_path=context.contract_name or "Contract.sol",
                        start_line=load_line,
                        end_line=load_line,
                        snippet=lines[load_line - 1].strip(),
                        remediation=(
                            "Use regular storage (sstore/sload) for values that must persist across "
                            "transactions. Reserve transient storage for intra-transaction state only."
                        ),
                    ))

        return findings


class TransientReentrancyGuardDetector(BaseDetector):
    """Detect reentrancy guards using transient storage that may be unsafe with internal calls."""

    DETECTOR_ID = "EIP1153-002"
    NAME = "Transient Reentrancy Guard with Untrusted Internal Calls"
    DESCRIPTION = (
        "A transient-storage-based reentrancy lock (tstore/tload pattern) "
        "guards a function that performs delegatecall or low-level call to a "
        "user-supplied address. Within the same transaction the lock is held, "
        "but the callee can invoke other functions on this contract."
    )
    SCWE_ID = "SCWE-070"
    CWE_ID = "CWE-667"
    SEVERITY = Severity.MEDIUM
    CATEGORY = "transient-storage"

    _LOCK_CHECK_RE = re.compile(r"tload\s*\(")
    _LOCK_SET_RE = re.compile(r"tstore\s*\(")

    def detect(self, context: DetectorContext) -> list[FindingSchema]:
        findings: list[FindingSchema] = []
        lines = context.source_code.split("\n")
        ver = context.solidity_version
        if ver < (0, 8, 24):
            return findings

        in_function = ""
        has_transient_lock = False
        lock_line = 0

        for i, line in enumerate(lines, 1):
            func_match = re.match(r"\s*function\s+(\w+)", line)
            if func_match:
                in_function = func_match.group(1)
                has_transient_lock = False
                lock_line = 0

            if self._LOCK_CHECK_RE.search(line) and self._LOCK_SET_RE.search(
                "\n".join(lines[max(0, i - 1) : min(len(lines), i + 3)])
            ):
                has_transient_lock = True
                lock_line = i

            if has_transient_lock and (
                ".delegatecall(" in line
                or ".call{" in line
                or ".call(" in line
            ):
                findings.append(self._make_finding(
                    title=f"Transient reentrancy guard in `{in_function}` with external call",
                    description=(
                        f"Function `{in_function}` uses a transient-storage reentrancy guard "
                        f"(line {lock_line}) but makes an external call. While the transient "
                        "lock prevents classic reentrancy within this tx, the external callee "
                        "could invoke other unprotected functions on this contract."
                    ),
                    file_path=context.contract_name or "Contract.sol",
                    start_line=i,
                    end_line=i,
                    snippet=line.strip(),
                    remediation=(
                        "Ensure ALL state-modifying functions check the transient lock, "
                        "not just the guarded function. Consider using OpenZeppelin's "
                        "ReentrancyGuardTransient which handles this correctly."
                    ),
                ))

        return findings


class TransientSlotCollisionDetector(BaseDetector):
    """Detect potential slot collision between transient and regular storage."""

    DETECTOR_ID = "EIP1153-003"
    NAME = "Transient/Regular Storage Slot Collision"
    DESCRIPTION = (
        "The same slot identifier is used for both tstore/tload and sstore/sload, "
        "which may indicate a developer confusion between storage types."
    )
    SCWE_ID = "SCWE-070"
    CWE_ID = "CWE-694"
    SEVERITY = Severity.MEDIUM
    CATEGORY = "transient-storage"

    _TSTORE_SLOT_RE = re.compile(r"\btstore\s*\(\s*(\w+)")
    _TLOAD_SLOT_RE = re.compile(r"\btload\s*\(\s*(\w+)")
    _SSTORE_SLOT_RE = re.compile(r"\bsstore\s*\(\s*(\w+)")
    _SLOAD_SLOT_RE = re.compile(r"\bsload\s*\(\s*(\w+)")

    def detect(self, context: DetectorContext) -> list[FindingSchema]:
        findings: list[FindingSchema] = []
        ver = context.solidity_version
        if ver < (0, 8, 24):
            return findings

        lines = context.source_code.split("\n")
        transient_slots: dict[str, int] = {}
        regular_slots: dict[str, int] = {}

        for i, line in enumerate(lines, 1):
            for m in self._TSTORE_SLOT_RE.finditer(line):
                transient_slots.setdefault(m.group(1), i)
            for m in self._TLOAD_SLOT_RE.finditer(line):
                transient_slots.setdefault(m.group(1), i)
            for m in self._SSTORE_SLOT_RE.finditer(line):
                regular_slots.setdefault(m.group(1), i)
            for m in self._SLOAD_SLOT_RE.finditer(line):
                regular_slots.setdefault(m.group(1), i)

        collisions = set(transient_slots.keys()) & set(regular_slots.keys())
        for slot in collisions:
            # Skip numeric literals (0, 1, etc.) that are commonly reused
            if slot.isdigit():
                continue
            findings.append(self._make_finding(
                title=f"Slot identifier '{slot}' used in both transient and regular storage",
                description=(
                    f"The identifier `{slot}` appears in both transient storage "
                    f"(tstore/tload at line {transient_slots[slot]}) and regular storage "
                    f"(sstore/sload at line {regular_slots[slot]}). This may indicate "
                    "confusion between persistent and transient storage semantics."
                ),
                file_path=context.contract_name or "Contract.sol",
                start_line=transient_slots[slot],
                end_line=transient_slots[slot],
                snippet=lines[transient_slots[slot] - 1].strip(),
                remediation=(
                    "Use distinct slot identifiers for transient and regular storage. "
                    "Consider prefixing transient slots: `bytes32 constant T_SLOT = keccak256('transient.lock');`"
                ),
            ))

        return findings


class UnvalidatedTloadDetector(BaseDetector):
    """Detect tload values used in access control without validation."""

    DETECTOR_ID = "EIP1153-004"
    NAME = "Unvalidated Transient Storage in Access Control"
    DESCRIPTION = (
        "A tload value is used directly in a require/if guard for access control. "
        "Transient storage resets each transaction, so the guard value must be "
        "set earlier in the same transaction or it defaults to zero."
    )
    SCWE_ID = "SCWE-070"
    CWE_ID = "CWE-284"
    SEVERITY = Severity.HIGH
    CATEGORY = "transient-storage"

    _REQUIRE_TLOAD_RE = re.compile(
        r"require\s*\(\s*tload\s*\(|if\s*\(\s*tload\s*\("
    )

    def detect(self, context: DetectorContext) -> list[FindingSchema]:
        findings: list[FindingSchema] = []
        ver = context.solidity_version
        if ver < (0, 8, 24):
            return findings

        lines = context.source_code.split("\n")

        for i, line in enumerate(lines, 1):
            if self._REQUIRE_TLOAD_RE.search(line):
                # Check if there was a tstore in the same function before this line
                func_start = i
                for j in range(i - 1, 0, -1):
                    if re.match(r"\s*function\s+", lines[j - 1]):
                        func_start = j
                        break
                preceding = "\n".join(lines[func_start - 1 : i - 1])
                if "tstore" not in preceding:
                    findings.append(self._make_finding(
                        title="Access control uses tload without prior tstore in same function",
                        description=(
                            "A require/if statement reads from transient storage (tload) "
                            "but no tstore appears earlier in this function. The transient "
                            "slot will be zero at the start of every transaction, which could "
                            "make this guard always-pass or always-fail."
                        ),
                        file_path=context.contract_name or "Contract.sol",
                        start_line=i,
                        end_line=i,
                        snippet=line.strip(),
                        remediation=(
                            "Ensure the transient slot is set (tstore) before being read (tload) "
                            "in the same transaction. For cross-function guards, use a modifier "
                            "that calls tstore before the function body executes."
                        ),
                    ))

        return findings
