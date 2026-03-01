"""Advanced storage analysis detectors — SCWE-042.

Deep storage layout analysis for proxy contracts and complex inheritance:
  - Uninitialized storage pointers (pre-0.5.0)
  - Storage collision in proxy upgrades
  - Dirty higher-order bits in storage packing
  - Incorrect storage gap sizing in upgradeable contracts
  - Storage slot overlap across inheritance chains
  - Transient storage (EIP-1153) misuse
"""

from __future__ import annotations

import re

from engine.analyzer.web3.base_detector import BaseDetector, DetectorContext
from engine.core.types import FindingSchema, Severity


class StorageGapDetector(BaseDetector):
    """Detect missing or incorrect storage gaps in upgradeable contracts."""

    DETECTOR_ID = "SCWE-042-001"
    NAME = "Missing / Incorrect Storage Gap"
    DESCRIPTION = (
        "Detects upgradeable contracts that lack __gap storage arrays, or have "
        "gaps that don't account for all state variables, risking storage "
        "collision on upgrade."
    )
    SCWE_ID = "SCWE-042"
    CWE_ID = "CWE-119"
    SEVERITY = Severity.HIGH
    CATEGORY = "storage"

    def detect(self, context: DetectorContext) -> list[FindingSchema]:
        findings: list[FindingSchema] = []
        source = context.source_code
        lines = source.split("\n")

        # Only check upgradeable contracts
        is_upgradeable = bool(re.search(
            r'Initializable|initializer|__init\(|upgradeTo|UUPSUpgradeable|TransparentUpgradeable',
            source,
        ))
        if not is_upgradeable:
            return findings

        # Find all contracts in the source
        contracts: list[tuple[str, int, int]] = []
        current_contract = ""
        contract_start = 0
        depth = 0
        for i, line in enumerate(lines):
            contract_match = re.match(
                r'\s*(?:abstract\s+)?contract\s+(\w+)', line
            )
            if contract_match:
                current_contract = contract_match.group(1)
                contract_start = i
                depth = 0

            depth += line.count("{") - line.count("}")
            if current_contract and depth <= 0 and i > contract_start:
                contracts.append((current_contract, contract_start, i))
                current_contract = ""

        for contract_name, start, end in contracts:
            contract_source = "\n".join(lines[start:end + 1])

            # Count state variables
            state_vars = re.findall(
                r'^\s+(?:uint\d*|int\d*|address|bool|bytes\d*|string|mapping)\s+',
                contract_source,
                re.MULTILINE,
            )

            has_gap = bool(re.search(r'uint256\s*\[\s*\d+\s*\]\s+__gap', contract_source))
            has_state = len(state_vars) > 0

            if has_state and not has_gap and "is" in lines[start]:
                # Has state vars, inherits, but no gap — collision risk on upgrade
                findings.append(self._make_finding(
                    title=f"Missing storage gap in `{contract_name}`",
                    description=(
                        f"The upgradeable contract `{contract_name}` (line {start + 1}) "
                        f"declares {len(state_vars)} state variable(s) but has no `__gap` "
                        "storage array. Adding new state variables in a future version "
                        "will cause storage collision with child contracts."
                    ),
                    file_path=context.contract_name or "Contract.sol",
                    start_line=start + 1,
                    end_line=start + 1,
                    remediation=(
                        "Add a storage gap at the end of the contract:\n"
                        "```solidity\n"
                        "// Reserve 50 - (number of slots used) slots for future use\n"
                        f"uint256[{50 - len(state_vars)}] private __gap;\n"
                        "```"
                    ),
                ))

            # Check gap sizing
            if has_gap:
                gap_match = re.search(r'uint256\s*\[\s*(\d+)\s*\]\s+__gap', contract_source)
                if gap_match:
                    gap_size = int(gap_match.group(1))
                    total_slots = gap_size + len(state_vars)
                    if total_slots != 50 and total_slots != 100:
                        gap_line = start + contract_source[:gap_match.start()].count("\n")
                        snippet = lines[gap_line] if gap_line < len(lines) else ""
                        findings.append(self._make_finding(
                            title=f"Incorrect storage gap in `{contract_name}`",
                            description=(
                                f"The contract has {len(state_vars)} state variables and "
                                f"a gap of {gap_size}, totaling {total_slots} slots. "
                                "Standard practice is to maintain exactly 50 or 100 total "
                                "slots. Incorrect gap sizing leads to storage collision."
                            ),
                            file_path=context.contract_name or "Contract.sol",
                            start_line=gap_line + 1,
                            end_line=gap_line + 1,
                            snippet=snippet,
                            severity=Severity.MEDIUM,
                            remediation=(
                                f"Update gap to maintain 50 total slots:\n"
                                f"```solidity\n"
                                f"uint256[{50 - len(state_vars)}] private __gap;\n"
                                f"```"
                            ),
                        ))

        return findings


class StorageSlotOverlapDetector(BaseDetector):
    """Detect potential storage slot overlaps in inheritance chains."""

    DETECTOR_ID = "SCWE-042-002"
    NAME = "Storage Slot Overlap"
    DESCRIPTION = (
        "Detects potential storage slot overlaps when multiple inheritance "
        "paths declare state variables that may collide."
    )
    SCWE_ID = "SCWE-042"
    CWE_ID = "CWE-119"
    SEVERITY = Severity.HIGH
    CATEGORY = "storage"

    def detect(self, context: DetectorContext) -> list[FindingSchema]:
        findings: list[FindingSchema] = []
        source = context.source_code
        lines = source.split("\n")

        # Analyze storage layout if available from compilation
        storage_layout = context.storage_layout
        if not storage_layout or "storage" not in storage_layout:
            return findings

        storage_entries = storage_layout.get("storage", [])
        slot_map: dict[str, list[dict]] = {}

        for entry in storage_entries:
            slot = entry.get("slot", "")
            if slot in slot_map:
                slot_map[slot].append(entry)
            else:
                slot_map[slot] = [entry]

        for slot, entries in slot_map.items():
            if len(entries) > 1:
                # Check if they're actually packed (same slot but different offsets)
                offsets = {e.get("offset", 0) for e in entries}
                if len(offsets) < len(entries):
                    # True overlap — same slot AND offset
                    names = [e.get("label", "?") for e in entries]
                    findings.append(self._make_finding(
                        title=f"Storage slot collision at slot {slot}",
                        description=(
                            f"Variables {', '.join(names)} share storage slot {slot} "
                            "with overlapping offsets. Writing to one variable will "
                            "corrupt the other, leading to unpredictable behavior."
                        ),
                        file_path=context.contract_name or "Contract.sol",
                        start_line=1,
                        end_line=1,
                        severity=Severity.CRITICAL,
                        remediation=(
                            "Review the inheritance chain and add __gap arrays to "
                            "prevent slot collisions. Use `forge inspect --storage-layout` "
                            "to verify slot assignments."
                        ),
                    ))

        return findings


class UninitializedStorageDetector(BaseDetector):
    """Detect uninitialized storage pointers (pre-Solidity 0.5)."""

    DETECTOR_ID = "SCWE-042-003"
    NAME = "Uninitialized Storage Pointer"
    DESCRIPTION = (
        "Detects local struct or array variables that default to storage "
        "reference (in Solidity < 0.5.0), potentially pointing to slot 0 "
        "and corrupting contract state."
    )
    SCWE_ID = "SCWE-042"
    CWE_ID = "CWE-457"
    SEVERITY = Severity.HIGH
    CATEGORY = "storage"

    def detect(self, context: DetectorContext) -> list[FindingSchema]:
        findings: list[FindingSchema] = []
        source = context.source_code
        lines = source.split("\n")

        # Check compiler version
        version_match = re.search(r'pragma\s+solidity\s+[^;]*(\d+)\.(\d+)\.(\d+)', source)
        if version_match:
            major = int(version_match.group(1))
            minor = int(version_match.group(2))
            if major > 0 or minor >= 5:
                return findings  # Fixed in Solidity 0.5.0+

        # Look for local variables that might default to storage
        for i, line in enumerate(lines):
            # struct Foo x; (without memory/storage keyword)
            struct_match = re.search(
                r'^\s+(\w+)\s+(\w+)\s*;', line
            )
            if struct_match:
                type_name = struct_match.group(1)
                var_name = struct_match.group(2)
                # Check if it's a struct type (not a basic type)
                if re.search(rf'struct\s+{type_name}\s*\{{', source):
                    if "memory" not in line and "storage" not in line:
                        snippet = "\n".join(
                            lines[max(0, i - 1):min(len(lines), i + 2)]
                        )
                        findings.append(self._make_finding(
                            title=f"Uninitialized storage pointer: `{var_name}`",
                            description=(
                                f"The local variable `{var_name}` of type `{type_name}` "
                                f"(line {i + 1}) is declared without a data location. "
                                "In Solidity < 0.5.0, local structs default to storage, "
                                "pointing to slot 0. Any writes to `{var_name}` will "
                                "overwrite critical contract state."
                            ),
                            file_path=context.contract_name or "Contract.sol",
                            start_line=i + 1,
                            end_line=i + 1,
                            snippet=snippet,
                            severity=Severity.CRITICAL,
                            remediation=(
                                f"Explicitly declare the data location:\n"
                                f"```solidity\n"
                                f"{type_name} memory {var_name}; // or storage if intended\n"
                                f"```\n"
                                f"Better yet, upgrade to Solidity >= 0.5.0 where this is a compiler error."
                            ),
                        ))

        return findings


class TransientStorageDetector(BaseDetector):
    """Detect potential misuse of EIP-1153 transient storage."""

    DETECTOR_ID = "SCWE-042-004"
    NAME = "Transient Storage Misuse"
    DESCRIPTION = (
        "Detects potential misuse of EIP-1153 transient storage (TSTORE/TLOAD) "
        "where values are expected to persist across transactions but are "
        "cleared at transaction end."
    )
    SCWE_ID = "SCWE-042"
    CWE_ID = "CWE-665"
    SEVERITY = Severity.MEDIUM
    CATEGORY = "storage"

    def detect(self, context: DetectorContext) -> list[FindingSchema]:
        findings: list[FindingSchema] = []
        source = context.source_code
        lines = source.split("\n")

        has_tstore = bool(re.search(r'\btstore\b|\btload\b', source, re.IGNORECASE))
        if not has_tstore:
            return findings

        # Find TSTORE usage
        for match in re.finditer(r'tstore\s*\(', source, re.IGNORECASE):
            line_no = source[:match.start()].count("\n")
            snippet = "\n".join(
                lines[max(0, line_no - 2):min(len(lines), line_no + 3)]
            )

            # Check if the stored value is read in a different function
            # (could indicate cross-call assumption)
            findings.append(self._make_finding(
                title=f"Transient storage (tstore) at line {line_no + 1}",
                description=(
                    "EIP-1153 transient storage is used here. Values stored with "
                    "TSTORE are cleared at the end of each transaction. If the code "
                    "expects these values to persist, this is a critical bug. "
                    "Also, transient storage is not available on all chains yet."
                ),
                file_path=context.contract_name or "Contract.sol",
                start_line=line_no + 1,
                end_line=line_no + 1,
                snippet=snippet,
                severity=Severity.LOW,
                remediation=(
                    "Ensure transient storage is used correctly:\n"
                    "1. Values are ONLY needed within the same transaction\n"
                    "2. Common valid uses: reentrancy locks, temporary approvals\n"
                    "3. Do NOT use for persistent state\n"
                    "4. Verify target chain supports EIP-1153 (Cancun+ on Ethereum)"
                ),
            ))

        return findings


class DirtyBitsDetector(BaseDetector):
    """Detect potential dirty higher-order bit issues in type casting."""

    DETECTOR_ID = "SCWE-042-005"
    NAME = "Dirty Storage Bits"
    DESCRIPTION = (
        "Detects unsafe type casting that may leave dirty higher-order bits "
        "in storage-packed variables, corrupting adjacent packed values."
    )
    SCWE_ID = "SCWE-042"
    CWE_ID = "CWE-704"
    SEVERITY = Severity.MEDIUM
    CATEGORY = "storage"

    def detect(self, context: DetectorContext) -> list[FindingSchema]:
        findings: list[FindingSchema] = []
        source = context.source_code
        lines = source.split("\n")

        # Detect unsafe downcasts to packed storage types
        downcast_patterns = [
            (r'uint8\s*\(\s*\w+\s*\)', "uint8"),
            (r'uint16\s*\(\s*\w+\s*\)', "uint16"),
            (r'uint32\s*\(\s*\w+\s*\)', "uint32"),
            (r'uint64\s*\(\s*\w+\s*\)', "uint64"),
            (r'uint128\s*\(\s*\w+\s*\)', "uint128"),
            (r'int8\s*\(\s*\w+\s*\)', "int8"),
            (r'int16\s*\(\s*\w+\s*\)', "int16"),
        ]

        for pattern, target_type in downcast_patterns:
            for match in re.finditer(pattern, source):
                line_no = source[:match.start()].count("\n")
                line_text = lines[line_no].strip()

                # Check if result is stored in a packed storage variable
                if "=" in line_text and ("storage" in line_text or "." in line_text):
                    snippet = "\n".join(
                        lines[max(0, line_no - 1):min(len(lines), line_no + 2)]
                    )
                    findings.append(self._make_finding(
                        title=f"Unsafe downcast to {target_type} stored in packed slot",
                        description=(
                            f"A value is downcast to {target_type} at line {line_no + 1} "
                            "and stored in what appears to be a packed storage slot. "
                            "If the value exceeds the target range, higher-order bits "
                            "may corrupt adjacent packed variables in the same slot."
                        ),
                        file_path=context.contract_name or "Contract.sol",
                        start_line=line_no + 1,
                        end_line=line_no + 1,
                        snippet=snippet,
                        severity=Severity.MEDIUM,
                        remediation=(
                            "Use OpenZeppelin's SafeCast library for safe downcasting:\n"
                            "```solidity\n"
                            "import '@openzeppelin/contracts/utils/math/SafeCast.sol';\n"
                            f"using SafeCast for uint256;\n"
                            f"uint{target_type[4:]} value = someValue.to{target_type.capitalize()}();\n"
                            "```"
                        ),
                    ))

        return findings
