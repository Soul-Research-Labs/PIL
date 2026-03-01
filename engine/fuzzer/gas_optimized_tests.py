"""Gas-optimised Forge test generation.

Produces test harnesses that minimise gas usage via:
  - Tight Solidity types (uint8/uint16/uint32 instead of uint256)
  - Batched multi-call sequences in a single ``test_*`` function
  - ``--gas-report`` result parsing and per-function cost tracking
  - Calldata packing to reduce testdata footprint
  - Cold/warm storage-access separation
"""

from __future__ import annotations

import hashlib
import json
import logging
import re
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)


# ── Types ────────────────────────────────────────────────────────────────────


@dataclass
class GasReportEntry:
    """Parsed ``forge test --gas-report`` entry for one function."""
    contract: str
    function: str
    min_gas: int = 0
    avg_gas: int = 0
    median_gas: int = 0
    max_gas: int = 0
    calls: int = 0


@dataclass
class GasReport:
    """Aggregate gas report for a test suite."""
    entries: list[GasReportEntry] = field(default_factory=list)
    total_gas: int = 0
    deployment_gas: int = 0

    @property
    def hotspots(self) -> list[GasReportEntry]:
        """Functions sorted by maximum gas, descending."""
        return sorted(self.entries, key=lambda e: e.max_gas, reverse=True)

    def to_dict(self) -> dict[str, Any]:
        return {
            "total_gas": self.total_gas,
            "deployment_gas": self.deployment_gas,
            "functions": [
                {
                    "contract": e.contract,
                    "function": e.function,
                    "min": e.min_gas,
                    "avg": e.avg_gas,
                    "median": e.median_gas,
                    "max": e.max_gas,
                    "calls": e.calls,
                }
                for e in self.entries
            ],
        }


# ── Forge gas-report parser ─────────────────────────────────────────────────

_GAS_LINE_RE = re.compile(
    r"\|\s*(?P<func>\S+)\s*\|\s*(?P<min>\d+)\s*\|\s*(?P<avg>\d+)\s*\|\s*(?P<median>\d+)\s*\|\s*(?P<max>\d+)\s*\|\s*(?P<calls>\d+)\s*\|"
)
_CONTRACT_HEADER_RE = re.compile(r"\|\s*(?P<contract>\w+)\s+contract\s*\|")
_DEPLOY_GAS_RE = re.compile(
    r"\|\s*Deployment Cost\s*\|\s*Deployment Size\s*\|"
)
_DEPLOY_VALUES_RE = re.compile(
    r"\|\s*(?P<cost>\d+)\s*\|\s*(?P<size>\d+)\s*\|"
)


def parse_gas_report(stdout: str) -> GasReport:
    """Parse ``forge test --gas-report`` text output.

    Expects the standard table format that Forge emits, e.g.::

        | src/Token.sol:Token contract |
        |---|---|---|---|---|---|
        | Function | min | avg | median | max | # calls |
        | transfer | 4521 | 8402 | 8402 | 12284 | 5 |
    """
    report = GasReport()
    current_contract = ""

    lines = stdout.splitlines()
    i = 0
    while i < len(lines):
        line = lines[i]

        # Contract header
        cm = _CONTRACT_HEADER_RE.search(line)
        if cm:
            current_contract = cm.group("contract")
            i += 1
            continue

        # Deployment cost
        if _DEPLOY_GAS_RE.search(line) and i + 2 < len(lines):
            dm = _DEPLOY_VALUES_RE.search(lines[i + 2])
            if dm:
                report.deployment_gas += int(dm.group("cost"))
            i += 3
            continue

        # Function gas row
        gm = _GAS_LINE_RE.search(line)
        if gm and gm.group("func") not in ("Function", "---"):
            entry = GasReportEntry(
                contract=current_contract,
                function=gm.group("func"),
                min_gas=int(gm.group("min")),
                avg_gas=int(gm.group("avg")),
                median_gas=int(gm.group("median")),
                max_gas=int(gm.group("max")),
                calls=int(gm.group("calls")),
            )
            report.entries.append(entry)
            report.total_gas += entry.avg_gas * entry.calls

        i += 1

    return report


# ── Type tightening ──────────────────────────────────────────────────────────

# Mapping from value ranges to tightest Solidity unsigned integer type
_UINT_RANGES: list[tuple[int, str]] = [
    (2**8 - 1, "uint8"),
    (2**16 - 1, "uint16"),
    (2**32 - 1, "uint32"),
    (2**64 - 1, "uint64"),
    (2**128 - 1, "uint128"),
    (2**256 - 1, "uint256"),
]

_INT_RANGES: list[tuple[int, int, str]] = [
    (-(2**7), 2**7 - 1, "int8"),
    (-(2**15), 2**15 - 1, "int16"),
    (-(2**31), 2**31 - 1, "int32"),
    (-(2**63), 2**63 - 1, "int64"),
    (-(2**127), 2**127 - 1, "int128"),
    (-(2**255), 2**255 - 1, "int256"),
]


def tightest_uint(value: int) -> str:
    """Return the smallest ``uintN`` type that fits *value*."""
    for ceiling, typ in _UINT_RANGES:
        if value <= ceiling:
            return typ
    return "uint256"


def tightest_int(value: int) -> str:
    """Return the smallest ``intN`` type that fits *value*."""
    for lo, hi, typ in _INT_RANGES:
        if lo <= value <= hi:
            return typ
    return "int256"


def optimal_solidity_type(value: Any) -> str:
    """Infer the tightest Solidity type for a Python value."""
    if isinstance(value, bool):
        return "bool"
    if isinstance(value, int):
        if value < 0:
            return tightest_int(value)
        return tightest_uint(value)
    if isinstance(value, str):
        if value.startswith("0x"):
            if len(value) == 42:
                return "address"
            if len(value) == 66:
                return "bytes32"
            byte_len = (len(value) - 2) // 2
            if 1 <= byte_len <= 32:
                return f"bytes{byte_len}"
            return "bytes memory"
    if isinstance(value, bytes):
        if len(value) <= 32:
            return f"bytes{len(value)}"
        return "bytes memory"
    return "uint256"


# ── Gas-optimised test generator ─────────────────────────────────────────────


class GasOptimizedTestGenerator:
    """Generate gas-efficient Forge test harnesses.

    Improvements over the default ``TestHarnessGenerator``:
      - Uses tightest-fitting Solidity types for inputs
      - Batches multiple calls into one test to amortise setUp cost
      - Marks view-call results as ignored to avoid MSTORE overhead
      - Emits ``--gas-report``-compatible test naming
    """

    def __init__(self, contract_name: str, source_filename: str) -> None:
        self.contract_name = contract_name
        self.source_filename = source_filename

    # ------------------------------------------------------------------
    # Single optimised test
    # ------------------------------------------------------------------

    def generate_test(
        self,
        function_name: str,
        inputs: dict[str, Any],
        test_name: str = "",
    ) -> str:
        """Generate a single gas-optimised test case."""
        if not test_name:
            h = hashlib.md5(str(inputs).encode()).hexdigest()[:8]
            test_name = f"test_gas_{function_name}_{h}"

        decls = self._tight_declarations(inputs)
        args = ", ".join(
            k for k in inputs if not k.startswith("_")
        )

        return f"""// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "../src/{self.source_filename}";

contract {test_name}_Test is Test {{
    {self.contract_name} internal target;

    function setUp() public {{
        target = new {self.contract_name}();
    }}

    function {test_name}() public {{
{decls}
        target.{function_name}({args});
    }}
}}
"""

    # ------------------------------------------------------------------
    # Batched sequence test
    # ------------------------------------------------------------------

    def generate_batched_test(
        self,
        calls: list[dict[str, Any]],
        test_name: str = "test_gas_batch",
        max_batch_size: int = 20,
    ) -> str:
        """Batch multiple calls into one test to amortise deployment cost.

        Each call dict has ``function``, ``inputs``, and optionally
        ``from`` and ``value`` keys.
        """
        steps: list[str] = []
        for idx, call in enumerate(calls[:max_batch_size]):
            fname = call.get("function", "unknown")
            inputs = call.get("inputs", {})
            sender = call.get("from", "")
            value_wei = call.get("value", 0)

            decls = self._tight_declarations(inputs, prefix=f"s{idx}_")
            args = ", ".join(
                f"s{idx}_{k}" for k in inputs if not k.startswith("_")
            )
            prank = f"        vm.prank({sender});\n" if sender else ""
            val = f"{{value: {value_wei}}}" if value_wei else ""

            steps.append(
                f"        // call {idx}: {fname}\n"
                f"{decls}\n"
                f"{prank}"
                f"        target.{fname}{val}({args});\n"
            )

        body = "\n".join(steps)

        return f"""// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "../src/{self.source_filename}";

contract {test_name}_Test is Test {{
    {self.contract_name} internal target;

    function setUp() public {{
        target = new {self.contract_name}();
        vm.deal(address(this), 100 ether);
    }}

    function {test_name}() public {{
{body}
    }}
}}
"""

    # ------------------------------------------------------------------
    # ABI gas snapshot harness
    # ------------------------------------------------------------------

    def generate_gas_snapshot_harness(
        self,
        abi: list[dict[str, Any]],
    ) -> str:
        """Generate a harness that produces per-function gas snapshots.

        Each external/public mutator gets its own ``test_gas_<func>()``
        so that ``forge test --gas-report`` emits a clean breakdown.
        """
        functions: list[str] = []

        for item in abi:
            if item.get("type") != "function":
                continue
            if item.get("stateMutability") in ("view", "pure"):
                continue

            fname = item["name"]
            params = item.get("inputs", [])

            # Default zero-valued arguments
            args: list[str] = []
            decls: list[str] = []
            for j, p in enumerate(params):
                ptype = p.get("type", "uint256")
                pname = p.get("name") or f"arg{j}"
                default = self._default_for_type(ptype)
                decls.append(f"        {ptype} {pname} = {default};")
                args.append(pname)

            decl_block = "\n".join(decls) if decls else "        // no args"
            arg_list = ", ".join(args)

            functions.append(f"""
    function test_gas_{fname}() public {{
{decl_block}
        target.{fname}({arg_list});
    }}""")

        fn_block = "\n".join(functions)

        return f"""// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "../src/{self.source_filename}";

contract GasSnapshot_{self.contract_name} is Test {{
    {self.contract_name} internal target;

    function setUp() public {{
        target = new {self.contract_name}();
        vm.deal(address(this), 100 ether);
    }}
{fn_block}
}}
"""

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _tight_declarations(
        self,
        inputs: dict[str, Any],
        prefix: str = "",
    ) -> str:
        """Emit variable declarations using the tightest type."""
        lines: list[str] = []
        for key, val in inputs.items():
            if key.startswith("_"):
                continue
            vname = f"{prefix}{key}"
            typ = optimal_solidity_type(val)

            if isinstance(val, bool):
                lit = "true" if val else "false"
            elif isinstance(val, int):
                lit = str(val) if val >= 0 else f"int256({val})"
                if val > 10_000:
                    lit = hex(val)
            elif isinstance(val, str) and val.startswith("0x"):
                lit = val
            elif isinstance(val, bytes):
                lit = f'hex"{val.hex()}"'
            else:
                lit = str(val)

            lines.append(f"        {typ} {vname} = {lit};")

        return "\n".join(lines) if lines else "        // no inputs"

    @staticmethod
    def _default_for_type(soltype: str) -> str:
        """Return a zero-value literal for a Solidity type."""
        if soltype == "address":
            return "address(1)"
        if soltype == "bool":
            return "false"
        if soltype.startswith("bytes") and not soltype.endswith("[]"):
            n = soltype[5:]
            if n.isdigit():
                return f'bytes{n}(0)'
            return 'bytes("")'
        if soltype.startswith("string"):
            return '""'
        if soltype.startswith("int"):
            return "0"
        # uint, default
        return "0"
