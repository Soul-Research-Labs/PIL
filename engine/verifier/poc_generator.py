"""PoC generator — AI-powered exploit proof-of-concept generation for smart contracts."""

from __future__ import annotations

import hashlib
from typing import Any

from engine.core.llm_client import LLMClient
from engine.core.types import FindingSchema, Severity


POC_SYSTEM_PROMPT = """You are a security researcher generating proof-of-concept exploits for smart contract vulnerabilities.

Rules:
1. Generate MINIMAL, self-contained exploit code that demonstrates the vulnerability.
2. The PoC should PASS (exit 0) if the vulnerability exists, and FAIL (exit 1) if it doesn't.
3. Print "EXPLOIT SUCCESSFUL" on success or "EXPLOIT FAILED" on failure.
4. Use Foundry's Test framework with forge-std assertions.
5. Include comments explaining each exploitation step.
6. Never generate destructive or malicious payloads — only demonstrate the vulnerability exists.

Respond ONLY with valid JSON."""

SOLIDITY_POC_PROMPT = """Generate a Foundry test that exploits this smart contract vulnerability:

**Title**: {title}
**Severity**: {severity}
**SCWE**: {scwe_id}
**Description**: {description}

**Vulnerable Contract**:
```solidity
{contract_source}
```

Generate a Foundry test contract (using forge-std/Test.sol) that:
1. Deploys the vulnerable contract
2. Sets up attacker account
3. Executes the exploit
4. Asserts that the exploit succeeded (e.g., attacker gained funds, state was corrupted)

Respond with:
{{
  "test_contract": "Full Solidity test code with forge-std imports",
  "exploit_steps": ["Step-by-step explanation"],
  "expected_result": "What the test proves"
}}"""


class PoCGenerator:
    """Generate proof-of-concept exploits for smart contract vulnerabilities."""

    def __init__(self) -> None:
        self._llm = LLMClient()

    async def generate_solidity_poc(
        self,
        finding: FindingSchema,
        contract_source: str,
    ) -> dict:
        """Generate a Foundry test PoC for a Solidity vulnerability."""
        prompt = SOLIDITY_POC_PROMPT.format(
            title=finding.title,
            severity=finding.severity.value,
            scwe_id=finding.scwe_id or finding.cwe_id or "N/A",
            description=finding.description,
            contract_source=contract_source[:8000],
        )

        return await self._llm.analyze(POC_SYSTEM_PROMPT, prompt)

    def generate_tx_sequence_poc(
        self,
        tx_sequence: list[dict[str, Any]],
        contract_name: str,
        source_filename: str = "",
        finding: FindingSchema | None = None,
    ) -> str:
        """Generate a deterministic Foundry PoC by replaying a concrete tx_sequence.

        Unlike ``generate_solidity_poc`` (which uses an LLM), this method
        produces a fully-concrete Foundry test that replays the exact
        calls discovered by the fuzzer — no LLM required.

        Parameters
        ----------
        tx_sequence:
            List of transaction dicts, each containing at minimum:
            ``{"function": "...", "inputs": {...}}``
            and optionally ``"from"``, ``"value"``, ``"block_timestamp"``.
        contract_name:
            Name of the target contract.
        source_filename:
            Filename for the import directive (defaults to ``{contract_name}.sol``).
        finding:
            Optional finding whose title/description are embedded as comments.
        """
        if not source_filename:
            source_filename = f"{contract_name}.sol"

        seq_hash = hashlib.sha256(str(tx_sequence).encode()).hexdigest()[:10]
        test_name = f"test_replay_{seq_hash}"

        # ── Per-step Solidity lines ──────────────────────────────────────
        steps_lines: list[str] = []
        for idx, tx in enumerate(tx_sequence):
            func = tx.get("function", "fallback")
            inputs = tx.get("inputs", {})
            sender = tx.get("from", "")
            value = tx.get("value", 0)
            ts = tx.get("block_timestamp")

            lines: list[str] = [f"        // Step {idx}: {func}"]
            if ts is not None:
                lines.append(f"        vm.warp({ts});")
            if sender:
                lines.append(f"        vm.prank({sender});")

            # Build typed value declarations
            decl_lines, arg_names = _build_input_decls(inputs, prefix=f"s{idx}_")
            lines.extend(f"        {d}" for d in decl_lines)

            call_args = ", ".join(arg_names)
            value_part = f"{{value: {value}}}" if value else ""
            lines.append(f"        target.{func}{value_part}({call_args});")
            steps_lines.append("\n".join(lines))

        steps_block = "\n\n".join(steps_lines)

        finding_comment = ""
        if finding:
            finding_comment = (
                f" * @notice Reproduces: {finding.title}\n"
                f" *         Severity:    {finding.severity.value}\n"
            )

        return f"""// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "../src/{source_filename}";

/**
 * @title Replay PoC — {test_name}
 * @dev Auto-generated from a concrete tx_sequence discovered by the PIL++ fuzzer.
{finding_comment} */
contract {test_name}_Test is Test {{
    {contract_name} target;

    function setUp() public {{
        target = new {contract_name}();
        vm.deal(address(this), 100 ether);
    }}

    function {test_name}() public {{
{steps_block}
    }}
}}
"""


# ── helpers ──────────────────────────────────────────────────────────────────

def _build_input_decls(
    inputs: dict[str, Any], prefix: str = "",
) -> tuple[list[str], list[str]]:
    """Return (declaration_lines, arg_names) for a set of concrete inputs."""
    decls: list[str] = []
    names: list[str] = []
    for key, val in inputs.items():
        if key.startswith("_"):
            continue
        var = f"{prefix}{key}"
        names.append(var)
        if isinstance(val, int):
            if val < 0:
                decls.append(f"int256 {var} = {val};")
            elif val > 2 ** 160:
                decls.append(f"uint256 {var} = {hex(val)};")
            else:
                decls.append(f"uint256 {var} = {val};")
        elif isinstance(val, str) and val.startswith("0x"):
            if len(val) == 42:
                decls.append(f"address {var} = {val};")
            elif len(val) == 66:
                decls.append(f"bytes32 {var} = {val};")
            else:
                decls.append(f'bytes memory {var} = hex"{val[2:]}";')
        elif isinstance(val, bytes):
            decls.append(f'bytes memory {var} = hex"{val.hex()}";')
        elif isinstance(val, bool):
            decls.append(f"bool {var} = {'true' if val else 'false'};")
        else:
            decls.append(f"// {var} = {val}")
    return decls, names


class VerificationEngine:
    """End-to-end smart contract exploit verification: generate PoC → execute → confirm.

    Pipeline:
    1. Generate Foundry test PoC via LLM
    2. Execute in Foundry sandbox
    3. Analyze results to confirm/deny vulnerability
    4. Update finding status (CONFIRMED / FALSE_POSITIVE)
    """

    def __init__(self) -> None:
        from engine.verifier.sandbox import FoundrySandbox

        self._poc_gen = PoCGenerator()
        self._foundry = FoundrySandbox()

    async def verify_finding(
        self,
        finding: FindingSchema,
        source_code: str,
    ) -> FindingSchema:
        """Verify a single finding by generating and executing a Foundry PoC.

        If the finding carries a ``tx_sequence`` in its metadata, a
        deterministic replay PoC is generated first (no LLM call).
        Falls back to the LLM-based generation when no sequence exists.

        Returns the finding with updated status and PoC details.
        """
        if finding.severity in (Severity.INFORMATIONAL, Severity.GAS):
            # Don't generate PoCs for informational / gas findings
            return finding

        try:
            # ── Prefer concrete tx_sequence replay ───────────────────────
            tx_seq = (finding.metadata or {}).get("tx_sequence")
            contract_name = (finding.metadata or {}).get("contract_name", "Target")
            if tx_seq and isinstance(tx_seq, list) and len(tx_seq) > 0:
                poc_code = self._poc_gen.generate_tx_sequence_poc(
                    tx_sequence=tx_seq,
                    contract_name=contract_name,
                    finding=finding,
                )
                poc_result: dict = {
                    "test_contract": poc_code,
                    "explanation": "Deterministic replay from fuzzer tx_sequence",
                }
            else:
                poc_result = await self._poc_gen.generate_solidity_poc(
                    finding, source_code
                )
                poc_code = poc_result.get("test_contract", "")

            if not poc_code:
                return finding

            sandbox_result = await self._foundry.execute_foundry_test(
                test_contract=poc_code,
                target_contract=source_code,
            )

            # Update finding based on verification result
            finding.poc_script = poc_code
            finding.metadata["verification"] = {
                "exploit_confirmed": sandbox_result.exploit_confirmed,
                "exit_code": sandbox_result.exit_code,
                "duration": sandbox_result.duration_seconds,
                "explanation": poc_result.get("explanation", ""),
            }

            if sandbox_result.exploit_confirmed:
                from engine.core.types import FindingStatus
                finding.status = FindingStatus.CONFIRMED
            else:
                finding.confidence *= 0.5  # Reduce confidence if PoC failed

        except Exception as e:
            finding.metadata["verification_error"] = str(e)

        return finding

    async def verify_findings(
        self,
        findings: list[FindingSchema],
        source_code: str,
        is_smart_contract: bool = True,
        max_concurrent: int = 3,
    ) -> list[FindingSchema]:
        """Verify multiple findings with concurrency limit."""
        import asyncio

        semaphore = asyncio.Semaphore(max_concurrent)

        async def _verify_with_limit(f: FindingSchema) -> FindingSchema:
            async with semaphore:
                return await self.verify_finding(f, source_code)

        tasks = [_verify_with_limit(f) for f in findings]
        return await asyncio.gather(*tasks)
