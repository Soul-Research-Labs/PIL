"""Governance attack detectors — SCWE-039.

Detect governance manipulation vectors:
  - Flash loan governance (borrow tokens to pass proposals)
  - Vote manipulation via delegation / snapshot bypass
  - Timelock bypass or insufficient delay
  - Proposal threshold manipulation
  - Quorum exploitation
"""

from __future__ import annotations

import re

from engine.analyzer.web3.base_detector import BaseDetector, DetectorContext
from engine.core.types import FindingSchema, Severity


class FlashLoanGovernanceDetector(BaseDetector):
    """Detect governance vulnerable to flash loan vote buying."""

    DETECTOR_ID = "SCWE-039-001"
    NAME = "Flash Loan Governance Attack"
    DESCRIPTION = (
        "Detects governance systems where voting power is based on current "
        "token balance rather than historical snapshots, allowing flash loan "
        "powered vote manipulation."
    )
    SCWE_ID = "SCWE-039"
    CWE_ID = "CWE-284"
    SEVERITY = Severity.CRITICAL
    CATEGORY = "governance"

    def detect(self, context: DetectorContext) -> list[FindingSchema]:
        findings: list[FindingSchema] = []
        source = context.source_code
        lines = source.split("\n")

        # Check for governance patterns
        is_governance = bool(re.search(
            r'function\s+(propose|castVote|execute|queue)\s*\(', source
        ))
        if not is_governance:
            return findings

        # Dangerous: using current balanceOf for voting
        balance_vote_patterns = [
            (r'balanceOf\s*\(\s*msg\.sender\s*\)', "balanceOf(msg.sender) as voting power"),
            (r'balanceOf\s*\(\s*voter\s*\)', "balanceOf(voter) as voting power"),
            (r'getVotes\s*\(\s*msg\.sender\s*\)', "current getVotes (no snapshot)"),
        ]

        # Safe patterns (snapshot-based)
        safe_patterns = [
            "getPastVotes", "getPriorVotes", "getVotesAtBlock", "_checkpoints",
            "snapshotId", "blockNumber", "proposalSnapshot",
        ]
        uses_snapshot = any(p in source for p in safe_patterns)

        if uses_snapshot:
            return findings

        for pattern, desc in balance_vote_patterns:
            for match in re.finditer(pattern, source):
                line_no = source[:match.start()].count("\n")
                snippet = "\n".join(
                    lines[max(0, line_no - 2):min(len(lines), line_no + 3)]
                )
                findings.append(self._make_finding(
                    title=f"Flash loan governance: {desc}",
                    description=(
                        f"Governance uses {desc} (line {line_no + 1}) for voting power. "
                        "An attacker can:\n"
                        "1. Flash loan a large amount of governance tokens\n"
                        "2. Vote on or create a malicious proposal\n"
                        "3. Return the tokens in the same transaction\n"
                        "This effectively gives free unlimited voting power."
                    ),
                    file_path=context.contract_name or "Contract.sol",
                    start_line=line_no + 1,
                    end_line=line_no + 1,
                    snippet=snippet,
                    remediation=(
                        "Use snapshot-based voting power (e.g., OpenZeppelin Governor):\n"
                        "```solidity\n"
                        "function getVotes(address account, uint256 blockNumber)\n"
                        "    public view returns (uint256) {\n"
                        "    return token.getPastVotes(account, blockNumber);\n"
                        "}\n```"
                    ),
                ))

        return findings


class TimelockBypassDetector(BaseDetector):
    """Detect timelock bypass or insufficient delay."""

    DETECTOR_ID = "SCWE-039-002"
    NAME = "Timelock Bypass"
    DESCRIPTION = (
        "Detects governance timelock implementations with insufficient delay, "
        "admin override capabilities, or missing delay enforcement."
    )
    SCWE_ID = "SCWE-039"
    CWE_ID = "CWE-284"
    SEVERITY = Severity.HIGH
    CATEGORY = "governance"

    def detect(self, context: DetectorContext) -> list[FindingSchema]:
        findings: list[FindingSchema] = []
        source = context.source_code
        lines = source.split("\n")

        has_timelock = bool(re.search(
            r'[Tt]imelock|TIMELOCK|delay|MIN_DELAY|MINIMUM_DELAY', source
        ))
        if not has_timelock:
            return findings

        # 1. Delay set to 0 or very low
        for match in re.finditer(
            r'(?:delay|MIN_DELAY|MINIMUM_DELAY|minDelay)\s*=\s*(\d+)',
            source,
        ):
            delay_val = int(match.group(1))
            line_no = source[:match.start()].count("\n")
            if delay_val < 3600:  # Less than 1 hour
                snippet = "\n".join(
                    lines[max(0, line_no - 1):min(len(lines), line_no + 2)]
                )
                findings.append(self._make_finding(
                    title=f"Timelock delay too short: {delay_val}s",
                    description=(
                        f"The timelock delay is set to {delay_val} seconds "
                        f"(line {line_no + 1}), which is less than 1 hour. This gives "
                        "users insufficient time to react to malicious proposals."
                    ),
                    file_path=context.contract_name or "Contract.sol",
                    start_line=line_no + 1,
                    end_line=line_no + 1,
                    snippet=snippet,
                    severity=Severity.HIGH if delay_val == 0 else Severity.MEDIUM,
                    remediation=(
                        "Set a minimum delay of at least 24-48 hours (86400-172800s) "
                        "to give token holders time to exit if a malicious proposal passes."
                    ),
                ))

        # 2. Admin can bypass timelock
        for match in re.finditer(
            r'function\s+(emergencyExecute|adminExecute|bypassTimelock|executeEmergency)\s*\(',
            source,
        ):
            func_name = match.group(1)
            line_no = source[:match.start()].count("\n")
            snippet = "\n".join(
                lines[line_no:min(len(lines), line_no + 5)]
            )
            findings.append(self._make_finding(
                title=f"Timelock bypass function: {func_name}",
                description=(
                    f"The function `{func_name}` (line {line_no + 1}) allows bypassing "
                    "the timelock mechanism. An admin with this capability can execute "
                    "arbitrary proposals immediately, defeating the purpose of the timelock."
                ),
                file_path=context.contract_name or "Contract.sol",
                start_line=line_no + 1,
                end_line=line_no + 5,
                snippet=snippet,
                severity=Severity.CRITICAL,
                remediation=(
                    "Remove admin bypass functions. If emergency execution is needed, "
                    "require a supermajority multisig with a shorter (but non-zero) delay."
                ),
            ))

        # 3. Delay can be changed by admin
        for match in re.finditer(
            r'function\s+(setDelay|updateDelay|changeDelay|setMinDelay)\s*\(',
            source,
        ):
            func_name = match.group(1)
            line_no = source[:match.start()].count("\n")
            func_end = min(len(lines), line_no + 15)
            func_text = "\n".join(lines[line_no:func_end])

            has_min_check = bool(re.search(r'require\s*\(.*>=\s*\d{4,}', func_text))
            if not has_min_check:
                snippet = "\n".join(lines[line_no:min(len(lines), line_no + 5)])
                findings.append(self._make_finding(
                    title=f"Timelock delay modifiable without minimum: {func_name}",
                    description=(
                        f"The function `{func_name}` (line {line_no + 1}) can change "
                        "the timelock delay without enforcing a minimum. An admin can "
                        "set the delay to 0 and then immediately execute proposals."
                    ),
                    file_path=context.contract_name or "Contract.sol",
                    start_line=line_no + 1,
                    end_line=line_no + 5,
                    snippet=snippet,
                    severity=Severity.HIGH,
                    remediation=(
                        "Enforce a minimum delay that cannot be changed:\n"
                        "```solidity\n"
                        "uint256 public constant MINIMUM_DELAY = 2 days;\n"
                        "function setDelay(uint256 newDelay) external onlyGovernance {\n"
                        "    require(newDelay >= MINIMUM_DELAY, \"Below minimum\");\n"
                        "    delay = newDelay;\n"
                        "}\n```"
                    ),
                ))

        return findings


class QuorumExploitDetector(BaseDetector):
    """Detect low or manipulable quorum thresholds."""

    DETECTOR_ID = "SCWE-039-003"
    NAME = "Governance Quorum Exploitation"
    DESCRIPTION = (
        "Detects governance systems with low fixed quorum thresholds, "
        "manipulable quorum calculations, or missing quorum checks that "
        "allow proposals to pass with minority support."
    )
    SCWE_ID = "SCWE-039"
    CWE_ID = "CWE-284"
    SEVERITY = Severity.HIGH
    CATEGORY = "governance"

    def detect(self, context: DetectorContext) -> list[FindingSchema]:
        findings: list[FindingSchema] = []
        source = context.source_code
        lines = source.split("\n")

        is_governance = bool(re.search(
            r'function\s+(propose|castVote|execute|quorum)\s*\(', source
        ))
        if not is_governance:
            return findings

        # 1. No quorum check
        has_quorum = bool(re.search(r'quorum|QUORUM', source))
        has_execute = bool(re.search(r'function\s+execute\s*\(', source))
        if has_execute and not has_quorum:
            for match in re.finditer(r'function\s+execute\s*\(', source):
                line_no = source[:match.start()].count("\n")
                snippet = "\n".join(lines[line_no:min(len(lines), line_no + 5)])
                findings.append(self._make_finding(
                    title="Missing quorum check in governance execution",
                    description=(
                        "The governance execute function has no quorum requirement. "
                        "A single voter could pass and execute proposals."
                    ),
                    file_path=context.contract_name or "Contract.sol",
                    start_line=line_no + 1,
                    end_line=line_no + 5,
                    snippet=snippet,
                    remediation=(
                        "Add a quorum check:\n"
                        "```solidity\n"
                        "require(\n"
                        "    proposal.forVotes >= quorum(proposal.startBlock),\n"
                        "    \"Quorum not reached\"\n"
                        ");\n```"
                    ),
                ))

        # 2. Fixed quorum (doesn't scale with supply)
        for match in re.finditer(
            r'(?:quorum|QUORUM)\s*=\s*(\d+)',
            source,
        ):
            line_no = source[:match.start()].count("\n")
            snippet = "\n".join(
                lines[max(0, line_no - 1):min(len(lines), line_no + 2)]
            )
            findings.append(self._make_finding(
                title="Fixed quorum threshold",
                description=(
                    f"Quorum is set to a fixed value (line {line_no + 1}) rather "
                    "than a percentage of total supply. As more tokens are minted "
                    "or burned, the quorum becomes easier or harder to reach, "
                    "potentially allowing governance capture with a small percentage."
                ),
                file_path=context.contract_name or "Contract.sol",
                start_line=line_no + 1,
                end_line=line_no + 1,
                snippet=snippet,
                severity=Severity.MEDIUM,
                remediation=(
                    "Use a percentage-based quorum that scales with total supply:\n"
                    "```solidity\n"
                    "function quorum(uint256 blockNumber) public view returns (uint256) {\n"
                    "    return token.getPastTotalSupply(blockNumber) * quorumNumerator / quorumDenominator;\n"
                    "}\n```"
                ),
            ))

        return findings


class ProposalThresholdDetector(BaseDetector):
    """Detect manipulable or missing proposal thresholds."""

    DETECTOR_ID = "SCWE-039-004"
    NAME = "Proposal Threshold Vulnerability"
    DESCRIPTION = (
        "Detects governance proposal thresholds that are missing, too low, "
        "or can be bypassed to spam the governance system."
    )
    SCWE_ID = "SCWE-039"
    CWE_ID = "CWE-770"
    SEVERITY = Severity.MEDIUM
    CATEGORY = "governance"

    def detect(self, context: DetectorContext) -> list[FindingSchema]:
        findings: list[FindingSchema] = []
        source = context.source_code
        lines = source.split("\n")

        has_propose = bool(re.search(r'function\s+propose\s*\(', source))
        if not has_propose:
            return findings

        # Check for proposal threshold
        has_threshold = bool(re.search(
            r'proposalThreshold|PROPOSAL_THRESHOLD|proposerThreshold',
            source,
        ))

        if not has_threshold:
            for match in re.finditer(r'function\s+propose\s*\(', source):
                line_no = source[:match.start()].count("\n")
                snippet = "\n".join(lines[line_no:min(len(lines), line_no + 5)])
                findings.append(self._make_finding(
                    title="Missing proposal threshold",
                    description=(
                        "The propose() function has no minimum token threshold "
                        "requirement. Anyone can spam the governance with proposals, "
                        "potentially causing voter fatigue or governance DoS."
                    ),
                    file_path=context.contract_name or "Contract.sol",
                    start_line=line_no + 1,
                    end_line=line_no + 5,
                    snippet=snippet,
                    remediation=(
                        "Add a proposal threshold:\n"
                        "```solidity\n"
                        "require(\n"
                        "    getVotes(msg.sender, block.number - 1) >= proposalThreshold(),\n"
                        "    \"Below proposal threshold\"\n"
                        ");\n```"
                    ),
                ))

        return findings
