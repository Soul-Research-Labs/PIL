"""Denial-of-Service (DoS) vulnerability detectors.

Detects:
  - Unbounded loops over dynamic arrays (gas DoS)
  - Block gas limit DoS via push patterns
  - External call failures in loops (single point of failure)
  - Pull-over-push anti-pattern violations
  - Unexpected revert DoS (griefing)
"""

from __future__ import annotations

import re

from engine.analyzer.web3.base_detector import BaseDetector, DetectorContext
from engine.core.types import FindingSchema, Location, Severity


class UnboundedLoop(BaseDetector):
    """Detect loops iterating over unbounded dynamic arrays."""

    DETECTOR_ID = "dos-unbounded-loop"
    DETECTOR_NAME = "Unbounded Loop DoS"
    SEVERITY = Severity.HIGH
    CONFIDENCE = 0.85
    CATEGORY = "denial-of-service"

    # for (uint i = 0; i < array.length; i++)
    _LOOP_LENGTH_RE = re.compile(
        r"for\s*\([^;]+;\s*\w+\s*[<>=]+\s*(\w+)\.length\s*;",
    )
    _WHILE_LENGTH_RE = re.compile(
        r"while\s*\([^)]*(\w+)\.length",
    )

    def detect(self, context: DetectorContext) -> list[FindingSchema]:
        findings = []

        for i, line in enumerate(context.lines):
            match = self._LOOP_LENGTH_RE.search(line) or self._WHILE_LENGTH_RE.search(line)
            if match:
                array_name = match.group(1)

                # Check if array is state variable (likely unbounded)
                is_state = any(
                    re.search(rf"\b{re.escape(array_name)}\b.*\[\s*\]", l)
                    for l in context.lines[:50]  # Check declarations at top
                )

                if is_state or "." not in array_name:
                    # Check for gas-intensive operations inside the loop
                    loop_body = "\n".join(context.lines[i:min(i + 20, len(context.lines))])
                    has_transfer = "transfer" in loop_body or ".call{" in loop_body
                    has_sstore = re.search(r"\w+\s*\[", loop_body) and "=" in loop_body

                    severity = Severity.HIGH
                    if has_transfer:
                        severity = Severity.CRITICAL  # Transfer in unbounded loop = severe DoS

                    findings.append(self._make_finding(
                        title=f"Unbounded loop over {array_name}.length",
                        description=(
                            f"Loop iterates over the length of '{array_name}', which appears to be "
                            "a dynamically-sized storage array. If this array grows large enough, "
                            "the loop will exceed the block gas limit, making the function unusable. "
                            + ("ETH transfers inside the loop amplify the risk." if has_transfer else "")
                        ),
                        severity=severity,
                        location=Location(
                            file_path=context.contract_name or "contract",
                            start_line=i + 1,
                            end_line=i + 1,
                            snippet=line.strip(),
                        ),
                        remediation=(
                            "Use pagination (process in batches with start/end indices), "
                            "or use a mapping instead of array for O(1) access. "
                            "For ETH distribution, use pull-over-push pattern."
                        ),
                    ))

        return findings


class ExternalCallInLoop(BaseDetector):
    """Detect external calls inside loops — single failure DoS."""

    DETECTOR_ID = "dos-external-call-loop"
    DETECTOR_NAME = "External Call in Loop"
    SEVERITY = Severity.HIGH
    CONFIDENCE = 0.80
    CATEGORY = "denial-of-service"

    _LOOP_RE = re.compile(r"\b(for|while)\s*\(")
    _CALL_RE = re.compile(
        r"\.(call|transfer|send|delegatecall)\s*[\({]"
    )

    def detect(self, context: DetectorContext) -> list[FindingSchema]:
        findings = []
        in_loop = 0  # Track loop depth

        for i, line in enumerate(context.lines):
            # Track loop nesting
            if self._LOOP_RE.search(line):
                in_loop += 1
            if in_loop > 0:
                # Count braces
                in_loop += line.count("{") - line.count("}")
                if in_loop < 0:
                    in_loop = 0

            if in_loop > 0 and self._CALL_RE.search(line):
                findings.append(self._make_finding(
                    title="External call inside loop",
                    description=(
                        "An external call (transfer/call/send) is made inside a loop. "
                        "If any single call fails (e.g., a contract that reverts on receive), "
                        "the entire transaction reverts, blocking execution for all recipients. "
                        "This is a Denial-of-Service vulnerability."
                    ),
                    severity=Severity.HIGH,
                    location=Location(
                        file_path=context.contract_name or "contract",
                        start_line=i + 1,
                        end_line=i + 1,
                        snippet=line.strip(),
                    ),
                    remediation=(
                        "Use the pull-over-push pattern: let recipients withdraw funds "
                        "instead of pushing to them in a loop. Use a mapping to track "
                        "pending balances."
                    ),
                ))

        return findings


class UnexpectedRevertDoS(BaseDetector):
    """Detect patterns that allow griefing via unexpected reverts."""

    DETECTOR_ID = "dos-unexpected-revert"
    DETECTOR_NAME = "Unexpected Revert DoS"
    SEVERITY = Severity.MEDIUM
    CONFIDENCE = 0.70
    CATEGORY = "denial-of-service"

    # require(someAddress.call(...), "...")
    _REQUIRE_CALL_RE = re.compile(
        r"require\s*\(\s*\w+\.(call|transfer|send)",
    )
    # address(0) check missing before transfer
    _ZERO_ADDR_MISSING_RE = re.compile(
        r"(\w+)\.(transfer|call\{value:)",
    )

    def detect(self, context: DetectorContext) -> list[FindingSchema]:
        findings = []

        for i, line in enumerate(context.lines):
            if self._REQUIRE_CALL_RE.search(line):
                findings.append(self._make_finding(
                    title="Require wraps external call — griefing risk",
                    description=(
                        "An external call result is wrapped in require(). "
                        "If the callee contract can deliberately revert, it can "
                        "permanently block execution of this function (griefing)."
                    ),
                    location=Location(
                        file_path=context.contract_name or "contract",
                        start_line=i + 1,
                        end_line=i + 1,
                        snippet=line.strip(),
                    ),
                    remediation=(
                        "Use try/catch or check the return value without reverting. "
                        "Implement fallback logic for failed external calls."
                    ),
                ))

        return findings


class BlockStuffing(BaseDetector):
    """Detect auction/bidding patterns vulnerable to block stuffing."""

    DETECTOR_ID = "dos-block-stuffing"
    DETECTOR_NAME = "Block Stuffing Vulnerability"
    SEVERITY = Severity.MEDIUM
    CONFIDENCE = 0.65
    CATEGORY = "denial-of-service"

    _AUCTION_END_RE = re.compile(
        r"block\.timestamp\s*>=?\s*\w*(end|deadline|expiry|close)\w*",
        re.IGNORECASE,
    )
    _HIGHEST_BID_RE = re.compile(
        r"highest|winner|leading|top\s*bid",
        re.IGNORECASE,
    )

    def detect(self, context: DetectorContext) -> list[FindingSchema]:
        findings = []
        src = context.source_code

        has_auction_end = bool(self._AUCTION_END_RE.search(src))
        has_highest = bool(self._HIGHEST_BID_RE.search(src))

        if has_auction_end and has_highest:
            for i, line in enumerate(context.lines):
                if self._AUCTION_END_RE.search(line):
                    findings.append(self._make_finding(
                        title="Auction vulnerable to block stuffing",
                        description=(
                            "This contract appears to implement an auction with a timestamp-based "
                            "deadline. A well-funded attacker could fill blocks with high-gas "
                            "transactions to prevent competing bids near the deadline (block stuffing)."
                        ),
                        severity=Severity.MEDIUM,
                        location=Location(
                            file_path=context.contract_name or "contract",
                            start_line=i + 1,
                            end_line=i + 1,
                            snippet=line.strip(),
                        ),
                        remediation=(
                            "Implement bid extension: reset the deadline when a new bid arrives "
                            "near the end. Use commit-reveal scheme for sealed-bid auctions."
                        ),
                    ))
                    break

        return findings
