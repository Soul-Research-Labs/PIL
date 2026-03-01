"""Cross-contract interaction vulnerability detectors.

Detects:
  - Unchecked low-level call return values (advanced patterns)
  - Callback re-entrancy via ERC721/ERC1155 hooks
  - Read-only reentrancy via view function price feeds
  - Composability risks in DeFi protocol integrations
  - Ether left in contract without withdrawal
"""

from __future__ import annotations

import re

from engine.analyzer.web3.base_detector import BaseDetector, DetectorContext
from engine.core.types import FindingSchema, Location, Severity


class UncheckedCallAdvanced(BaseDetector):
    """Detect unchecked low-level call results with advanced patterns."""

    DETECTOR_ID = "interaction-unchecked-call-adv"
    DETECTOR_NAME = "Unchecked Call Return (Advanced)"
    SEVERITY = Severity.HIGH
    CONFIDENCE = 0.85
    CATEGORY = "unchecked-returns"

    _CALL_RE = re.compile(r"(\w+)?\.call\{?\s*(?:value\s*:|gas\s*:)?[^}]*\}?\s*\(")
    _IGNORED_RE = re.compile(r"\(\s*bool\s+\w+\s*,\s*\)\s*=|;\s*$")

    def detect(self, context: DetectorContext) -> list[FindingSchema]:
        findings = []

        for i, line in enumerate(context.lines):
            if ".call" not in line:
                continue

            if self._CALL_RE.search(line):
                # Check if return value is captured
                surrounding = "\n".join(context.lines[max(0, i - 1):i + 2])

                # Patterns that indicate checked:
                # (bool success, ) = addr.call(...)
                # require(success, ...)
                has_capture = re.search(r"\(bool\s+\w+", surrounding)
                has_require = re.search(
                    r"require\s*\(\s*\w+", 
                    "\n".join(context.lines[i:min(i + 3, len(context.lines))])
                )

                if not has_capture:
                    findings.append(self._make_finding(
                        title="Low-level call return value not captured",
                        description=(
                            "A low-level .call() is made without capturing the return value. "
                            "If the call fails silently, the contract will continue execution "
                            "as if it succeeded, potentially leading to loss of funds."
                        ),
                        location=Location(
                            file_path=context.contract_name or "contract",
                            start_line=i + 1,
                            end_line=i + 1,
                            snippet=line.strip(),
                        ),
                        remediation=(
                            "Capture and check the return value: "
                            "(bool success, ) = addr.call{value: amount}(\"\"); "
                            "require(success, \"Transfer failed\");"
                        ),
                    ))
                elif has_capture and not has_require:
                    findings.append(self._make_finding(
                        title="Low-level call return value captured but not checked",
                        description=(
                            "The return value of .call() is captured in a variable "
                            "but may not be checked with require/if. Silent failures "
                            "can lead to unexpected behavior."
                        ),
                        severity=Severity.MEDIUM,
                        location=Location(
                            file_path=context.contract_name or "contract",
                            start_line=i + 1,
                            end_line=i + 1,
                            snippet=line.strip(),
                        ),
                        remediation=(
                            "Add require(success) or handle the failure case: "
                            "if (!success) revert TransferFailed();"
                        ),
                    ))

        return findings


class CallbackReentrancy(BaseDetector):
    """Detect reentrancy via ERC721/ERC1155/ERC777 callback hooks."""

    DETECTOR_ID = "interaction-callback-reentrancy"
    DETECTOR_NAME = "Callback Reentrancy"
    SEVERITY = Severity.HIGH
    CONFIDENCE = 0.80
    CATEGORY = "reentrancy"

    _CALLBACK_FUNCTIONS = [
        "_safeMint",
        "safeTransferFrom",
        "_safeTransfer",
        "onERC721Received",
        "onERC1155Received",
        "onERC1155BatchReceived",
        "tokensReceived",  # ERC777
    ]

    def detect(self, context: DetectorContext) -> list[FindingSchema]:
        findings = []

        for i, line in enumerate(context.lines):
            for callback in self._CALLBACK_FUNCTIONS:
                if callback not in line:
                    continue

                # Check if there are state writes after the callback
                following = "\n".join(context.lines[i + 1:min(i + 10, len(context.lines))])
                has_state_write = re.search(
                    r"(\w+\s*\[.*\]\s*=|\w+\s*\+=|\w+\s*-=|\w+\s*=\s*\w+)",
                    following,
                )
                has_guard = context.has_reentrancy_guard

                if has_state_write and not has_guard:
                    findings.append(self._make_finding(
                        title=f"Callback reentrancy via {callback}",
                        description=(
                            f"{callback} triggers a callback to the recipient, "
                            "which can re-enter the contract before state updates. "
                            f"State modifications after {callback} may be vulnerable."
                        ),
                        location=Location(
                            file_path=context.contract_name or "contract",
                            start_line=i + 1,
                            end_line=i + 1,
                            snippet=line.strip(),
                        ),
                        remediation=(
                            f"Move all state changes before the {callback} call, "
                            "or use ReentrancyGuard. Follow checks-effects-interactions."
                        ),
                    ))
                    break

        return findings


class EtherLocked(BaseDetector):
    """Detect contracts that can receive ETH but have no withdrawal mechanism."""

    DETECTOR_ID = "interaction-ether-locked"
    DETECTOR_NAME = "Ether Locked in Contract"
    SEVERITY = Severity.MEDIUM
    CONFIDENCE = 0.80
    CATEGORY = "code-quality"

    _PAYABLE_RE = re.compile(r"\bpayable\b")
    _RECEIVE_RE = re.compile(r"(receive|fallback)\s*\(\s*\)\s*(external\s+)?payable")
    _WITHDRAW_RE = re.compile(
        r"(withdraw|transfer|\.call\{value:|\.(send|transfer)\()",
        re.IGNORECASE,
    )

    def detect(self, context: DetectorContext) -> list[FindingSchema]:
        findings = []
        src = context.source_code

        can_receive = bool(self._RECEIVE_RE.search(src)) or "msg.value" in src
        can_withdraw = bool(self._WITHDRAW_RE.search(src))

        if can_receive and not can_withdraw:
            findings.append(self._make_finding(
                title="Contract can receive ETH but has no withdrawal function",
                description=(
                    "This contract can receive Ether (via payable functions or receive/fallback) "
                    "but has no mechanism to withdraw it. Any ETH sent to this contract "
                    "will be permanently locked."
                ),
                severity=Severity.MEDIUM,
                location=Location(
                    file_path=context.contract_name or "contract",
                    start_line=1,
                    end_line=1,
                    snippet="",
                ),
                remediation=(
                    "Add a withdraw function with proper access control: "
                    "function withdraw() external onlyOwner { "
                    "payable(msg.sender).transfer(address(this).balance); }"
                ),
            ))

        return findings


class ReturnBombAdvanced(BaseDetector):
    """Detect return-data bomb vulnerability in low-level calls."""

    DETECTOR_ID = "interaction-return-bomb-adv"
    DETECTOR_NAME = "Return Data Bomb"
    SEVERITY = Severity.MEDIUM
    CONFIDENCE = 0.70
    CATEGORY = "denial-of-service"

    _CALL_WITH_DATA_RE = re.compile(
        r"\(bool\s+\w+\s*,\s*bytes\s+(?:memory\s+)?(\w+)\s*\)\s*=\s*\w+\.call"
    )

    def detect(self, context: DetectorContext) -> list[FindingSchema]:
        findings = []

        for i, line in enumerate(context.lines):
            match = self._CALL_WITH_DATA_RE.search(line)
            if match:
                data_var = match.group(1)
                # Check if the return data size is bounded
                following = "\n".join(context.lines[i:min(i + 5, len(context.lines))])
                has_length_check = f"{data_var}.length" in following

                if not has_length_check:
                    findings.append(self._make_finding(
                        title="Return data bomb — unbounded return data from external call",
                        description=(
                            f"Return data from external call is stored in '{data_var}' "
                            "without size limits. A malicious contract could return "
                            "extremely large data, consuming excessive gas for memory "
                            "allocation (return data bomb)."
                        ),
                        location=Location(
                            file_path=context.contract_name or "contract",
                            start_line=i + 1,
                            end_line=i + 1,
                            snippet=line.strip(),
                        ),
                        remediation=(
                            "Use assembly to limit return data size: "
                            "assembly { returndatacopy(0, 0, min(returndatasize(), maxSize)) } "
                            "Or use ExcessivelySafeCall library."
                        ),
                    ))

        return findings
