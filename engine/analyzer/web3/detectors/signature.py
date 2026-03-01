"""Signature and cryptography vulnerability detectors."""

from __future__ import annotations

import re

from engine.analyzer.web3.base_detector import BaseDetector, DetectorContext
from engine.core.types import FindingSchema, Severity


class MissingNonceDetector(BaseDetector):
    """Detect signature schemes without nonce — replay attack risk."""

    DETECTOR_ID = "SCWE-054-001"
    NAME = "Missing Signature Nonce"
    DESCRIPTION = "Signature verification without nonce allows replay attacks"
    SCWE_ID = "SCWE-054"
    CWE_ID = "CWE-294"
    SEVERITY = Severity.HIGH
    CATEGORY = "signature"

    def detect(self, context: DetectorContext) -> list[FindingSchema]:
        findings: list[FindingSchema] = []
        source = context.source_code
        lines = source.split("\n")

        # Look for ecrecover / ECDSA.recover usage
        has_signature_verification = "ecrecover" in source or "ECDSA.recover" in source
        has_nonce = "nonce" in source.lower()

        if has_signature_verification and not has_nonce:
            for i, line in enumerate(lines, 1):
                if "ecrecover" in line or "ECDSA.recover" in line:
                    findings.append(self._make_finding(
                        title="Signature verification without nonce — replay attack possible",
                        description=(
                            "The contract verifies signatures but does not include a nonce in the "
                            "signed message. An attacker can replay a valid signature multiple times."
                        ),
                        file_path=context.contract_name or "Contract.sol",
                        start_line=i,
                        end_line=i,
                        snippet=line.strip(),
                        remediation="Include an incrementing nonce in the signed message hash and verify it on-chain.",
                    ))
                    break
        return findings


class MissingChainIdDetector(BaseDetector):
    """Detect signatures without chain ID — cross-chain replay risk."""

    DETECTOR_ID = "SCWE-055-001"
    NAME = "Missing Chain ID in Signature"
    DESCRIPTION = "Signature does not include chain ID, vulnerable to cross-chain replay"
    SCWE_ID = "SCWE-055"
    CWE_ID = "CWE-294"
    SEVERITY = Severity.MEDIUM
    CATEGORY = "signature"

    def detect(self, context: DetectorContext) -> list[FindingSchema]:
        findings: list[FindingSchema] = []
        source = context.source_code
        lines = source.split("\n")

        has_sig = "ecrecover" in source or "ECDSA.recover" in source
        uses_eip712 = "DOMAIN_SEPARATOR" in source or "EIP712" in source
        has_chain_id = "block.chainid" in source or "chainId" in source or "chain_id" in source

        if has_sig and not uses_eip712 and not has_chain_id:
            for i, line in enumerate(lines, 1):
                if "ecrecover" in line or "ECDSA.recover" in line:
                    findings.append(self._make_finding(
                        title="Signature missing chain ID — cross-chain replay possible",
                        description=(
                            "Signed messages do not include block.chainid or use EIP-712 domain separator. "
                            "Signatures can be replayed on other chains or forks."
                        ),
                        file_path=context.contract_name or "Contract.sol",
                        start_line=i,
                        end_line=i,
                        snippet=line.strip(),
                        remediation="Use EIP-712 typed data signing with a domain separator that includes block.chainid.",
                    ))
                    break
        return findings


class ECRecoverMalleabilityDetector(BaseDetector):
    """Detect ecrecover signature malleability."""

    DETECTOR_ID = "SCWE-056-001"
    NAME = "ECDSA Signature Malleability"
    DESCRIPTION = "ecrecover without s-value check allows signature malleability"
    SCWE_ID = "SCWE-056"
    CWE_ID = "CWE-347"
    SEVERITY = Severity.HIGH
    CATEGORY = "signature"

    def detect(self, context: DetectorContext) -> list[FindingSchema]:
        findings: list[FindingSchema] = []
        source = context.source_code
        lines = source.split("\n")

        # Only flag raw ecrecover, not OpenZeppelin ECDSA (which handles it)
        if "ecrecover(" in source and "ECDSA" not in source:
            has_s_check = re.search(
                r"require\s*\(\s*uint256\s*\(\s*s\s*\)\s*<=",
                source
            ) is not None or "0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0" in source

            if not has_s_check:
                for i, line in enumerate(lines, 1):
                    if "ecrecover(" in line:
                        findings.append(self._make_finding(
                            title="ecrecover without signature malleability protection",
                            description=(
                                "Raw `ecrecover` is used without checking that `s` is in the lower half of the curve. "
                                "An attacker can create a second valid signature for the same message, "
                                "potentially replaying actions."
                            ),
                            file_path=context.contract_name or "Contract.sol",
                            start_line=i,
                            end_line=i,
                            snippet=line.strip(),
                            remediation="Use OpenZeppelin's ECDSA library which includes the s-value check, or add: `require(uint256(s) <= 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0);`",
                        ))
                        break
        return findings


class ECRecoverZeroAddressDetector(BaseDetector):
    """Detect missing zero-address check on ecrecover result."""

    DETECTOR_ID = "SCWE-019-001"
    NAME = "ecrecover Zero Address Check"
    DESCRIPTION = "ecrecover result not checked for address(0)"
    SCWE_ID = "SCWE-019"
    CWE_ID = "CWE-347"
    SEVERITY = Severity.HIGH
    CATEGORY = "signature"

    def detect(self, context: DetectorContext) -> list[FindingSchema]:
        findings: list[FindingSchema] = []
        source = context.source_code
        lines = source.split("\n")

        for i, line in enumerate(lines, 1):
            if "ecrecover(" in line:
                # Find variable assigned
                match = re.search(r"(\w+)\s*=\s*ecrecover", line)
                if match:
                    var_name = match.group(1)
                    # Check surrounding lines for zero address check
                    context_lines = "\n".join(lines[max(0, i - 1):min(len(lines), i + 5)])
                    if f"{var_name} != address(0)" not in context_lines and f"{var_name} == address(0)" not in context_lines:
                        findings.append(self._make_finding(
                            title="ecrecover result not checked for address(0)",
                            description=(
                                f"`ecrecover` can return `address(0)` for invalid signatures. "
                                f"Without checking, an attacker with an invalid signature could "
                                f"impersonate `address(0)` or bypass authorization."
                            ),
                            file_path=context.contract_name or "Contract.sol",
                            start_line=i,
                            end_line=i,
                            snippet=line.strip(),
                            remediation=f"Add: `require({var_name} != address(0), \"Invalid signature\");`",
                        ))
        return findings
