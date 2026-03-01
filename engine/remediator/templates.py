"""Remediation templates for common smart contract vulnerability patterns.

Each template maps a vulnerability category to a structured fix strategy
with before/after patterns, gas impact estimates, and confidence scores.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class FixStrategy(str, Enum):
    """How the fix should be applied."""

    PATTERN_REPLACE = "pattern_replace"
    INSERT_BEFORE = "insert_before"
    INSERT_AFTER = "insert_after"
    WRAP_BLOCK = "wrap_block"
    ADD_MODIFIER = "add_modifier"
    ADD_IMPORT = "add_import"
    RESTRUCTURE = "restructure"


@dataclass(frozen=True)
class RemediationTemplate:
    """A single remediation template for a vulnerability pattern."""

    id: str
    category: str
    title: str
    description: str
    strategy: FixStrategy
    severity_range: tuple[str, ...] = ("critical", "high", "medium")
    pattern: str = ""           # regex or AST pattern to match
    fix_template: str = ""      # Solidity code template with {{placeholders}}
    gas_impact: int = 0         # estimated gas change (+/-)
    confidence: float = 0.9
    requires_review: bool = False
    references: list[str] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)


# ─────────────────────────────────────────────────────────────────────────────
# Built-in remediation templates
# ─────────────────────────────────────────────────────────────────────────────

TEMPLATES: list[RemediationTemplate] = [
    # ── Reentrancy ───────────────────────────────────────────────────────
    RemediationTemplate(
        id="REEN-001",
        category="reentrancy",
        title="Checks-Effects-Interactions Pattern",
        description=(
            "Move state updates before external calls to prevent reentrancy. "
            "The Checks-Effects-Interactions pattern ensures all state changes "
            "happen before any external call is made."
        ),
        strategy=FixStrategy.RESTRUCTURE,
        pattern=r"(\w+)\.call\{value:\s*(\w+)\}",
        fix_template="""\
// Checks
require({{balance_var}}[msg.sender] >= {{amount_var}}, "Insufficient balance");

// Effects
{{balance_var}}[msg.sender] -= {{amount_var}};

// Interactions
(bool success, ) = {{recipient}}.call{value: {{amount_var}}}("");
require(success, "Transfer failed");
""",
        gas_impact=0,
        confidence=0.95,
        references=["SWC-107", "CWE-841"],
        tags=["reentrancy", "cei", "state-update"],
    ),
    RemediationTemplate(
        id="REEN-002",
        category="reentrancy",
        title="ReentrancyGuard Modifier",
        description="Add OpenZeppelin's ReentrancyGuard to functions with external calls.",
        strategy=FixStrategy.ADD_MODIFIER,
        pattern=r"function\s+\w+.*external.*\{",
        fix_template="""\
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";

// Add to contract inheritance:
// contract {{contract_name}} is ReentrancyGuard { ... }

// Add nonReentrant modifier to the function:
function {{function_name}}({{params}}) external nonReentrant {
""",
        gas_impact=2500,
        confidence=0.98,
        references=["SWC-107"],
        tags=["reentrancy", "openzeppelin", "modifier"],
    ),

    # ── Access Control ───────────────────────────────────────────────────
    RemediationTemplate(
        id="AC-001",
        category="access-control",
        title="Add Ownable Access Control",
        description="Restrict sensitive functions to contract owner using Ownable.",
        strategy=FixStrategy.ADD_MODIFIER,
        fix_template="""\
import "@openzeppelin/contracts/access/Ownable.sol";

function {{function_name}}({{params}}) external onlyOwner {
""",
        gas_impact=2300,
        confidence=0.92,
        references=["SWC-105", "CWE-284"],
        tags=["access-control", "ownable"],
    ),
    RemediationTemplate(
        id="AC-002",
        category="access-control",
        title="Role-Based Access Control",
        description="Use AccessControl for fine-grained role management.",
        strategy=FixStrategy.ADD_IMPORT,
        fix_template="""\
import "@openzeppelin/contracts/access/AccessControl.sol";

bytes32 public constant ADMIN_ROLE = keccak256("ADMIN_ROLE");

function {{function_name}}({{params}}) external onlyRole(ADMIN_ROLE) {
""",
        gas_impact=5000,
        confidence=0.90,
        references=["SWC-105"],
        tags=["access-control", "rbac"],
    ),

    # ── Integer Overflow/Underflow ───────────────────────────────────────
    RemediationTemplate(
        id="INT-001",
        category="integer-overflow",
        title="Use SafeMath or Solidity >=0.8.0 Checked Arithmetic",
        description=(
            "Replace unchecked arithmetic with checked operations. "
            "Solidity >=0.8.0 has built-in overflow checks; for older versions, use SafeMath."
        ),
        strategy=FixStrategy.PATTERN_REPLACE,
        pattern=r"unchecked\s*\{",
        fix_template="""\
// Remove unchecked block for safety, or explicitly document:
// unchecked { ... } — overflow verified impossible by invariant
{{checked_expression}}
""",
        gas_impact=-200,
        confidence=0.85,
        references=["SWC-101", "CWE-190"],
        tags=["integer", "overflow", "safemath"],
    ),

    # ── Uninitialized Storage ────────────────────────────────────────────
    RemediationTemplate(
        id="STOR-001",
        category="uninitialized-storage",
        title="Initialize Storage Variables",
        description="Declare storage variables with explicit initial values.",
        strategy=FixStrategy.PATTERN_REPLACE,
        fix_template="{{type}} {{var_name}} = {{default_value}};",
        gas_impact=0,
        confidence=0.88,
        references=["SWC-109"],
        tags=["storage", "initialization"],
    ),

    # ── Delegatecall Injection ───────────────────────────────────────────
    RemediationTemplate(
        id="DC-001",
        category="delegatecall",
        title="Restrict Delegatecall Targets",
        description="Validate delegatecall targets against an allowlist.",
        strategy=FixStrategy.INSERT_BEFORE,
        fix_template="""\
require(allowedTargets[{{target}}], "Unauthorized delegatecall target");
""",
        gas_impact=2100,
        confidence=0.90,
        references=["SWC-112", "CWE-829"],
        tags=["delegatecall", "proxy"],
    ),

    # ── ZK Proof Replay (Soul Protocol) ──────────────────────────────────
    RemediationTemplate(
        id="SOUL-ZK-001",
        category="zk-vulnerability",
        title="Add Chain-Specific Nonce to ZK Proofs",
        description=(
            "Bind ZK proofs to specific chain IDs and nonces to prevent "
            "cross-chain replay attacks in Soul Protocol ZK-SLock contracts."
        ),
        strategy=FixStrategy.INSERT_BEFORE,
        pattern=r"verifyProof|zkVerify",
        fix_template="""\
bytes32 proofId = keccak256(abi.encodePacked(
    proof,
    block.chainid,
    nonces[msg.sender]++
));
require(!usedProofIds[proofId], "Proof already used on this chain");
usedProofIds[proofId] = true;
""",
        gas_impact=5200,
        confidence=0.93,
        references=["SCWE-050"],
        tags=["soul", "zk", "replay", "cross-chain"],
    ),

    # ── Privacy Leak (Soul PC3) ──────────────────────────────────────────
    RemediationTemplate(
        id="SOUL-PC3-001",
        category="privacy",
        title="Add Timing Obfuscation to Cross-Chain Messages",
        description=(
            "Introduce random delay and batch processing for cross-chain "
            "messages to prevent timing-based identity correlation."
        ),
        strategy=FixStrategy.WRAP_BLOCK,
        pattern=r"sendCrossChain|relayMessage",
        fix_template="""\
// Queue message with random delay for batch processing
uint256 delay = uint256(keccak256(abi.encodePacked(block.timestamp, msg.sender))) % MAX_DELAY;
messageQueue.push(PendingMessage({
    message: {{message_var}},
    executeAfter: block.timestamp + delay
}));
emit MessageQueued(messageId, block.timestamp + delay);
""",
        gas_impact=8000,
        confidence=0.80,
        requires_review=True,
        references=["SOUL-PRIVACY-001"],
        tags=["soul", "pc3", "privacy", "timing"],
    ),

    # ── EASC Unbounded Loop ──────────────────────────────────────────────
    RemediationTemplate(
        id="SOUL-EASC-001",
        category="gas-efficiency",
        title="Add Iteration Cap to Adaptive Loops",
        description="Bound adaptive computation loops to prevent out-of-gas conditions.",
        strategy=FixStrategy.INSERT_BEFORE,
        pattern=r"while\s*\(\s*adaptiveCondition",
        fix_template="""\
uint256 iterationCount = 0;
uint256 constant MAX_ITERATIONS = {{max_iterations}};

// In the loop body, add:
require(iterationCount++ < MAX_ITERATIONS, "Iteration limit reached");
""",
        gas_impact=200,
        confidence=0.95,
        references=["SWC-128"],
        tags=["soul", "easc", "gas", "loop"],
    ),

    # ── PBP Missing Events ──────────────────────────────────────────────
    RemediationTemplate(
        id="SOUL-PBP-001",
        category="best-practice",
        title="Emit Events for Privacy Budget Updates",
        description="Add event emissions for all PBP state changes for off-chain tracking.",
        strategy=FixStrategy.INSERT_AFTER,
        pattern=r"updateBudget|setBudget|modifyBudget",
        fix_template="""\
event BudgetUpdated(address indexed user, uint256 oldBudget, uint256 newBudget, uint256 timestamp);

// After state update:
emit BudgetUpdated(msg.sender, oldBudget, newBudget, block.timestamp);
""",
        gas_impact=1500,
        confidence=0.98,
        references=["SWC-135"],
        tags=["soul", "pbp", "events", "best-practice"],
    ),

    # ── CDNA Commitment Ordering ─────────────────────────────────────────
    RemediationTemplate(
        id="SOUL-CDNA-001",
        category="logic-error",
        title="Enforce Strict Commitment Ordering",
        description=(
            "Add sequence numbers to CDNA commitments to prevent "
            "out-of-order processing in the DNA aggregation chain."
        ),
        strategy=FixStrategy.INSERT_BEFORE,
        pattern=r"processCommitment|aggregateData",
        fix_template="""\
require(
    commitment.sequenceNumber == lastProcessedSequence + 1,
    "Out-of-order commitment"
);
lastProcessedSequence = commitment.sequenceNumber;
""",
        gas_impact=2100,
        confidence=0.88,
        references=["SOUL-CDNA-ORD-001"],
        tags=["soul", "cdna", "ordering", "commitment"],
    ),

    # ── Flash Loan Protection ────────────────────────────────────────────
    RemediationTemplate(
        id="FL-001",
        category="flash-loan",
        title="Add Flash Loan Guard",
        description="Prevent same-block manipulation by requiring multi-block settlement.",
        strategy=FixStrategy.INSERT_BEFORE,
        fix_template="""\
require(block.number > lastActionBlock[msg.sender], "Same-block action not allowed");
lastActionBlock[msg.sender] = block.number;
""",
        gas_impact=5000,
        confidence=0.87,
        references=["SWC-136"],
        tags=["flash-loan", "oracle", "manipulation"],
    ),

    # ── Frontrunning Protection ──────────────────────────────────────────
    RemediationTemplate(
        id="FR-001",
        category="frontrunning",
        title="Commit-Reveal Scheme",
        description="Use commit-reveal pattern to prevent front-running of sensitive transactions.",
        strategy=FixStrategy.RESTRUCTURE,
        fix_template="""\
// Phase 1: Commit
mapping(address => bytes32) public commitments;

function commit(bytes32 hash) external {
    commitments[msg.sender] = hash;
}

// Phase 2: Reveal (after N blocks)
function reveal({{params}}) external {
    require(block.number >= commitBlock[msg.sender] + REVEAL_DELAY, "Too early");
    bytes32 expected = keccak256(abi.encodePacked({{params}}, msg.sender));
    require(commitments[msg.sender] == expected, "Invalid reveal");
    delete commitments[msg.sender];
    // ... original logic
}
""",
        gas_impact=25000,
        confidence=0.82,
        requires_review=True,
        references=["SWC-114"],
        tags=["frontrunning", "commit-reveal", "mev"],
    ),
]


# ── Template Registry ────────────────────────────────────────────────────────


def get_template(template_id: str) -> RemediationTemplate | None:
    """Look up a template by ID."""
    for t in TEMPLATES:
        if t.id == template_id:
            return t
    return None


def get_templates_for_category(category: str) -> list[RemediationTemplate]:
    """Return all templates matching a vulnerability category."""
    return [t for t in TEMPLATES if t.category == category]


def get_soul_templates() -> list[RemediationTemplate]:
    """Return all Soul Protocol–specific remediation templates."""
    return [t for t in TEMPLATES if any(tag.startswith("soul") for tag in t.tags)]


def get_high_confidence_templates(threshold: float = 0.9) -> list[RemediationTemplate]:
    """Return templates with confidence >= threshold."""
    return [t for t in TEMPLATES if t.confidence >= threshold]
