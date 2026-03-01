"""Finding diff view — compare findings between scan versions.

Provides an API to compute the delta between two scans' findings:
  - New findings (present in new scan but not in baseline)
  - Resolved findings (present in baseline but not in new scan)
  - Persistent findings (present in both)
  - Regressions (previously resolved, now re-introduced)

Finding matching uses a composite key: (detector_id, location hash, title hash)
to handle minor description/line changes across scan versions.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, Field

router = APIRouter()


# ── Data Models ──────────────────────────────────────────────────────────────


class DiffStatus(str, Enum):
    NEW = "new"
    RESOLVED = "resolved"
    PERSISTENT = "persistent"
    REGRESSION = "regression"


@dataclass
class FindingFingerprint:
    """Unique identity of a finding across scan versions."""
    detector_id: str
    location_hash: str   # hash of file_path + approximate line range
    title_hash: str      # hash of title (normalized)
    severity: str

    @property
    def key(self) -> str:
        return f"{self.detector_id}:{self.location_hash}:{self.title_hash}"


@dataclass
class DiffEntry:
    """A single entry in the diff result."""
    status: DiffStatus
    finding: dict[str, Any]
    baseline_finding: dict[str, Any] | None = None
    changes: list[str] = field(default_factory=list)


@dataclass
class DiffResult:
    """Full diff between two scans."""
    baseline_scan_id: str
    target_scan_id: str
    new_findings: list[DiffEntry] = field(default_factory=list)
    resolved_findings: list[DiffEntry] = field(default_factory=list)
    persistent_findings: list[DiffEntry] = field(default_factory=list)
    regressions: list[DiffEntry] = field(default_factory=list)
    summary: dict[str, int] = field(default_factory=dict)


# ── Fingerprinting ───────────────────────────────────────────────────────────


def _fingerprint(finding: dict[str, Any]) -> FindingFingerprint:
    """Compute a stable fingerprint for a finding."""
    detector_id = finding.get("metadata", {}).get("detector_id", "")
    if not detector_id:
        detector_id = finding.get("category", "unknown")

    # Location hash: file path + approximate line (rounded to nearest 5)
    location = finding.get("location", {})
    file_path = location.get("file_path", "")
    start_line = location.get("start_line", 0)
    # Round line to reduce noise from minor shifts
    approx_line = (start_line // 5) * 5
    location_str = f"{file_path}:{approx_line}"
    location_hash = hashlib.sha256(location_str.encode()).hexdigest()[:12]

    # Title hash (normalize whitespace and case)
    title = finding.get("title", "").strip().lower()
    title = " ".join(title.split())
    title_hash = hashlib.sha256(title.encode()).hexdigest()[:12]

    severity = finding.get("severity", "medium")

    return FindingFingerprint(
        detector_id=detector_id,
        location_hash=location_hash,
        title_hash=title_hash,
        severity=severity,
    )


# ── Diff Engine ──────────────────────────────────────────────────────────────


def compute_diff(
    baseline_findings: list[dict[str, Any]],
    target_findings: list[dict[str, Any]],
    baseline_scan_id: str = "",
    target_scan_id: str = "",
    previously_resolved: set[str] | None = None,
) -> DiffResult:
    """Compute the diff between baseline and target findings.

    Args:
        baseline_findings: Findings from the older scan
        target_findings: Findings from the newer scan
        baseline_scan_id: ID of the baseline scan
        target_scan_id: ID of the target scan
        previously_resolved: Set of finding fingerprint keys that were
            resolved in earlier scans (for regression detection)

    Returns:
        DiffResult with categorized findings
    """
    previously_resolved = previously_resolved or set()

    # Fingerprint both sets
    baseline_map: dict[str, dict[str, Any]] = {}
    for f in baseline_findings:
        fp = _fingerprint(f)
        baseline_map[fp.key] = f

    target_map: dict[str, dict[str, Any]] = {}
    for f in target_findings:
        fp = _fingerprint(f)
        target_map[fp.key] = f

    result = DiffResult(
        baseline_scan_id=baseline_scan_id,
        target_scan_id=target_scan_id,
    )

    baseline_keys = set(baseline_map.keys())
    target_keys = set(target_map.keys())

    # New findings — in target but not in baseline
    for key in target_keys - baseline_keys:
        finding = target_map[key]
        status = DiffStatus.REGRESSION if key in previously_resolved else DiffStatus.NEW
        entry = DiffEntry(status=status, finding=finding)
        if status == DiffStatus.REGRESSION:
            result.regressions.append(entry)
        else:
            result.new_findings.append(entry)

    # Resolved findings — in baseline but not in target
    for key in baseline_keys - target_keys:
        result.resolved_findings.append(DiffEntry(
            status=DiffStatus.RESOLVED,
            finding=baseline_map[key],
        ))

    # Persistent findings — in both
    for key in baseline_keys & target_keys:
        changes = _compute_changes(baseline_map[key], target_map[key])
        result.persistent_findings.append(DiffEntry(
            status=DiffStatus.PERSISTENT,
            finding=target_map[key],
            baseline_finding=baseline_map[key],
            changes=changes,
        ))

    result.summary = {
        "new": len(result.new_findings),
        "resolved": len(result.resolved_findings),
        "persistent": len(result.persistent_findings),
        "regressions": len(result.regressions),
        "total_baseline": len(baseline_findings),
        "total_target": len(target_findings),
        "delta": len(target_findings) - len(baseline_findings),
    }

    return result


def _compute_changes(
    baseline: dict[str, Any], target: dict[str, Any]
) -> list[str]:
    """Detect meaningful changes between matched findings."""
    changes: list[str] = []

    if baseline.get("severity") != target.get("severity"):
        changes.append(
            f"Severity changed: {baseline.get('severity')} → {target.get('severity')}"
        )

    if baseline.get("confidence") != target.get("confidence"):
        changes.append(
            f"Confidence changed: {baseline.get('confidence')} → {target.get('confidence')}"
        )

    bl = baseline.get("location", {})
    tl = target.get("location", {})
    if bl.get("start_line") != tl.get("start_line"):
        changes.append(
            f"Line shifted: {bl.get('start_line')} → {tl.get('start_line')}"
        )

    if baseline.get("description") != target.get("description"):
        changes.append("Description updated")

    if baseline.get("remediation") != target.get("remediation"):
        changes.append("Remediation updated")

    return changes


# ── API Schemas ──────────────────────────────────────────────────────────────


class FindingDiffEntry(BaseModel):
    status: str
    finding: dict[str, Any]
    baseline_finding: dict[str, Any] | None = None
    changes: list[str] = Field(default_factory=list)


class FindingDiffResponse(BaseModel):
    baseline_scan_id: str
    target_scan_id: str
    new_findings: list[FindingDiffEntry]
    resolved_findings: list[FindingDiffEntry]
    persistent_findings: list[FindingDiffEntry]
    regressions: list[FindingDiffEntry]
    summary: dict[str, int]


# ── API Routes ───────────────────────────────────────────────────────────────


@router.get("/diff", response_model=FindingDiffResponse)
async def get_finding_diff(
    baseline_scan_id: str = Query(..., description="ID of the baseline (older) scan"),
    target_scan_id: str = Query(..., description="ID of the target (newer) scan"),
) -> FindingDiffResponse:
    """Compare findings between two scans and return categorized diff.

    Returns new, resolved, persistent, and regression findings.
    """
    # In production, fetch findings from database
    from engine.core.database import get_session
    from sqlalchemy import select

    try:
        async with get_session() as session:
            from engine.models.scan import Finding as FindingModel

            baseline_q = select(FindingModel).where(FindingModel.scan_id == baseline_scan_id)
            target_q = select(FindingModel).where(FindingModel.scan_id == target_scan_id)

            baseline_result = await session.execute(baseline_q)
            target_result = await session.execute(target_q)

            baseline_findings = [
                _model_to_dict(f) for f in baseline_result.scalars().all()
            ]
            target_findings = [
                _model_to_dict(f) for f in target_result.scalars().all()
            ]
    except Exception:
        # Fallback: return empty diff if DB is unavailable
        baseline_findings = []
        target_findings = []

    diff = compute_diff(
        baseline_findings,
        target_findings,
        baseline_scan_id=baseline_scan_id,
        target_scan_id=target_scan_id,
    )

    return FindingDiffResponse(
        baseline_scan_id=diff.baseline_scan_id,
        target_scan_id=diff.target_scan_id,
        new_findings=[_entry_to_schema(e) for e in diff.new_findings],
        resolved_findings=[_entry_to_schema(e) for e in diff.resolved_findings],
        persistent_findings=[_entry_to_schema(e) for e in diff.persistent_findings],
        regressions=[_entry_to_schema(e) for e in diff.regressions],
        summary=diff.summary,
    )


def _entry_to_schema(entry: DiffEntry) -> FindingDiffEntry:
    return FindingDiffEntry(
        status=entry.status.value,
        finding=entry.finding,
        baseline_finding=entry.baseline_finding,
        changes=entry.changes,
    )


def _model_to_dict(model: Any) -> dict[str, Any]:
    """Convert a SQLAlchemy model to a dict for diffing."""
    return {
        "title": getattr(model, "title", ""),
        "description": getattr(model, "description", ""),
        "severity": getattr(model, "severity", "medium"),
        "confidence": getattr(model, "confidence", 0.0),
        "category": getattr(model, "category", ""),
        "location": {
            "file_path": getattr(model, "file_path", ""),
            "start_line": getattr(model, "start_line", 0),
            "end_line": getattr(model, "end_line", 0),
        },
        "remediation": getattr(model, "remediation", ""),
        "metadata": getattr(model, "metadata_", {}) if hasattr(model, "metadata_") else {},
    }
