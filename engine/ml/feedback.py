"""Feedback loop — collect human corrections, learn from them,
and refine LLM prompts automatically.

Three subsystems:
    1. CorrectionStore    — persist analyst corrections to findings
    2. PatternAnalyser    — detect systematic error patterns in corrections
    3. PromptOptimiser    — rewrite / augment LLM system prompts from patterns
    4. FeedbackLoop       — orchestrates the cycle: collect → analyse → optimise
"""

from __future__ import annotations

import hashlib
import json
import logging
import re
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any

logger = logging.getLogger(__name__)


# ── Types ────────────────────────────────────────────────────────────────────


class CorrectionType(str, Enum):
    """Kind of analyst correction."""
    SEVERITY_CHANGE = "severity_change"
    FALSE_POSITIVE = "false_positive"
    FALSE_NEGATIVE = "false_negative"
    CATEGORY_CHANGE = "category_change"
    DESCRIPTION_EDIT = "description_edit"
    REMEDIATION_EDIT = "remediation_edit"
    TITLE_EDIT = "title_edit"


@dataclass
class Correction:
    """A single analyst correction record."""
    finding_id: str
    correction_type: CorrectionType
    original_value: str
    corrected_value: str
    analyst_id: str = ""
    reason: str = ""
    detector_id: str = ""
    category: str = ""
    source_snippet: str = ""
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    @property
    def fingerprint(self) -> str:
        """A content-hash for deduplication."""
        payload = f"{self.finding_id}:{self.correction_type}:{self.corrected_value}"
        return hashlib.sha256(payload.encode()).hexdigest()[:12]


@dataclass
class ErrorPattern:
    """A recurring error pattern extracted from corrections."""
    pattern_id: str
    correction_type: CorrectionType
    description: str
    frequency: int
    examples: list[dict[str, str]] = field(default_factory=list)
    detector_ids: list[str] = field(default_factory=list)
    suggested_prompt_patch: str = ""


@dataclass
class PromptPatch:
    """A proposed improvement to an LLM prompt."""
    prompt_name: str          # e.g., "analysis_system", "remediation"
    section: str              # e.g., "severity_guidelines"
    original_text: str
    patched_text: str
    rationale: str
    improvement_estimate: float  # 0–1
    applied: bool = False


# ── Correction store ─────────────────────────────────────────────────────────


class CorrectionStore:
    """In-memory store for analyst corrections.

    In production this is backed by the AuditLog + a dedicated table;
    this implementation provides the interface and in-memory fallback.
    """

    def __init__(self) -> None:
        self._corrections: list[Correction] = []
        self._seen: set[str] = set()

    def record(self, correction: Correction) -> bool:
        """Record a correction. Returns False if duplicate."""
        fp = correction.fingerprint
        if fp in self._seen:
            return False
        self._seen.add(fp)
        self._corrections.append(correction)
        logger.info(
            "Recorded correction %s for finding %s: %s → %s",
            correction.correction_type.value,
            correction.finding_id,
            correction.original_value[:40],
            correction.corrected_value[:40],
        )
        return True

    def load_from_jsonl(self, path: str) -> int:
        """Bulk-load corrections from a JSONL file."""
        from pathlib import Path

        data = Path(path)
        if not data.exists():
            return 0
        count = 0
        for line in data.read_text().strip().split("\n"):
            if not line.strip():
                continue
            try:
                d = json.loads(line)
                c = Correction(
                    finding_id=d["finding_id"],
                    correction_type=CorrectionType(d["correction_type"]),
                    original_value=d.get("original_value", ""),
                    corrected_value=d.get("corrected_value", ""),
                    analyst_id=d.get("analyst_id", ""),
                    reason=d.get("reason", ""),
                    detector_id=d.get("detector_id", ""),
                    category=d.get("category", ""),
                    source_snippet=d.get("source_snippet", ""),
                )
                self.record(c)
                count += 1
            except (KeyError, ValueError) as e:
                logger.warning("Skipping malformed correction: %s", e)
        return count

    @property
    def corrections(self) -> list[Correction]:
        return list(self._corrections)

    @property
    def size(self) -> int:
        return len(self._corrections)

    def get_by_type(self, ct: CorrectionType) -> list[Correction]:
        return [c for c in self._corrections if c.correction_type == ct]

    def get_by_detector(self, detector_id: str) -> list[Correction]:
        return [c for c in self._corrections if c.detector_id == detector_id]

    def export_jsonl(self) -> str:
        """Serialise all corrections as JSONL."""
        lines = []
        for c in self._corrections:
            lines.append(json.dumps({
                "finding_id": c.finding_id,
                "correction_type": c.correction_type.value,
                "original_value": c.original_value,
                "corrected_value": c.corrected_value,
                "analyst_id": c.analyst_id,
                "reason": c.reason,
                "detector_id": c.detector_id,
                "category": c.category,
                "timestamp": c.timestamp,
            }))
        return "\n".join(lines)


# ── Pattern analysis ─────────────────────────────────────────────────────────


class PatternAnalyser:
    """Detects systematic error patterns from accumulated corrections."""

    def __init__(self, min_frequency: int = 3) -> None:
        self._min_freq = min_frequency

    def analyse(self, corrections: list[Correction]) -> list[ErrorPattern]:
        """Discover recurring patterns. Returns patterns sorted by frequency."""
        patterns: list[ErrorPattern] = []

        # 1. Severity over-/under-estimation per detector
        patterns.extend(self._severity_patterns(corrections))

        # 2. False-positive clusters
        patterns.extend(self._false_positive_patterns(corrections))

        # 3. Category misclassification
        patterns.extend(self._category_patterns(corrections))

        # 4. Description quality issues
        patterns.extend(self._description_patterns(corrections))

        patterns.sort(key=lambda p: p.frequency, reverse=True)
        return patterns

    def _severity_patterns(self, corrections: list[Correction]) -> list[ErrorPattern]:
        """Detect detectors that systematically over-/under-rate severity."""
        sev_corrections = [c for c in corrections if c.correction_type == CorrectionType.SEVERITY_CHANGE]
        if len(sev_corrections) < self._min_freq:
            return []

        # Group by detector
        by_det: dict[str, list[Correction]] = defaultdict(list)
        for c in sev_corrections:
            key = c.detector_id or "unknown"
            by_det[key].append(c)

        patterns = []
        sev_rank = {"critical": 4, "high": 3, "medium": 2, "low": 1, "informational": 0}

        for det_id, corrs in by_det.items():
            if len(corrs) < self._min_freq:
                continue

            deltas = []
            for c in corrs:
                orig = sev_rank.get(c.original_value.lower(), 2)
                fixed = sev_rank.get(c.corrected_value.lower(), 2)
                deltas.append(fixed - orig)

            avg_delta = sum(deltas) / len(deltas)
            direction = "over-estimates" if avg_delta < 0 else "under-estimates"

            patterns.append(ErrorPattern(
                pattern_id=f"sev_{det_id}_{direction.replace('-', '_')}",
                correction_type=CorrectionType.SEVERITY_CHANGE,
                description=f"Detector '{det_id}' consistently {direction} severity (avg Δ={avg_delta:.1f})",
                frequency=len(corrs),
                examples=[{"original": c.original_value, "corrected": c.corrected_value} for c in corrs[:3]],
                detector_ids=[det_id],
                suggested_prompt_patch=(
                    f"When using detector '{det_id}', consider that it tends to {direction.replace('-', ' ')} "
                    f"severity. Adjust confidence thresholds accordingly."
                ),
            ))

        return patterns

    def _false_positive_patterns(self, corrections: list[Correction]) -> list[ErrorPattern]:
        """Detect false-positive hotspots."""
        fps = [c for c in corrections if c.correction_type == CorrectionType.FALSE_POSITIVE]
        if len(fps) < self._min_freq:
            return []

        by_det: Counter[str] = Counter(c.detector_id or "unknown" for c in fps)
        patterns = []
        for det_id, count in by_det.most_common():
            if count < self._min_freq:
                break
            examples = [c for c in fps if (c.detector_id or "unknown") == det_id]
            reasons = [c.reason for c in examples if c.reason][:3]

            patterns.append(ErrorPattern(
                pattern_id=f"fp_{det_id}",
                correction_type=CorrectionType.FALSE_POSITIVE,
                description=f"Detector '{det_id}' produces frequent false positives ({count} instances)",
                frequency=count,
                examples=[{"reason": r} for r in reasons],
                detector_ids=[det_id],
                suggested_prompt_patch=(
                    f"Detector '{det_id}' has a high false-positive rate. "
                    f"Common FP reasons: {'; '.join(reasons[:2]) or 'N/A'}. "
                    f"Apply additional verification before reporting."
                ),
            ))

        return patterns

    def _category_patterns(self, corrections: list[Correction]) -> list[ErrorPattern]:
        """Detect systematic category misclassifications."""
        cats = [c for c in corrections if c.correction_type == CorrectionType.CATEGORY_CHANGE]
        if len(cats) < self._min_freq:
            return []

        confusion: Counter[tuple[str, str]] = Counter()
        for c in cats:
            confusion[(c.original_value, c.corrected_value)] += 1

        patterns = []
        for (orig, fixed), count in confusion.most_common():
            if count < self._min_freq:
                break
            patterns.append(ErrorPattern(
                pattern_id=f"cat_{orig}_to_{fixed}",
                correction_type=CorrectionType.CATEGORY_CHANGE,
                description=f"Category '{orig}' frequently corrected to '{fixed}' ({count}×)",
                frequency=count,
                suggested_prompt_patch=(
                    f"Findings labelled '{orig}' are often actually '{fixed}'. "
                    f"Review classification criteria for these two categories."
                ),
            ))

        return patterns

    def _description_patterns(self, corrections: list[Correction]) -> list[ErrorPattern]:
        """Detect common description quality issues."""
        descs = [c for c in corrections if c.correction_type == CorrectionType.DESCRIPTION_EDIT]
        if len(descs) < self._min_freq:
            return []

        # Check if corrections tend to add attack-scenario or impact detail
        attack_adds = sum(
            1 for c in descs
            if "attack" in c.corrected_value.lower() and "attack" not in c.original_value.lower()
        )
        impact_adds = sum(
            1 for c in descs
            if "impact" in c.corrected_value.lower() and "impact" not in c.original_value.lower()
        )

        patterns = []
        if attack_adds >= self._min_freq:
            patterns.append(ErrorPattern(
                pattern_id="desc_missing_attack_scenario",
                correction_type=CorrectionType.DESCRIPTION_EDIT,
                description=f"Descriptions frequently lack attack scenarios ({attack_adds}× added by analysts)",
                frequency=attack_adds,
                suggested_prompt_patch=(
                    "Always include a concrete attack scenario in finding descriptions. "
                    "Describe step-by-step how an attacker could exploit the vulnerability."
                ),
            ))
        if impact_adds >= self._min_freq:
            patterns.append(ErrorPattern(
                pattern_id="desc_missing_impact",
                correction_type=CorrectionType.DESCRIPTION_EDIT,
                description=f"Descriptions frequently lack impact analysis ({impact_adds}× added)",
                frequency=impact_adds,
                suggested_prompt_patch=(
                    "Always quantify potential impact: estimated loss in USD/ETH, "
                    "affected user count, and protocol integrity consequences."
                ),
            ))

        return patterns


# ── Prompt optimiser ─────────────────────────────────────────────────────────


# Canonical prompt sections that can receive patches
PROMPT_SECTIONS = {
    "analysis_system": {
        "severity_guidelines": (
            "Classify severity as critical, high, medium, low, or informational "
            "based on exploit likelihood and potential financial impact."
        ),
        "description_format": (
            "Each finding must include: title, severity, category, description, "
            "attack scenario, impact, and recommended fix."
        ),
        "false_positive_filter": (
            "Before reporting, verify the vulnerability is reachable in the call graph "
            "and not mitigated by existing checks."
        ),
    },
    "remediation": {
        "fix_quality": (
            "Proposed fixes must be minimal, correct, and preserve existing functionality. "
            "Include gas-impact estimates."
        ),
    },
}


class PromptOptimiser:
    """Generates prompt patches from detected error patterns."""

    def __init__(self) -> None:
        self._patches: list[PromptPatch] = []

    def generate_patches(self, patterns: list[ErrorPattern]) -> list[PromptPatch]:
        """Convert error patterns into prompt patches."""
        self._patches = []

        for pattern in patterns:
            if pattern.correction_type == CorrectionType.SEVERITY_CHANGE:
                self._patch_severity_guidelines(pattern)
            elif pattern.correction_type == CorrectionType.FALSE_POSITIVE:
                self._patch_fp_filter(pattern)
            elif pattern.correction_type == CorrectionType.DESCRIPTION_EDIT:
                self._patch_description_format(pattern)
            elif pattern.correction_type == CorrectionType.CATEGORY_CHANGE:
                self._patch_severity_guidelines(pattern)  # category is in same section

        return list(self._patches)

    def _patch_severity_guidelines(self, pattern: ErrorPattern) -> None:
        section = PROMPT_SECTIONS["analysis_system"]["severity_guidelines"]
        patched = section + f"\n\nLEARNED: {pattern.suggested_prompt_patch}"
        self._patches.append(PromptPatch(
            prompt_name="analysis_system",
            section="severity_guidelines",
            original_text=section,
            patched_text=patched,
            rationale=pattern.description,
            improvement_estimate=min(0.9, 0.1 * pattern.frequency),
        ))

    def _patch_fp_filter(self, pattern: ErrorPattern) -> None:
        section = PROMPT_SECTIONS["analysis_system"]["false_positive_filter"]
        patched = section + f"\n\nLEARNED: {pattern.suggested_prompt_patch}"
        self._patches.append(PromptPatch(
            prompt_name="analysis_system",
            section="false_positive_filter",
            original_text=section,
            patched_text=patched,
            rationale=pattern.description,
            improvement_estimate=min(0.9, 0.12 * pattern.frequency),
        ))

    def _patch_description_format(self, pattern: ErrorPattern) -> None:
        section = PROMPT_SECTIONS["analysis_system"]["description_format"]
        patched = section + f"\n\nLEARNED: {pattern.suggested_prompt_patch}"
        self._patches.append(PromptPatch(
            prompt_name="analysis_system",
            section="description_format",
            original_text=section,
            patched_text=patched,
            rationale=pattern.description,
            improvement_estimate=min(0.9, 0.08 * pattern.frequency),
        ))

    def apply_patches(self) -> dict[str, dict[str, str]]:
        """Apply all patches and return the updated prompt sections."""
        updated = json.loads(json.dumps(PROMPT_SECTIONS))

        for patch in self._patches:
            if patch.prompt_name in updated and patch.section in updated[patch.prompt_name]:
                updated[patch.prompt_name][patch.section] = patch.patched_text
                patch.applied = True
                logger.info(
                    "Applied prompt patch: %s/%s (improvement est: %.0f%%)",
                    patch.prompt_name, patch.section, patch.improvement_estimate * 100,
                )

        return updated


# ── Orchestrator ─────────────────────────────────────────────────────────────


class FeedbackLoop:
    """Orchestrates the full feedback cycle:
    collect corrections → analyse patterns → optimise prompts → export.
    """

    def __init__(
        self,
        min_pattern_frequency: int = 3,
        correction_store: CorrectionStore | None = None,
    ) -> None:
        self._store = correction_store or CorrectionStore()
        self._analyser = PatternAnalyser(min_frequency=min_pattern_frequency)
        self._optimiser = PromptOptimiser()
        self._patterns: list[ErrorPattern] = []
        self._patches: list[PromptPatch] = []

    @property
    def store(self) -> CorrectionStore:
        return self._store

    @property
    def patterns(self) -> list[ErrorPattern]:
        return list(self._patterns)

    @property
    def patches(self) -> list[PromptPatch]:
        return list(self._patches)

    def record_correction(self, correction: Correction) -> bool:
        """Record a single correction."""
        return self._store.record(correction)

    def run_cycle(self) -> dict[str, Any]:
        """Run one full feedback cycle. Returns a summary dict."""
        # 1. Analyse patterns
        self._patterns = self._analyser.analyse(self._store.corrections)

        # 2. Generate patches
        self._patches = self._optimiser.generate_patches(self._patterns)

        # 3. Apply patches
        updated_prompts = self._optimiser.apply_patches()

        summary = {
            "corrections_total": self._store.size,
            "patterns_found": len(self._patterns),
            "patches_generated": len(self._patches),
            "patches_applied": sum(1 for p in self._patches if p.applied),
            "top_patterns": [
                {"id": p.pattern_id, "description": p.description, "frequency": p.frequency}
                for p in self._patterns[:5]
            ],
            "updated_prompt_sections": list({
                f"{p.prompt_name}/{p.section}" for p in self._patches if p.applied
            }),
        }

        logger.info(
            "Feedback cycle complete: %d corrections → %d patterns → %d patches applied",
            summary["corrections_total"],
            summary["patterns_found"],
            summary["patches_applied"],
        )

        return summary

    def get_metrics(self) -> dict[str, Any]:
        """Return correction/pattern metrics for monitoring."""
        type_counts = Counter(c.correction_type.value for c in self._store.corrections)
        detector_counts = Counter(c.detector_id for c in self._store.corrections if c.detector_id)

        return {
            "total_corrections": self._store.size,
            "by_type": dict(type_counts),
            "by_detector": dict(detector_counts.most_common(10)),
            "patterns_count": len(self._patterns),
            "fp_rate": (
                type_counts.get("false_positive", 0) / max(1, self._store.size)
            ),
        }
