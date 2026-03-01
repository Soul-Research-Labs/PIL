"""Auto-triage — ML-powered severity scoring and prioritisation.

Extracts structural / semantic features from raw findings and
produces a calibrated severity score that augments (or overrides)
the static-analysis severity assigned by detectors.

Capabilities:
    1. FeatureExtractor   — 30+ signals from finding metadata + source
    2. TriageClassifier   — gradient-boosted ensemble (scikit-learn)
    3. ConfidenceCalibrator — Platt scaling for probability estimates
    4. AutoTriageEngine   — end-to-end: extract → classify → calibrate → rank
"""

from __future__ import annotations

import json
import logging
import math
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

# ── Types ────────────────────────────────────────────────────────────────────

SEVERITY_ORDER = ["critical", "high", "medium", "low", "informational"]
SEVERITY_WEIGHT: dict[str, float] = {
    "critical": 1.0,
    "high": 0.8,
    "medium": 0.5,
    "low": 0.2,
    "informational": 0.05,
}


@dataclass
class TriageResult:
    """Output of the auto-triage pipeline for a single finding."""
    original_severity: str
    predicted_severity: str
    confidence: float
    feature_importance: dict[str, float] = field(default_factory=dict)
    risk_score: float = 0.0          # 0–100, higher = more urgent
    exploit_likelihood: float = 0.0  # 0–1
    impact_score: float = 0.0        # 0–1
    recommendation: str = ""


@dataclass
class TriageFeatures:
    """Numeric feature vector for a single finding."""
    values: dict[str, float] = field(default_factory=dict)

    def to_list(self, feature_names: list[str]) -> list[float]:
        return [self.values.get(n, 0.0) for n in feature_names]


# ── Feature extraction ───────────────────────────────────────────────────────


# Canonical feature names (order matters for the model)
FEATURE_NAMES: list[str] = [
    # Source-level
    "has_external_call",
    "has_delegatecall",
    "has_selfdestruct",
    "has_inline_assembly",
    "has_low_level_call",
    "has_send_transfer",
    "has_state_after_call",
    "has_msg_value",
    "has_tx_origin",
    "has_block_timestamp",
    "num_modifiers",
    "num_require",
    "uses_safemath",
    "uses_reentrancy_guard",
    "contract_size_lines",
    "function_complexity",
    # Finding metadata
    "sev_numeric",
    "detector_confidence",
    "num_related_findings",
    "in_constructor",
    "in_fallback_or_receive",
    "is_payable",
    "is_public_external",
    "loc_start",
    "file_num_contracts",
    # Cross-reference
    "similar_cve_count",
    "known_exploit_pattern",
    "protocol_tvl_tier",
    "has_proxy_pattern",
    "has_flash_loan_interaction",
]


class FeatureExtractor:
    """Extracts numeric features from finding + source code context."""

    def extract(
        self,
        source_code: str,
        finding: dict[str, Any],
        related_count: int = 0,
        protocol_tvl_tier: int = 0,
    ) -> TriageFeatures:
        """Produce a TriageFeatures vector."""
        code = source_code.lower()
        snippet = finding.get("code_snippet", "").lower()

        v: dict[str, float] = {}

        # Source-level signals
        v["has_external_call"] = float(".call{" in code or ".call(" in code)
        v["has_delegatecall"] = float("delegatecall" in code)
        v["has_selfdestruct"] = float("selfdestruct" in code or "suicide" in code)
        v["has_inline_assembly"] = float("assembly" in code and "{" in code)
        v["has_low_level_call"] = float(
            bool(re.search(r'\.(call|staticcall|delegatecall)\s*[\({]', code))
        )
        v["has_send_transfer"] = float(".send(" in code or ".transfer(" in code)
        v["has_state_after_call"] = float(
            bool(re.search(r'\.(call|send|transfer)\s*\([^)]*\).*\n.*\w+\s*=', code))
        )
        v["has_msg_value"] = float("msg.value" in code)
        v["has_tx_origin"] = float("tx.origin" in code)
        v["has_block_timestamp"] = float("block.timestamp" in code)
        v["num_modifiers"] = float(len(re.findall(r'\bmodifier\s+\w+', code)))
        v["num_require"] = float(len(re.findall(r'\brequire\s*\(', code)))
        v["uses_safemath"] = float("safemath" in code or "using safemathlib" in code)
        v["uses_reentrancy_guard"] = float("nonreentrant" in code or "reentrancyguard" in code)
        v["contract_size_lines"] = float(code.count("\n"))
        v["function_complexity"] = self._cyclomatic_complexity(snippet or code[:3000])

        # Finding metadata
        severity = finding.get("severity", "medium").lower()
        v["sev_numeric"] = float(SEVERITY_ORDER.index(severity)) if severity in SEVERITY_ORDER else 2.0
        v["detector_confidence"] = float(finding.get("confidence", 0.5))
        v["num_related_findings"] = float(related_count)
        v["in_constructor"] = float("constructor" in snippet)
        v["in_fallback_or_receive"] = float("fallback" in snippet or "receive" in snippet)
        v["is_payable"] = float("payable" in snippet)
        v["is_public_external"] = float("public" in snippet or "external" in snippet)
        v["loc_start"] = float(finding.get("line_start", 0))
        v["file_num_contracts"] = float(len(re.findall(r'\bcontract\s+\w+', code)))

        # Cross-reference signals
        v["similar_cve_count"] = float(finding.get("similar_cve_count", 0))
        v["known_exploit_pattern"] = float(finding.get("known_exploit_pattern", False))
        v["protocol_tvl_tier"] = float(protocol_tvl_tier)
        v["has_proxy_pattern"] = float(
            "transparentupgradeableproxy" in code or "uupsproxy" in code or "erc1967" in code
        )
        v["has_flash_loan_interaction"] = float("flashloan" in code or "flash_loan" in code)

        return TriageFeatures(values=v)

    @staticmethod
    def _cyclomatic_complexity(code: str) -> float:
        """Approximate cyclomatic complexity from branch keywords."""
        branches = len(re.findall(r'\b(if|else|for|while|do|switch|case|require|assert)\b', code))
        return float(max(1, branches))


# ── Classification ───────────────────────────────────────────────────────────


class TriageClassifier:
    """Gradient-boosted ensemble for severity classification.

    Uses scikit-learn HistGradientBoostingClassifier when available,
    otherwise falls back to a heuristic scorer.
    """

    def __init__(self, model_path: str | None = None) -> None:
        self._model: Any | None = None
        self._model_path = model_path
        self._fitted = False

    def fit(self, X: list[list[float]], y: list[str]) -> dict[str, float]:
        """Train the classifier. Returns accuracy / F1 metrics."""
        try:
            from sklearn.ensemble import HistGradientBoostingClassifier
            from sklearn.model_selection import cross_val_score
            import numpy as np

            self._model = HistGradientBoostingClassifier(
                max_iter=300,
                max_depth=6,
                learning_rate=0.05,
                min_samples_leaf=5,
                class_weight="balanced",
                random_state=42,
            )

            arr_x = np.array(X)
            arr_y = np.array(y)

            # Cross-validated score
            scores = cross_val_score(self._model, arr_x, arr_y, cv=5, scoring="f1_weighted")
            self._model.fit(arr_x, arr_y)
            self._fitted = True

            metrics = {
                "cv_f1_mean": float(scores.mean()),
                "cv_f1_std": float(scores.std()),
            }
            logger.info("Triage classifier trained. CV F1=%.3f ± %.3f", metrics["cv_f1_mean"], metrics["cv_f1_std"])

            if self._model_path:
                import joblib
                joblib.dump(self._model, self._model_path)
                logger.info("Saved triage model to %s", self._model_path)

            return metrics

        except ImportError:
            logger.warning("scikit-learn not available; using heuristic triage")
            return {"cv_f1_mean": 0.0, "cv_f1_std": 0.0}

    def load(self) -> bool:
        """Load a previously trained model."""
        if not self._model_path or not Path(self._model_path).exists():
            return False
        try:
            import joblib
            self._model = joblib.load(self._model_path)
            self._fitted = True
            logger.info("Loaded triage model from %s", self._model_path)
            return True
        except Exception as e:
            logger.warning("Failed to load triage model: %s", e)
            return False

    def predict(self, features: list[float]) -> tuple[str, dict[str, float]]:
        """Predict severity + per-class probabilities."""
        if self._fitted and self._model is not None:
            try:
                import numpy as np

                x = np.array([features])
                pred = self._model.predict(x)[0]
                proba = self._model.predict_proba(x)[0]
                classes = self._model.classes_.tolist()
                return str(pred), dict(zip(classes, [float(p) for p in proba]))
            except Exception as e:
                logger.warning("ML prediction error, falling back: %s", e)

        return self._heuristic_predict(features)

    def _heuristic_predict(self, features: list[float]) -> tuple[str, dict[str, float]]:
        """Rule-based fallback."""
        fmap = dict(zip(FEATURE_NAMES, features))

        score = 0.0
        if fmap.get("has_external_call", 0):
            score += 15
        if fmap.get("has_delegatecall", 0):
            score += 25
        if fmap.get("has_selfdestruct", 0):
            score += 30
        if fmap.get("has_state_after_call", 0):
            score += 20
        if fmap.get("has_tx_origin", 0):
            score += 10
        if fmap.get("uses_reentrancy_guard", 0):
            score -= 15
        score += fmap.get("num_related_findings", 0) * 3
        score += fmap.get("known_exploit_pattern", 0) * 25
        score = max(0.0, min(100.0, score))

        if score >= 70:
            sev = "critical"
        elif score >= 50:
            sev = "high"
        elif score >= 30:
            sev = "medium"
        elif score >= 10:
            sev = "low"
        else:
            sev = "informational"

        probs = {s: 0.1 for s in SEVERITY_ORDER}
        probs[sev] = 0.6
        return sev, probs


# ── Confidence calibration ───────────────────────────────────────────────────


class ConfidenceCalibrator:
    """Platt scaling post-hoc calibration for probability estimates."""

    def __init__(self) -> None:
        self._a: float = 1.0
        self._b: float = 0.0
        self._fitted = False

    def fit(self, raw_scores: list[float], labels: list[int]) -> None:
        """Fit Platt scaling parameters on a validation set.

        labels: 1 = correct prediction, 0 = incorrect
        """
        if not raw_scores:
            return

        # Simple logistic regression on scores
        # σ(a·s + b) = P(correct | score=s)
        a, b = 1.0, 0.0
        lr = 0.01
        for _ in range(500):
            grad_a, grad_b = 0.0, 0.0
            for s, y in zip(raw_scores, labels):
                p = 1.0 / (1.0 + math.exp(-(a * s + b)))
                err = p - y
                grad_a += err * s
                grad_b += err
            n = len(raw_scores)
            a -= lr * grad_a / n
            b -= lr * grad_b / n

        self._a = a
        self._b = b
        self._fitted = True

    def calibrate(self, raw_score: float) -> float:
        """Apply Platt scaling to a raw confidence score."""
        if not self._fitted:
            return raw_score
        z = self._a * raw_score + self._b
        z = max(-50.0, min(50.0, z))  # clamp
        return 1.0 / (1.0 + math.exp(-z))


# ── Engine ───────────────────────────────────────────────────────────────────


class AutoTriageEngine:
    """End-to-end auto-triage pipeline.

    Usage:
        engine = AutoTriageEngine()
        engine.load_or_train(training_data)
        results = engine.triage_findings(source, findings)
    """

    def __init__(
        self,
        model_path: str | None = None,
        calibrator: ConfidenceCalibrator | None = None,
    ) -> None:
        self._extractor = FeatureExtractor()
        self._classifier = TriageClassifier(model_path=model_path)
        self._calibrator = calibrator or ConfidenceCalibrator()

    def load_model(self) -> bool:
        """Attempt to load a pre-trained model."""
        return self._classifier.load()

    def train(
        self,
        samples: list[dict[str, Any]],
        protocol_tvl_tier: int = 0,
    ) -> dict[str, float]:
        """Train the triage classifier from labeled samples.

        Each sample dict needs: source_code, severity, code_snippet (optional),
        confidence (optional).
        """
        X, y = [], []
        for s in samples:
            feats = self._extractor.extract(
                s.get("source_code", ""),
                s,
                protocol_tvl_tier=protocol_tvl_tier,
            )
            X.append(feats.to_list(FEATURE_NAMES))
            y.append(s.get("severity", "medium"))

        return self._classifier.fit(X, y)

    def triage_finding(
        self,
        source_code: str,
        finding: dict[str, Any],
        related_count: int = 0,
        protocol_tvl_tier: int = 0,
    ) -> TriageResult:
        """Triage a single finding."""
        feats = self._extractor.extract(source_code, finding, related_count, protocol_tvl_tier)
        vec = feats.to_list(FEATURE_NAMES)

        predicted, probs = self._classifier.predict(vec)
        raw_conf = max(probs.values()) if probs else 0.5
        confidence = self._calibrator.calibrate(raw_conf)

        # Risk score: severity weight × confidence × (1 + exploit likelihood)
        exploit_likelihood = self._estimate_exploit_likelihood(feats)
        impact = SEVERITY_WEIGHT.get(predicted, 0.5)
        risk_score = min(100.0, impact * confidence * (1.0 + exploit_likelihood) * 100)

        rec = self._generate_recommendation(predicted, feats, risk_score)

        return TriageResult(
            original_severity=finding.get("severity", "unknown"),
            predicted_severity=predicted,
            confidence=round(confidence, 3),
            feature_importance=self._top_features(feats),
            risk_score=round(risk_score, 1),
            exploit_likelihood=round(exploit_likelihood, 3),
            impact_score=round(impact, 3),
            recommendation=rec,
        )

    def triage_findings(
        self,
        source_code: str,
        findings: list[dict[str, Any]],
        protocol_tvl_tier: int = 0,
    ) -> list[TriageResult]:
        """Triage and rank a batch of findings by risk score (desc)."""
        results = [
            self.triage_finding(source_code, f, len(findings), protocol_tvl_tier)
            for f in findings
        ]
        results.sort(key=lambda r: r.risk_score, reverse=True)
        return results

    @staticmethod
    def _estimate_exploit_likelihood(feats: TriageFeatures) -> float:
        """Heuristic estimate of exploit likelihood 0–1."""
        v = feats.values
        score = 0.0
        if v.get("has_external_call"):
            score += 0.2
        if v.get("has_state_after_call"):
            score += 0.3  # classic reentrancy
        if v.get("has_delegatecall"):
            score += 0.25
        if v.get("known_exploit_pattern"):
            score += 0.4
        if v.get("has_flash_loan_interaction"):
            score += 0.15
        if v.get("uses_reentrancy_guard"):
            score -= 0.2
        return max(0.0, min(1.0, score))

    @staticmethod
    def _top_features(feats: TriageFeatures, n: int = 5) -> dict[str, float]:
        """Return the top-n contributing features."""
        sorted_feats = sorted(
            feats.values.items(), key=lambda kv: abs(kv[1]), reverse=True,
        )
        return dict(sorted_feats[:n])

    @staticmethod
    def _generate_recommendation(severity: str, feats: TriageFeatures, risk: float) -> str:
        """Generate a human-readable triage recommendation."""
        v = feats.values
        parts = []

        if risk >= 80:
            parts.append("URGENT: Immediate remediation required.")
        elif risk >= 50:
            parts.append("HIGH PRIORITY: Schedule fix for next sprint.")
        elif risk >= 25:
            parts.append("MODERATE: Review and plan remediation.")
        else:
            parts.append("LOW: Monitor; fix at convenience.")

        if v.get("has_state_after_call"):
            parts.append("State modification after external call detected — apply checks-effects-interactions pattern.")
        if v.get("has_delegatecall") and not v.get("has_proxy_pattern"):
            parts.append("Unrestricted delegatecall without standard proxy pattern — restrict target.")
        if v.get("has_tx_origin"):
            parts.append("tx.origin used for authorisation — replace with msg.sender.")

        return " ".join(parts)
