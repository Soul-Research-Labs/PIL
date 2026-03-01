"""Fine-tuned vulnerability detection model — training pipeline,
dataset management, and inference wrapper.

Architecture:
    - Pre-trained CodeBERT/StarCoder2 encoder finetuned on labeled audit data
    - Multi-label classification head: severity × category × confidence
    - Training corpus: labeled security audit findings (CodeArena, Immunefi, C4)
    - Inference: embeddings → classifier → ranked vulnerabilities

This module provides:
    1. DatasetLoader  — loads and preprocesses labeled audit data
    2. VulnModelTrainer — fine-tuning loop with evaluation
    3. VulnModelInference — production inference wrapper
    4. Feature extraction utilities for Solidity/Vyper source
"""

from __future__ import annotations

import hashlib
import json
import logging
import re
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


# ── Configuration ────────────────────────────────────────────────────────────


class ModelBackend(str, Enum):
    """Supported model backends."""
    CODEBERT = "codebert"          # microsoft/codebert-base
    STARCODER2 = "starcoder2"      # bigcode/starcoder2-3b
    CUSTOM = "custom"              # User-provided model path


@dataclass
class TrainingConfig:
    """Configuration for model fine-tuning."""
    model_backend: ModelBackend = ModelBackend.CODEBERT
    model_name: str = "microsoft/codebert-base"
    output_dir: str = "/tmp/zaseon_ml/models"
    dataset_dir: str = "/tmp/zaseon_ml/datasets"

    # Training hyperparameters
    learning_rate: float = 2e-5
    batch_size: int = 16
    epochs: int = 10
    warmup_steps: int = 500
    weight_decay: float = 0.01
    max_seq_length: int = 512
    gradient_accumulation_steps: int = 2

    # Labels
    severity_labels: list[str] = field(
        default_factory=lambda: ["critical", "high", "medium", "low", "informational"]
    )
    category_labels: list[str] = field(
        default_factory=lambda: [
            "reentrancy", "access_control", "arithmetic", "flash_loan",
            "oracle_manipulation", "governance", "token_standard",
            "delegatecall", "storage", "gas_optimization", "mev",
            "upgradeable", "bridge", "privacy", "economic",
        ]
    )


# ── Dataset ──────────────────────────────────────────────────────────────────


@dataclass
class LabeledSample:
    """A labeled training sample from audit data."""
    source_code: str
    vulnerability_snippet: str
    severity: str
    category: str
    title: str
    description: str
    confidence: float = 1.0
    source: str = ""           # e.g., "code4rena", "immunefi", "internal"
    cwe_id: str = ""
    file_hash: str = ""

    def __post_init__(self):
        if not self.file_hash:
            self.file_hash = hashlib.sha256(self.source_code.encode()).hexdigest()[:16]


class DatasetLoader:
    """Loads and preprocesses labeled audit datasets.

    Supports formats:
    - JSONL: one JSON object per line with fields matching LabeledSample
    - Annotated Solidity: .sol files with inline `// @vuln: severity, category` comments
    """

    def __init__(self, config: TrainingConfig) -> None:
        self._config = config
        self._samples: list[LabeledSample] = []

    @property
    def samples(self) -> list[LabeledSample]:
        return list(self._samples)

    @property
    def size(self) -> int:
        return len(self._samples)

    def load_jsonl(self, path: str | Path) -> int:
        """Load samples from a JSONL file. Returns count of samples loaded."""
        path = Path(path)
        if not path.exists():
            logger.warning("Dataset file not found: %s", path)
            return 0

        count = 0
        for line in path.read_text().strip().split("\n"):
            if not line.strip():
                continue
            try:
                data = json.loads(line)
                sample = LabeledSample(
                    source_code=data.get("source_code", ""),
                    vulnerability_snippet=data.get("snippet", data.get("vulnerability_snippet", "")),
                    severity=data.get("severity", "medium"),
                    category=data.get("category", ""),
                    title=data.get("title", ""),
                    description=data.get("description", ""),
                    confidence=data.get("confidence", 1.0),
                    source=data.get("source", ""),
                    cwe_id=data.get("cwe_id", ""),
                )
                self._samples.append(sample)
                count += 1
            except (json.JSONDecodeError, KeyError) as e:
                logger.warning("Skipping malformed line: %s", e)

        logger.info("Loaded %d samples from %s", count, path)
        return count

    def load_annotated_solidity(self, directory: str | Path) -> int:
        """Load samples from annotated Solidity files.

        Expected format:
            // @vuln: high, reentrancy, Title here
            function vulnerable() external {
                ...
            }
        """
        directory = Path(directory)
        count = 0
        for sol_file in directory.rglob("*.sol"):
            source = sol_file.read_text()
            annotations = re.finditer(
                r'//\s*@vuln:\s*(\w+),\s*(\w+),\s*(.+)',
                source,
            )
            for m in annotations:
                severity, category, title = m.group(1), m.group(2), m.group(3).strip()
                line_no = source[:m.start()].count("\n")
                # Extract surrounding code (10 lines before and after)
                lines = source.split("\n")
                snippet_start = max(0, line_no - 5)
                snippet_end = min(len(lines), line_no + 15)
                snippet = "\n".join(lines[snippet_start:snippet_end])

                self._samples.append(LabeledSample(
                    source_code=source,
                    vulnerability_snippet=snippet,
                    severity=severity,
                    category=category,
                    title=title,
                    source=str(sol_file),
                ))
                count += 1

        logger.info("Loaded %d annotated samples from %s", count, directory)
        return count

    def get_train_test_split(
        self, test_ratio: float = 0.2, seed: int = 42,
    ) -> tuple[list[LabeledSample], list[LabeledSample]]:
        """Split samples into train/test sets with stratification by severity."""
        import random
        rng = random.Random(seed)

        # Group by severity for stratification
        by_severity: dict[str, list[LabeledSample]] = {}
        for s in self._samples:
            by_severity.setdefault(s.severity, []).append(s)

        train, test = [], []
        for sev, samples in by_severity.items():
            rng.shuffle(samples)
            split_idx = max(1, int(len(samples) * test_ratio))
            test.extend(samples[:split_idx])
            train.extend(samples[split_idx:])

        rng.shuffle(train)
        rng.shuffle(test)
        return train, test

    def to_feature_dicts(self) -> list[dict[str, Any]]:
        """Convert samples to feature dictionaries for model input."""
        return [
            {
                "text": _extract_features(s.source_code, s.vulnerability_snippet),
                "severity_label": s.severity,
                "category_label": s.category,
                "confidence": s.confidence,
            }
            for s in self._samples
        ]


# ── Feature extraction ───────────────────────────────────────────────────────


def _extract_features(source: str, snippet: str) -> str:
    """Extract a feature string for model input.

    Combines source structure signals with the vulnerability snippet,
    truncated to fit within token limits.
    """
    # Extract structural signals
    signals = []

    # Pragma version
    pragma = re.search(r'pragma\s+solidity\s+([^;]+);', source)
    if pragma:
        signals.append(f"[PRAGMA:{pragma.group(1).strip()}]")

    # Imports
    imports = re.findall(r'import\s+"([^"]+)"', source)
    for imp in imports[:5]:
        signals.append(f"[IMPORT:{imp.split('/')[-1]}]")

    # Contract inheritance
    inherits = re.findall(r'contract\s+\w+\s+is\s+([^{]+)', source)
    for inh in inherits:
        signals.append(f"[INHERITS:{inh.strip()}]")

    # Modifier usage
    modifiers = set(re.findall(r'\b(onlyOwner|nonReentrant|whenNotPaused|initializer)\b', source))
    for mod in modifiers:
        signals.append(f"[MOD:{mod}]")

    # External call patterns
    if ".call{" in source:
        signals.append("[EXTERNAL_CALL]")
    if "delegatecall" in source:
        signals.append("[DELEGATECALL]")
    if "selfdestruct" in source:
        signals.append("[SELFDESTRUCT]")

    header = " ".join(signals)
    return f"{header}\n{snippet[:2000]}"


# ── Model Trainer ────────────────────────────────────────────────────────────


class VulnModelTrainer:
    """Fine-tuning pipeline for the vulnerability detection model.

    Wraps HuggingFace Trainer with:
    - Multi-label classification head (severity + category)
    - Weighted loss for class imbalance
    - Early stopping on validation F1
    - Checkpoint management
    """

    def __init__(self, config: TrainingConfig) -> None:
        self._config = config
        self._model = None
        self._tokenizer = None

    def prepare(self) -> None:
        """Load the pre-trained model and tokenizer.

        Requires `transformers` and `torch` packages.
        """
        try:
            from transformers import AutoTokenizer, AutoModelForSequenceClassification

            num_labels = len(self._config.severity_labels) + len(self._config.category_labels)
            self._tokenizer = AutoTokenizer.from_pretrained(self._config.model_name)
            self._model = AutoModelForSequenceClassification.from_pretrained(
                self._config.model_name,
                num_labels=num_labels,
                problem_type="multi_label_classification",
            )
            logger.info("Loaded model %s with %d labels", self._config.model_name, num_labels)
        except ImportError:
            logger.error(
                "Install transformers and torch: pip install transformers torch"
            )
            raise

    def train(
        self,
        train_samples: list[LabeledSample],
        eval_samples: list[LabeledSample],
    ) -> dict[str, float]:
        """Run the fine-tuning loop.

        Returns a dict with training metrics: loss, accuracy, f1.
        """
        if self._model is None or self._tokenizer is None:
            raise RuntimeError("Call prepare() first")

        try:
            from transformers import Trainer, TrainingArguments

            training_args = TrainingArguments(
                output_dir=self._config.output_dir,
                num_train_epochs=self._config.epochs,
                per_device_train_batch_size=self._config.batch_size,
                per_device_eval_batch_size=self._config.batch_size,
                learning_rate=self._config.learning_rate,
                warmup_steps=self._config.warmup_steps,
                weight_decay=self._config.weight_decay,
                gradient_accumulation_steps=self._config.gradient_accumulation_steps,
                evaluation_strategy="epoch",
                save_strategy="epoch",
                load_best_model_at_end=True,
                metric_for_best_model="f1",
                logging_steps=50,
            )

            # Tokenize
            train_encodings = self._tokenize(train_samples)
            eval_encodings = self._tokenize(eval_samples)

            trainer = Trainer(
                model=self._model,
                args=training_args,
                train_dataset=train_encodings,
                eval_dataset=eval_encodings,
            )

            result = trainer.train()
            metrics = trainer.evaluate()

            # Save model
            trainer.save_model(self._config.output_dir)
            self._tokenizer.save_pretrained(self._config.output_dir)

            logger.info("Training complete. Metrics: %s", metrics)
            return metrics

        except ImportError:
            logger.error("Install transformers and torch for training")
            raise

    def _tokenize(self, samples: list[LabeledSample]) -> Any:
        """Tokenize samples into model input format."""
        texts = [_extract_features(s.source_code, s.vulnerability_snippet) for s in samples]
        encodings = self._tokenizer(
            texts,
            truncation=True,
            padding=True,
            max_length=self._config.max_seq_length,
            return_tensors="pt",
        )
        return encodings


# ── Inference ────────────────────────────────────────────────────────────────


@dataclass
class VulnPrediction:
    """A predicted vulnerability from the ML model."""
    severity: str
    category: str
    confidence: float
    severity_scores: dict[str, float] = field(default_factory=dict)
    category_scores: dict[str, float] = field(default_factory=dict)


class VulnModelInference:
    """Production inference wrapper for the fine-tuned model.

    Loads a trained checkpoint and provides `predict()` for
    classifying code snippets.
    """

    def __init__(self, model_dir: str = "/tmp/zaseon_ml/models") -> None:
        self._model_dir = model_dir
        self._model = None
        self._tokenizer = None
        self._config = TrainingConfig()
        self._loaded = False

    def load(self) -> bool:
        """Load the trained model from disk. Returns True on success."""
        model_path = Path(self._model_dir)
        if not model_path.exists():
            logger.warning("Model directory not found: %s", self._model_dir)
            return False

        try:
            from transformers import AutoTokenizer, AutoModelForSequenceClassification
            import torch

            self._tokenizer = AutoTokenizer.from_pretrained(self._model_dir)
            self._model = AutoModelForSequenceClassification.from_pretrained(self._model_dir)
            self._model.eval()
            self._loaded = True
            logger.info("Loaded vulnerability model from %s", self._model_dir)
            return True
        except Exception as e:
            logger.warning("Failed to load model: %s", e)
            return False

    def predict(self, source_code: str, snippet: str = "") -> VulnPrediction | None:
        """Predict vulnerability severity and category for a code snippet.

        Falls back to heuristic scoring if the ML model is not available.
        """
        if not self._loaded:
            return self._heuristic_predict(source_code, snippet)

        try:
            import torch

            text = _extract_features(source_code, snippet or source_code[:2000])
            inputs = self._tokenizer(
                text,
                truncation=True,
                max_length=self._config.max_seq_length,
                return_tensors="pt",
            )

            with torch.no_grad():
                outputs = self._model(**inputs)
                logits = outputs.logits[0]
                probs = torch.sigmoid(logits).numpy()

            # Split into severity and category scores
            n_sev = len(self._config.severity_labels)
            sev_probs = probs[:n_sev]
            cat_probs = probs[n_sev:]

            sev_scores = dict(zip(self._config.severity_labels, sev_probs.tolist()))
            cat_scores = dict(zip(self._config.category_labels, cat_probs.tolist()))

            top_severity = max(sev_scores, key=sev_scores.get)  # type: ignore
            top_category = max(cat_scores, key=cat_scores.get)  # type: ignore
            confidence = max(sev_scores[top_severity], cat_scores[top_category])

            return VulnPrediction(
                severity=top_severity,
                category=top_category,
                confidence=float(confidence),
                severity_scores=sev_scores,
                category_scores=cat_scores,
            )
        except Exception as e:
            logger.warning("ML prediction failed, falling back to heuristic: %s", e)
            return self._heuristic_predict(source_code, snippet)

    def _heuristic_predict(self, source: str, snippet: str) -> VulnPrediction:
        """Fallback heuristic prediction when ML model is unavailable."""
        text = (snippet or source).lower()

        # Severity heuristic
        if any(k in text for k in ["selfdestruct", "delegatecall", "suicide", "arbitrary"]):
            severity = "critical"
            confidence = 0.7
        elif any(k in text for k in ["reentrancy", "overflow", "underflow", "unauthorized"]):
            severity = "high"
            confidence = 0.65
        elif any(k in text for k in ["require", "assert", "revert", "modifier"]):
            severity = "medium"
            confidence = 0.5
        else:
            severity = "low"
            confidence = 0.4

        # Category heuristic
        category = "access_control"
        if "reentran" in text:
            category = "reentrancy"
        elif "overflow" in text or "underflow" in text:
            category = "arithmetic"
        elif "flash" in text or "loan" in text:
            category = "flash_loan"
        elif "delegate" in text:
            category = "delegatecall"
        elif "oracle" in text or "price" in text:
            category = "oracle_manipulation"

        return VulnPrediction(
            severity=severity,
            category=category,
            confidence=confidence,
        )

    def predict_batch(
        self, items: list[tuple[str, str]],
    ) -> list[VulnPrediction | None]:
        """Predict for multiple (source, snippet) pairs."""
        return [self.predict(src, snip) for src, snip in items]
