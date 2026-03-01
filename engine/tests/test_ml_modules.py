"""Tests for engine/ml/ — vuln_model, auto_triage, feedback, nl_query.

Covers:
    - DatasetLoader parsing (JSONL, annotated Solidity, train/test split)
    - VulnModelInference heuristic fallback prediction
    - FeatureExtractor signal extraction (30 features)
    - TriageClassifier heuristic prediction
    - AutoTriageEngine end-to-end triage
    - CorrectionStore record/dedup/export
    - PatternAnalyser pattern discovery
    - FeedbackLoop orchestration
    - QueryParser heuristic NL parsing
    - ResultFormatter summary / markdown table
    - NLQueryEngine query flow
"""

from __future__ import annotations

import json
import tempfile
from pathlib import Path

import pytest
import pytest_asyncio

# ── vuln_model ───────────────────────────────────────────────────────────────

from engine.ml.vuln_model import (
    DatasetLoader,
    LabeledSample,
    TrainingConfig,
    VulnModelInference,
    VulnPrediction,
    _extract_features,
)


class TestLabeledSample:
    def test_auto_hash(self):
        s = LabeledSample(
            source_code="contract A {}",
            vulnerability_snippet="function f() {}",
            severity="high",
            category="reentrancy",
            title="Reentrancy Bug",
            description="desc",
        )
        assert len(s.file_hash) == 16

    def test_explicit_hash(self):
        s = LabeledSample(
            source_code="x",
            vulnerability_snippet="y",
            severity="low",
            category="gas",
            title="T",
            description="D",
            file_hash="custom",
        )
        assert s.file_hash == "custom"


class TestDatasetLoader:
    def test_load_jsonl(self, tmp_path: Path):
        """Load samples from a JSONL file."""
        data = tmp_path / "samples.jsonl"
        data.write_text(
            "\n".join([
                json.dumps({
                    "source_code": "contract A {}",
                    "snippet": "function f() external {}",
                    "severity": "high",
                    "category": "reentrancy",
                    "title": "Bug",
                    "description": "desc",
                }),
                json.dumps({
                    "source_code": "contract B {}",
                    "snippet": "function g() public {}",
                    "severity": "medium",
                    "category": "access_control",
                    "title": "Access",
                    "description": "d2",
                }),
            ])
        )

        loader = DatasetLoader(TrainingConfig())
        count = loader.load_jsonl(str(data))
        assert count == 2
        assert loader.size == 2

    def test_load_jsonl_missing_file(self):
        loader = DatasetLoader(TrainingConfig())
        assert loader.load_jsonl("/nonexistent/path.jsonl") == 0

    def test_load_jsonl_malformed(self, tmp_path: Path):
        data = tmp_path / "bad.jsonl"
        data.write_text("not json\n{}\n")
        loader = DatasetLoader(TrainingConfig())
        count = loader.load_jsonl(str(data))
        # "not json" is malformed, {} creates a sample with defaults
        assert count == 1

    def test_train_test_split(self, tmp_path: Path):
        data = tmp_path / "samples.jsonl"
        lines = []
        for i in range(20):
            lines.append(json.dumps({
                "source_code": f"contract C{i} {{}}",
                "snippet": f"function f{i}() {{}}",
                "severity": ["high", "medium", "low"][i % 3],
                "category": "reentrancy",
                "title": f"Bug {i}",
                "description": f"desc {i}",
            }))
        data.write_text("\n".join(lines))

        loader = DatasetLoader(TrainingConfig())
        loader.load_jsonl(str(data))
        train, test = loader.get_train_test_split(test_ratio=0.2, seed=42)
        assert len(train) + len(test) == 20
        assert len(test) >= 3  # at least 1 per severity class

    def test_to_feature_dicts(self, tmp_path: Path):
        data = tmp_path / "s.jsonl"
        data.write_text(json.dumps({
            "source_code": "pragma solidity ^0.8.0; contract X {}",
            "snippet": "function f() {}",
            "severity": "high",
            "category": "reentrancy",
            "title": "T",
            "description": "D",
        }))
        loader = DatasetLoader(TrainingConfig())
        loader.load_jsonl(str(data))
        dicts = loader.to_feature_dicts()
        assert len(dicts) == 1
        assert dicts[0]["severity_label"] == "high"
        assert "[PRAGMA:" in dicts[0]["text"]


class TestExtractFeatures:
    def test_pragma_extraction(self):
        result = _extract_features("pragma solidity ^0.8.20;", "snippet")
        assert "[PRAGMA:" in result

    def test_modifier_extraction(self):
        result = _extract_features(
            "modifier onlyOwner {} modifier nonReentrant {}",
            "snippet",
        )
        assert "[MOD:onlyOwner]" in result
        assert "[MOD:nonReentrant]" in result

    def test_external_call_signal(self):
        result = _extract_features("x.call{value: 1}(data);", "snippet")
        assert "[EXTERNAL_CALL]" in result

    def test_delegatecall_signal(self):
        result = _extract_features("target.delegatecall(data);", "snippet")
        assert "[DELEGATECALL]" in result


class TestVulnModelInference:
    def test_heuristic_critical(self):
        model = VulnModelInference()
        pred = model.predict("selfdestruct(owner);", "selfdestruct(owner);")
        assert pred is not None
        assert pred.severity == "critical"

    def test_heuristic_high(self):
        model = VulnModelInference()
        pred = model.predict(
            "function withdraw() { (bool ok,) = msg.sender.call{value: bal}(\"\"); }",
            "reentrancy vulnerability",
        )
        assert pred is not None
        assert pred.severity == "high"

    def test_heuristic_medium(self):
        model = VulnModelInference()
        pred = model.predict("require(msg.sender == owner);", "require check")
        assert pred is not None
        assert pred.severity == "medium"

    def test_heuristic_low(self):
        model = VulnModelInference()
        pred = model.predict("uint256 x = 1;", "simple assignment")
        assert pred is not None
        assert pred.severity == "low"

    def test_heuristic_category_reentrancy(self):
        model = VulnModelInference()
        pred = model.predict("reentrancy in withdraw", "reentrant call")
        assert pred is not None
        assert pred.category == "reentrancy"

    def test_heuristic_category_oracle(self):
        model = VulnModelInference()
        pred = model.predict("oracle price manipulation", "oracle feed")
        assert pred is not None
        assert pred.category == "oracle_manipulation"

    def test_predict_batch(self):
        model = VulnModelInference()
        items = [
            ("selfdestruct(owner);", "selfdestruct"),
            ("uint x = 1;", "assignment"),
        ]
        results = model.predict_batch(items)
        assert len(results) == 2

    def test_load_nonexistent_model(self):
        model = VulnModelInference(model_dir="/nonexistent/path")
        assert model.load() is False


# ── auto_triage ──────────────────────────────────────────────────────────────

from engine.ml.auto_triage import (
    AutoTriageEngine,
    ConfidenceCalibrator,
    FeatureExtractor,
    TriageClassifier,
    TriageResult,
    FEATURE_NAMES,
)


class TestFeatureExtractor:
    def test_basic_extraction(self):
        extractor = FeatureExtractor()
        source = """
        pragma solidity ^0.8.0;
        contract Vuln {
            function withdraw(uint amount) external {
                require(balances[msg.sender] >= amount);
                (bool ok,) = msg.sender.call{value: amount}("");
                balances[msg.sender] -= amount;
            }
        }
        """
        finding = {"severity": "high", "confidence": 0.9, "code_snippet": source}
        feats = extractor.extract(source, finding)
        assert feats.values["has_external_call"] == 1.0
        assert feats.values["has_msg_value"] == 0.0  # no msg.value
        assert feats.values["num_require"] >= 1.0
        assert feats.values["sev_numeric"] == 1.0  # high = index 1

    def test_delegatecall_detection(self):
        extractor = FeatureExtractor()
        source = "target.delegatecall(data); selfdestruct(owner);"
        feats = extractor.extract(source, {"severity": "critical"})
        assert feats.values["has_delegatecall"] == 1.0
        assert feats.values["has_selfdestruct"] == 1.0

    def test_to_list_ordering(self):
        extractor = FeatureExtractor()
        feats = extractor.extract("contract X {}", {"severity": "low"})
        vec = feats.to_list(FEATURE_NAMES)
        assert len(vec) == len(FEATURE_NAMES)

    def test_cyclomatic_complexity(self):
        code = "if (x) {} else if (y) {} for (i=0;;) {} while(true) {}"
        cx = FeatureExtractor._cyclomatic_complexity(code)
        assert cx >= 4  # if, else, for, while


class TestTriageClassifier:
    def test_heuristic_predict_critical(self):
        classifier = TriageClassifier()
        # Build feature vector with dangerous patterns
        fmap = {n: 0.0 for n in FEATURE_NAMES}
        fmap["has_external_call"] = 1.0
        fmap["has_state_after_call"] = 1.0
        fmap["has_delegatecall"] = 1.0
        fmap["known_exploit_pattern"] = 1.0
        vec = [fmap.get(n, 0.0) for n in FEATURE_NAMES]
        sev, probs = classifier.predict(vec)
        assert sev == "critical"
        assert probs[sev] > 0.5

    def test_heuristic_predict_low(self):
        classifier = TriageClassifier()
        vec = [0.0] * len(FEATURE_NAMES)
        sev, probs = classifier.predict(vec)
        assert sev in ("informational", "low")


class TestConfidenceCalibrator:
    def test_uncalibrated_passthrough(self):
        cal = ConfidenceCalibrator()
        assert cal.calibrate(0.8) == 0.8

    def test_fit_and_calibrate(self):
        cal = ConfidenceCalibrator()
        scores = [0.9, 0.8, 0.7, 0.3, 0.2, 0.1]
        labels = [1, 1, 1, 0, 0, 0]
        cal.fit(scores, labels)
        # High scores should calibrate higher
        high = cal.calibrate(0.9)
        low = cal.calibrate(0.1)
        assert high > low


class TestAutoTriageEngine:
    def test_triage_single_finding(self):
        engine = AutoTriageEngine()
        source = "contract X { function f() external { msg.sender.call{value: 1}(\"\"); } }"
        finding = {
            "severity": "medium",
            "confidence": 0.7,
            "code_snippet": source,
        }
        result = engine.triage_finding(source, finding)
        assert isinstance(result, TriageResult)
        assert result.predicted_severity in ("critical", "high", "medium", "low", "informational")
        assert 0 <= result.risk_score <= 100
        assert result.recommendation

    def test_triage_findings_sorted(self):
        engine = AutoTriageEngine()
        source = "contract X {}"
        findings = [
            {"severity": "low", "confidence": 0.3},
            {"severity": "critical", "confidence": 0.9, "code_snippet": "selfdestruct(owner);"},
        ]
        results = engine.triage_findings(source, findings)
        assert len(results) == 2
        # Should be sorted by risk score descending
        assert results[0].risk_score >= results[1].risk_score


# ── feedback ─────────────────────────────────────────────────────────────────

from engine.ml.feedback import (
    Correction,
    CorrectionStore,
    CorrectionType,
    ErrorPattern,
    FeedbackLoop,
    PatternAnalyser,
    PromptOptimiser,
)


class TestCorrectionStore:
    def test_record_and_size(self):
        store = CorrectionStore()
        c = Correction(
            finding_id="f1",
            correction_type=CorrectionType.SEVERITY_CHANGE,
            original_value="high",
            corrected_value="critical",
        )
        assert store.record(c) is True
        assert store.size == 1

    def test_deduplication(self):
        store = CorrectionStore()
        c = Correction(
            finding_id="f1",
            correction_type=CorrectionType.SEVERITY_CHANGE,
            original_value="high",
            corrected_value="critical",
        )
        store.record(c)
        assert store.record(c) is False
        assert store.size == 1

    def test_get_by_type(self):
        store = CorrectionStore()
        store.record(Correction("f1", CorrectionType.SEVERITY_CHANGE, "high", "critical"))
        store.record(Correction("f2", CorrectionType.FALSE_POSITIVE, "high", "fp"))
        assert len(store.get_by_type(CorrectionType.FALSE_POSITIVE)) == 1

    def test_get_by_detector(self):
        store = CorrectionStore()
        store.record(Correction("f1", CorrectionType.SEVERITY_CHANGE, "h", "c", detector_id="DET-001"))
        store.record(Correction("f2", CorrectionType.FALSE_POSITIVE, "h", "fp", detector_id="DET-002"))
        assert len(store.get_by_detector("DET-001")) == 1

    def test_export_jsonl(self):
        store = CorrectionStore()
        store.record(Correction("f1", CorrectionType.SEVERITY_CHANGE, "high", "critical", detector_id="D1"))
        text = store.export_jsonl()
        data = json.loads(text)
        assert data["finding_id"] == "f1"
        assert data["correction_type"] == "severity_change"

    def test_load_from_jsonl(self, tmp_path: Path):
        f = tmp_path / "corrections.jsonl"
        f.write_text(json.dumps({
            "finding_id": "f1",
            "correction_type": "false_positive",
            "original_value": "high",
            "corrected_value": "fp",
        }))
        store = CorrectionStore()
        count = store.load_from_jsonl(str(f))
        assert count == 1
        assert store.size == 1


class TestPatternAnalyser:
    def test_severity_patterns(self):
        analyser = PatternAnalyser(min_frequency=2)
        corrections = [
            Correction("f1", CorrectionType.SEVERITY_CHANGE, "high", "medium", detector_id="D1"),
            Correction("f2", CorrectionType.SEVERITY_CHANGE, "high", "low", detector_id="D1"),
            Correction("f3", CorrectionType.SEVERITY_CHANGE, "critical", "medium", detector_id="D1"),
        ]
        patterns = analyser.analyse(corrections)
        assert len(patterns) >= 1
        assert any("over-estimates" in p.description for p in patterns)

    def test_false_positive_patterns(self):
        analyser = PatternAnalyser(min_frequency=2)
        corrections = [
            Correction("f1", CorrectionType.FALSE_POSITIVE, "h", "fp", detector_id="FP-DET", reason="not reachable"),
            Correction("f2", CorrectionType.FALSE_POSITIVE, "h", "fp", detector_id="FP-DET", reason="guarded"),
            Correction("f3", CorrectionType.FALSE_POSITIVE, "m", "fp", detector_id="FP-DET", reason="lib code"),
        ]
        patterns = analyser.analyse(corrections)
        assert any("false positive" in p.description.lower() for p in patterns)

    def test_no_patterns_below_threshold(self):
        analyser = PatternAnalyser(min_frequency=10)
        corrections = [
            Correction("f1", CorrectionType.SEVERITY_CHANGE, "h", "m", detector_id="D1"),
        ]
        patterns = analyser.analyse(corrections)
        assert len(patterns) == 0


class TestPromptOptimiser:
    def test_generate_patches(self):
        opt = PromptOptimiser()
        patterns = [
            ErrorPattern(
                pattern_id="sev_D1_over_estimates",
                correction_type=CorrectionType.SEVERITY_CHANGE,
                description="D1 over-estimates severity",
                frequency=5,
                suggested_prompt_patch="Adjust D1 thresholds",
            ),
        ]
        patches = opt.generate_patches(patterns)
        assert len(patches) >= 1
        assert "LEARNED:" in patches[0].patched_text

    def test_apply_patches(self):
        opt = PromptOptimiser()
        patterns = [
            ErrorPattern(
                pattern_id="fp_D1",
                correction_type=CorrectionType.FALSE_POSITIVE,
                description="D1 false positives",
                frequency=5,
                suggested_prompt_patch="Check reachability",
            ),
        ]
        opt.generate_patches(patterns)
        updated = opt.apply_patches()
        assert "analysis_system" in updated
        assert "LEARNED:" in updated["analysis_system"]["false_positive_filter"]


class TestFeedbackLoop:
    def test_full_cycle(self):
        loop = FeedbackLoop(min_pattern_frequency=2)
        # Record corrections
        for i in range(5):
            loop.record_correction(Correction(
                finding_id=f"f{i}",
                correction_type=CorrectionType.SEVERITY_CHANGE,
                original_value="high",
                corrected_value="medium",
                detector_id="REEN-001",
            ))

        summary = loop.run_cycle()
        assert summary["corrections_total"] == 5
        assert summary["patterns_found"] >= 1
        assert summary["patches_generated"] >= 1

    def test_get_metrics(self):
        loop = FeedbackLoop()
        loop.record_correction(Correction("f1", CorrectionType.FALSE_POSITIVE, "h", "fp"))
        metrics = loop.get_metrics()
        assert metrics["total_corrections"] == 1
        assert metrics["fp_rate"] == 1.0


# ── nl_query ─────────────────────────────────────────────────────────────────

from engine.ml.nl_query import (
    NLQueryEngine,
    QueryParser,
    QueryResult,
    QueryTarget,
    ResultFormatter,
    SortOrder,
    StructuredQuery,
)


class TestQueryParser:
    @pytest.mark.asyncio
    async def test_parse_critical_findings(self):
        parser = QueryParser()
        sq = await parser.parse("show me all critical reentrancy findings")
        assert sq.filters.get("severity") == "critical"
        assert sq.filters.get("category") == "reentrancy"
        assert sq.target == QueryTarget.FINDINGS

    @pytest.mark.asyncio
    async def test_parse_scan_query(self):
        parser = QueryParser()
        sq = await parser.parse("latest failed scans")
        assert sq.target == QueryTarget.SCANS
        assert sq.filters.get("status") == "failed"
        assert sq.sort_by == "created_at"
        assert sq.sort_order == SortOrder.DESC

    @pytest.mark.asyncio
    async def test_parse_count_query(self):
        parser = QueryParser()
        sq = await parser.parse("how many high findings?")
        assert sq.aggregation == "count"
        assert sq.filters.get("severity") == "high"

    @pytest.mark.asyncio
    async def test_parse_group_by(self):
        parser = QueryParser()
        sq = await parser.parse("breakdown of findings per severity this month")
        assert sq.aggregation == "group_by"
        assert sq.group_by == "severity"
        assert sq.time_range_start  # should have time range

    @pytest.mark.asyncio
    async def test_parse_limit(self):
        parser = QueryParser()
        sq = await parser.parse("top 5 critical findings")
        assert sq.limit == 5

    @pytest.mark.asyncio
    async def test_parse_chain_filter(self):
        parser = QueryParser()
        sq = await parser.parse("open findings on ethereum")
        assert sq.filters.get("chain") == "ethereum"
        assert sq.filters.get("status") == "open"

    @pytest.mark.asyncio
    async def test_parse_time_last_n_days(self):
        parser = QueryParser()
        sq = await parser.parse("findings from last 7 days")
        assert sq.time_range_start


class TestResultFormatter:
    def test_summarise_count(self):
        sq = StructuredQuery(aggregation="count", target=QueryTarget.FINDINGS)
        result = QueryResult(structured_query=sq, data=[{"count": 42}], total_count=1)
        summary = ResultFormatter.summarise(result)
        assert "42" in summary

    def test_summarise_list(self):
        sq = StructuredQuery(
            target=QueryTarget.FINDINGS,
            filters={"severity": "high"},
        )
        result = QueryResult(
            structured_query=sq,
            data=[{"id": "1"}, {"id": "2"}],
            total_count=10,
            execution_time_ms=15.3,
        )
        summary = ResultFormatter.summarise(result)
        assert "2 of 10" in summary
        assert "severity=high" in summary

    def test_markdown_table(self):
        sq = StructuredQuery()
        result = QueryResult(
            structured_query=sq,
            data=[{"id": "1", "title": "Bug A"}, {"id": "2", "title": "Bug B"}],
        )
        md = ResultFormatter.to_markdown_table(result)
        assert "| id | title |" in md
        assert "Bug A" in md

    def test_markdown_table_empty(self):
        sq = StructuredQuery()
        result = QueryResult(structured_query=sq, data=[])
        md = ResultFormatter.to_markdown_table(result)
        assert "No results" in md


class TestNLQueryEngine:
    @pytest.mark.asyncio
    async def test_query_no_db(self):
        """Query without DB returns empty results gracefully."""
        engine = NLQueryEngine()
        result = await engine.query("show me all critical findings")
        assert isinstance(result, QueryResult)
        assert result.structured_query.filters.get("severity") == "critical"

    @pytest.mark.asyncio
    async def test_is_followup(self):
        assert NLQueryEngine._is_followup("now show me only the critical ones")
        assert NLQueryEngine._is_followup("filter those by reentrancy")
        assert not NLQueryEngine._is_followup("show me all findings")

    @pytest.mark.asyncio
    async def test_merge_queries(self):
        prev = StructuredQuery(
            target=QueryTarget.FINDINGS,
            filters={"severity": "high"},
            sort_by="created_at",
        )
        new = StructuredQuery(
            target=QueryTarget.FINDINGS,
            filters={"category": "reentrancy"},
        )
        merged = NLQueryEngine._merge_queries(prev, new)
        assert merged.filters["severity"] == "high"
        assert merged.filters["category"] == "reentrancy"
        assert merged.sort_by == "created_at"
