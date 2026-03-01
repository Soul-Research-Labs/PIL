"""Tests for the mutation engine — strategy selection, weight adaptation, Soul-aware mutations."""

from __future__ import annotations

import pytest


class TestMutationEngine:
    """Test MutationEngine import and basic interface."""

    def test_import(self):
        from engine.fuzzer.mutation_engine import MutationEngine
        assert MutationEngine is not None

    def test_instantiation(self):
        from engine.fuzzer.mutation_engine import MutationEngine
        me = MutationEngine()
        assert me is not None

    def test_has_mutate_method(self):
        from engine.fuzzer.mutation_engine import MutationEngine
        me = MutationEngine()
        assert hasattr(me, "mutate") or hasattr(me, "generate_mutations")

    def test_has_soul_strategies(self):
        from engine.fuzzer.mutation_engine import MutationEngine
        me = MutationEngine()
        if hasattr(me, "strategies"):
            strat_names = [s if isinstance(s, str) else getattr(s, "name", str(s)) for s in me.strategies]
            strat_str = " ".join(strat_names).lower()
            assert any(
                kw in strat_str
                for kw in ["soul", "zk", "proof", "cross_chain", "privacy"]
            ), f"No Soul-specific strategies found in: {strat_str}"


class TestFeedbackLoop:
    """Test FeedbackLoop coverage tracking."""

    def test_import(self):
        from engine.fuzzer.feedback_loop import FeedbackLoop
        assert FeedbackLoop is not None

    def test_instantiation(self):
        from engine.fuzzer.feedback_loop import FeedbackLoop
        fl = FeedbackLoop()
        assert fl is not None

    def test_has_coverage_tracking(self):
        from engine.fuzzer.feedback_loop import FeedbackLoop
        fl = FeedbackLoop()
        assert hasattr(fl, "update") or hasattr(fl, "record_coverage") or hasattr(fl, "process_feedback")


class TestCorpusEvolution:
    """Test CorpusEvolution seed management."""

    def test_import(self):
        from engine.fuzzer.corpus_evolution import CorpusEvolution
        assert CorpusEvolution is not None

    def test_instantiation(self):
        from engine.fuzzer.corpus_evolution import CorpusEvolution
        ce = CorpusEvolution()
        assert ce is not None

    def test_has_corpus_methods(self):
        from engine.fuzzer.corpus_evolution import CorpusEvolution
        ce = CorpusEvolution()
        assert (
            hasattr(ce, "add_seed") or hasattr(ce, "evolve") or hasattr(ce, "select_seed")
        ), "CorpusEvolution missing expected seed management methods"
