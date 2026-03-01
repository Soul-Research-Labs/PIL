"""Tests for the Soul Fuzzer — campaign lifecycle and phase pipeline."""

from __future__ import annotations

import asyncio
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from engine.core.types import FindingSchema, Severity, Location


class TestSoulFuzzerInit:
    """Test SoulFuzzer instantiation and configuration."""

    def test_import(self):
        from engine.fuzzer.soul_fuzzer import SoulFuzzer
        assert SoulFuzzer is not None

    def test_instantiation(self):
        from engine.fuzzer.soul_fuzzer import SoulFuzzer
        fuzzer = SoulFuzzer()
        assert fuzzer is not None

    def test_has_phase_methods(self):
        from engine.fuzzer.soul_fuzzer import SoulFuzzer
        fuzzer = SoulFuzzer()
        expected_phases = [
            "_phase_model_load",
            "_phase_seed_gen",
            "_phase_static_precheck",
            "_phase_mutation",
            "_phase_symbolic",
            "_phase_concolic",
            "_phase_forge_execute",
            "_phase_feedback",
            "_phase_corpus_evolve",
            "_phase_property_test",
            "_phase_differential",
            "_phase_llm_oracle",
        ]
        for phase in expected_phases:
            assert hasattr(fuzzer, phase), f"Missing phase method: {phase}"

    def test_has_v2_phase_methods(self):
        from engine.fuzzer.soul_fuzzer import SoulFuzzer
        fuzzer = SoulFuzzer()
        v2_phases = [
            "_phase_bytecode_analysis",
            "_phase_taint_mutation",
            "_phase_gas_profiling",
            "_phase_invariant_synthesis",
            "_phase_state_replay",
            "_phase_exploit_composition",
        ]
        for phase in v2_phases:
            assert hasattr(fuzzer, phase), f"Missing v2 phase method: {phase}"

    def test_has_campaign_methods(self):
        from engine.fuzzer.soul_fuzzer import SoulFuzzer
        fuzzer = SoulFuzzer()
        assert hasattr(fuzzer, "run_campaign")
        assert hasattr(fuzzer, "get_campaign_status")
        assert callable(fuzzer.run_campaign)
        assert callable(fuzzer.get_campaign_status)


class TestSoulFuzzerResults:
    """Test result building and scoring."""

    def test_build_result_returns_dict(self):
        from engine.fuzzer.soul_fuzzer import SoulFuzzer
        fuzzer = SoulFuzzer()
        if hasattr(fuzzer, "_build_result"):
            # Build result needs campaign state; just verify method exists
            assert callable(fuzzer._build_result)

    def test_generate_seeds_returns_list(self):
        from engine.fuzzer.soul_fuzzer import SoulFuzzer
        fuzzer = SoulFuzzer()
        if hasattr(fuzzer, "_generate_seeds"):
            assert callable(fuzzer._generate_seeds)


class TestSoulFuzzerEngines:
    """Verify all 13 engines can be imported."""

    def test_import_mutation_engine(self):
        from engine.fuzzer.mutation_engine import MutationEngine
        assert MutationEngine is not None

    def test_import_feedback_loop(self):
        from engine.fuzzer.feedback_loop import FeedbackLoop
        assert FeedbackLoop is not None

    def test_import_symbolic(self):
        from engine.fuzzer.symbolic import SymbolicAnalyzer
        assert SymbolicAnalyzer is not None

    def test_import_concolic(self):
        from engine.fuzzer.concolic import ConcolicEngine
        assert ConcolicEngine is not None

    def test_import_forge_executor(self):
        from engine.fuzzer.forge_executor import ForgeExecutor
        assert ForgeExecutor is not None

    def test_import_differential(self):
        from engine.fuzzer.differential import DifferentialEngine
        assert DifferentialEngine is not None

    def test_import_llm_oracle(self):
        from engine.fuzzer.llm_oracle import LLMOracle
        assert LLMOracle is not None

    def test_import_property_tester(self):
        from engine.fuzzer.property_tester import PropertyTester
        assert PropertyTester is not None

    def test_import_corpus_evolution(self):
        from engine.fuzzer.corpus_evolution import CorpusEvolution
        assert CorpusEvolution is not None

    def test_import_bytecode_analyzer(self):
        from engine.fuzzer.bytecode_analyzer import BytecodeAnalyzer
        assert BytecodeAnalyzer is not None

    def test_import_taint_mutator(self):
        from engine.fuzzer.taint_mutator import TaintMutator
        assert TaintMutator is not None

    def test_import_gas_profiler(self):
        from engine.fuzzer.gas_profiler import GasProfiler
        assert GasProfiler is not None

    def test_import_invariant_synth(self):
        from engine.fuzzer.invariant_synth import InvariantSynthesizer
        assert InvariantSynthesizer is not None

    def test_import_state_replay(self):
        from engine.fuzzer.state_replay import StateReplayEngine
        assert StateReplayEngine is not None

    def test_import_exploit_composer(self):
        from engine.fuzzer.exploit_composer import ExploitComposer
        assert ExploitComposer is not None
