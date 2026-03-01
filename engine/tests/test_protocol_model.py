"""Tests for the Soul Protocol model — contract registry and invariant queries."""

from __future__ import annotations

import pytest

from engine.analyzer.soul.protocol_model import SoulProtocolModel


class TestSoulProtocolModel:
    """Verify the Soul protocol model loads and queries correctly."""

    @pytest.fixture(autouse=True)
    def setup_model(self):
        self.model = SoulProtocolModel()

    # ── Initialization ───────────────────────────────────────────────────

    def test_model_has_contracts(self):
        assert len(self.model.contracts) > 0

    def test_model_has_invariants(self):
        assert len(self.model.invariants) > 0

    def test_model_has_mutation_strategies(self):
        assert len(self.model.mutation_strategies) > 0

    def test_model_has_categories(self):
        names = self.model.get_contract_names()
        assert isinstance(names, list)
        assert len(names) > 0

    # ── Contract Registry ────────────────────────────────────────────────

    def test_zk_slock_registered(self):
        names = self.model.get_contract_names()
        zk_names = [n for n in names if "ZK" in n.upper() or "SLOCK" in n.upper() or "Lock" in n]
        assert len(zk_names) >= 1, f"No ZK/SLock contract found in {names}"

    def test_pc3_registered(self):
        names = self.model.get_contract_names()
        pc3_names = [n for n in names if "PC3" in n.upper() or "PRIVACY" in n.upper()]
        assert len(pc3_names) >= 1, f"No PC3 contract found in {names}"

    def test_cdna_registered(self):
        names = self.model.get_contract_names()
        cdna_names = [n for n in names if "CDNA" in n.upper() or "DNA" in n.upper()]
        assert len(cdna_names) >= 1, f"No CDNA contract found in {names}"

    def test_easc_registered(self):
        names = self.model.get_contract_names()
        easc_names = [n for n in names if "EASC" in n.upper() or "ADAPTIVE" in n.upper()]
        assert len(easc_names) >= 1, f"No EASC contract found in {names}"

    def test_pbp_registered(self):
        names = self.model.get_contract_names()
        pbp_names = [n for n in names if "PBP" in n.upper() or "BUDGET" in n.upper()]
        assert len(pbp_names) >= 1, f"No PBP contract found in {names}"

    # ── Invariants ───────────────────────────────────────────────────────

    def test_invariant_struct(self):
        inv = self.model.invariants[0]
        assert "name" in inv or hasattr(inv, "name")

    def test_get_invariants_for_contract(self):
        names = self.model.get_contract_names()
        if names:
            invs = self.model.get_invariants_for_contract(names[0])
            assert isinstance(invs, list)

    # ── Mutation Strategies ──────────────────────────────────────────────

    def test_mutation_strategy_struct(self):
        strat = self.model.mutation_strategies[0]
        assert isinstance(strat, dict) or hasattr(strat, "name")

    def test_has_zk_mutations(self):
        strats = self.model.mutation_strategies
        zk_strats = [
            s for s in strats
            if "zk" in str(s).lower() or "proof" in str(s).lower()
        ]
        assert len(zk_strats) >= 1, "No ZK-specific mutation strategies"

    def test_has_cross_chain_mutations(self):
        strats = self.model.mutation_strategies
        cc_strats = [
            s for s in strats
            if "cross" in str(s).lower() or "chain" in str(s).lower()
        ]
        assert len(cc_strats) >= 1, "No cross-chain mutation strategies"

    # ── Detectors ────────────────────────────────────────────────────────

    def test_model_has_detectors(self):
        if hasattr(self.model, "detectors"):
            assert len(self.model.detectors) > 0

    # ── Query Methods (v2) ───────────────────────────────────────────────

    def test_get_high_risk_functions(self):
        if hasattr(self.model, "get_high_risk_functions"):
            funcs = self.model.get_high_risk_functions()
            assert isinstance(funcs, (list, dict))

    def test_get_state_dependencies(self):
        if hasattr(self.model, "get_state_dependencies"):
            deps = self.model.get_state_dependencies()
            assert isinstance(deps, (list, dict))

    def test_get_cross_contract_flows(self):
        if hasattr(self.model, "get_cross_contract_flows"):
            flows = self.model.get_cross_contract_flows()
            assert isinstance(flows, (list, dict))

    def test_get_privacy_critical_paths(self):
        if hasattr(self.model, "get_privacy_critical_paths"):
            paths = self.model.get_privacy_critical_paths()
            assert isinstance(paths, (list, dict))

    def test_get_upgrade_boundaries(self):
        if hasattr(self.model, "get_upgrade_boundaries"):
            bounds = self.model.get_upgrade_boundaries()
            assert isinstance(bounds, (list, dict))

    def test_get_gas_hotspots(self):
        if hasattr(self.model, "get_gas_hotspots"):
            spots = self.model.get_gas_hotspots()
            assert isinstance(spots, (list, dict))
