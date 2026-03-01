"""Tests for the plugin loader system.

Covers:
    - PluginHook enum values
    - PluginManifest parsing
    - PluginLoader discovery, load/unload, enable/disable
    - Hook firing with context chaining
    - Detector / mutation plugin discovery
"""

from __future__ import annotations

import textwrap
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from engine.plugins.loader import (
    BaseMutationPlugin,
    LoadedPlugin,
    MutationStrategy,
    PluginHook,
    PluginLoader,
    PluginManifest,
)


class TestPluginHook:
    def test_hook_count(self):
        assert len(PluginHook) == 8

    def test_hook_values(self):
        expected = {
            "pre_analysis", "post_analysis",
            "pre_fuzz", "post_fuzz",
            "on_finding", "on_scan_complete",
            "pre_report", "post_report",
        }
        assert {h.value for h in PluginHook} == expected


class TestPluginManifest:
    def test_manifest_fields(self):
        m = PluginManifest(
            name="test-plugin",
            version="1.0.0",
            description="A test plugin",
            hooks=[PluginHook.ON_FINDING],
            provides_detectors=True,
            provides_mutations=False,
            entry_module="plugin_main",
        )
        assert m.name == "test-plugin"
        assert m.provides_detectors is True
        assert PluginHook.ON_FINDING in m.hooks


class TestPluginLoader:
    def test_init(self, tmp_path: Path):
        loader = PluginLoader(plugin_dir=str(tmp_path))
        assert loader.get_detectors() == []
        assert loader.get_mutations() == []

    def test_discover_empty_dir(self, tmp_path: Path):
        loader = PluginLoader(plugin_dir=str(tmp_path))
        manifests = loader.discover()
        assert manifests == []

    def test_discover_plugin_with_manifest(self, tmp_path: Path):
        """Create a plugin dir with plugin.yaml and verify discovery."""
        plugin_dir = tmp_path / "my_plugin"
        plugin_dir.mkdir()

        manifest = plugin_dir / "plugin.yaml"
        manifest.write_text(textwrap.dedent("""\
            name: my-plugin
            version: 0.1.0
            description: Test detector plugin
            hooks:
              - on_finding
            provides_detectors: true
            provides_mutations: false
            entry_module: main
        """))

        # Create the entry module
        main_py = plugin_dir / "main.py"
        main_py.write_text(textwrap.dedent("""\
            # Empty plugin module
            def on_finding(context):
                return context
        """))

        loader = PluginLoader(plugin_dir=str(tmp_path))
        manifests = loader.discover()
        assert len(manifests) == 1
        assert manifests[0].name == "my-plugin"

    def test_fire_hook_no_handlers(self, tmp_path: Path):
        loader = PluginLoader(plugin_dir=str(tmp_path))
        result = loader.fire_hook(PluginHook.PRE_ANALYSIS, {"key": "value"})
        assert result == {"key": "value"}  # passes through unchanged

    def test_enable_disable(self, tmp_path: Path):
        loader = PluginLoader(plugin_dir=str(tmp_path))
        # These should not raise even with no plugins
        loader.enable_plugin("nonexistent")
        loader.disable_plugin("nonexistent")

    def test_unload_nonexistent(self, tmp_path: Path):
        loader = PluginLoader(plugin_dir=str(tmp_path))
        loader.unload_plugin("nonexistent")  # should not raise


class TestBaseMutationPlugin:
    def test_protocol(self):
        """BaseMutationPlugin should define the mutation interface."""
        assert hasattr(BaseMutationPlugin, "mutate")
        assert hasattr(BaseMutationPlugin, "name")
