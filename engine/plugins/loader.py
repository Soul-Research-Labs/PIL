"""Plugin system — dynamic loading, validation, and lifecycle management
for custom detectors, mutation strategies, and analysis hooks.

A plugin is a Python package containing:
    plugin.yaml       — metadata (name, version, author, hooks)
    detectors/        — optional: BaseDetector subclasses
    mutations/        — optional: BaseMutationStrategy subclasses
    hooks/            — optional: pre/post analysis hooks

Usage:
    loader = PluginLoader(plugins_dir="/etc/zaseon/plugins")
    loader.discover()
    loader.load_all()

    for detector_cls in loader.get_detectors():
        findings = detector_cls().detect(context)
"""

from __future__ import annotations

import hashlib
import importlib
import importlib.util
import logging
import sys
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Protocol, Type, runtime_checkable

import yaml

from engine.analyzer.web3.base_detector import BaseDetector
from engine.core.types import FindingSchema

logger = logging.getLogger(__name__)


# ── Plugin protocol / base classes ───────────────────────────────────────────


class PluginHook(str, Enum):
    """Lifecycle hooks that plugins can register for."""
    PRE_ANALYSIS = "pre_analysis"           # Before static analysis
    POST_ANALYSIS = "post_analysis"         # After static analysis, before scoring
    PRE_FUZZ = "pre_fuzz"                   # Before fuzzing campaign starts
    POST_FUZZ = "post_fuzz"                 # After fuzzing campaign ends
    ON_FINDING = "on_finding"               # When a new finding is detected
    ON_SCAN_COMPLETE = "on_scan_complete"    # When a full scan completes
    PRE_REPORT = "pre_report"               # Before report generation
    POST_REPORT = "post_report"             # After report generation


@runtime_checkable
class MutationStrategy(Protocol):
    """Protocol for custom mutation strategies.

    Implementations must define:
        NAME: str — unique identifier
        DESCRIPTION: str — human-readable description
        mutate(seed_input, context) -> list[bytes]
    """
    NAME: str
    DESCRIPTION: str

    def mutate(self, seed_input: bytes, context: dict[str, Any]) -> list[bytes]:
        ...


class BaseMutationPlugin:
    """Base class for mutation strategy plugins."""
    NAME: str = ""
    DESCRIPTION: str = ""

    def mutate(self, seed_input: bytes, context: dict[str, Any]) -> list[bytes]:
        """Generate mutated inputs from a seed.

        Args:
            seed_input: The original input bytes.
            context: Runtime context (ABI, contract info, coverage bitmap).

        Returns:
            List of mutated input variants.
        """
        raise NotImplementedError


@runtime_checkable
class HookHandler(Protocol):
    """Protocol for plugin hook handlers."""
    def __call__(self, context: dict[str, Any]) -> dict[str, Any] | None:
        ...


# ── Plugin metadata ──────────────────────────────────────────────────────────


@dataclass
class PluginManifest:
    """Parsed plugin.yaml metadata."""
    name: str
    version: str
    description: str = ""
    author: str = ""
    license: str = ""
    min_engine_version: str = "0.1.0"
    max_engine_version: str = ""
    hooks: list[str] = field(default_factory=list)
    provides_detectors: bool = False
    provides_mutations: bool = False
    dependencies: list[str] = field(default_factory=list)
    config_schema: dict[str, Any] = field(default_factory=dict)


@dataclass
class LoadedPlugin:
    """Represents a loaded and validated plugin."""
    manifest: PluginManifest
    path: Path
    module: Any = None
    detectors: list[Type[BaseDetector]] = field(default_factory=list)
    mutations: list[Type[BaseMutationPlugin]] = field(default_factory=list)
    hook_handlers: dict[PluginHook, list[Callable]] = field(default_factory=dict)
    checksum: str = ""
    is_enabled: bool = True
    load_errors: list[str] = field(default_factory=list)


# ── Plugin loader ────────────────────────────────────────────────────────────


class PluginLoader:
    """Discovers, validates, and loads plugins from a directory.

    Each subdirectory in the plugins root that contains a ``plugin.yaml``
    is treated as a plugin candidate.
    """

    def __init__(self, plugins_dir: str | Path = "/etc/zaseon/plugins") -> None:
        self._plugins_dir = Path(plugins_dir)
        self._plugins: dict[str, LoadedPlugin] = {}
        self._hook_registry: dict[PluginHook, list[Callable]] = {
            hook: [] for hook in PluginHook
        }

    @property
    def plugins(self) -> dict[str, LoadedPlugin]:
        return dict(self._plugins)

    def discover(self) -> list[PluginManifest]:
        """Scan the plugins directory for plugin.yaml files."""
        manifests: list[PluginManifest] = []

        if not self._plugins_dir.exists():
            logger.info("Plugins directory %s does not exist — no plugins loaded", self._plugins_dir)
            return manifests

        for candidate in sorted(self._plugins_dir.iterdir()):
            if not candidate.is_dir():
                continue
            manifest_path = candidate / "plugin.yaml"
            if not manifest_path.exists():
                manifest_path = candidate / "plugin.yml"
            if not manifest_path.exists():
                continue

            try:
                manifest = _parse_manifest(manifest_path)
                manifests.append(manifest)
                logger.info("Discovered plugin: %s v%s", manifest.name, manifest.version)
            except Exception as e:
                logger.warning("Failed to parse manifest at %s: %s", manifest_path, e)

        return manifests

    def load_all(self) -> int:
        """Discover and load all plugins. Returns count of successfully loaded plugins."""
        manifests = self.discover()
        loaded = 0
        for manifest in manifests:
            try:
                self.load_plugin(manifest)
                loaded += 1
            except Exception as e:
                logger.error("Failed to load plugin '%s': %s", manifest.name, e)
        return loaded

    def load_plugin(self, manifest: PluginManifest) -> LoadedPlugin:
        """Load a single plugin by manifest."""
        plugin_dir = self._plugins_dir / manifest.name
        if not plugin_dir.exists():
            # Try slug-ified name
            slug = manifest.name.lower().replace(" ", "-").replace("_", "-")
            plugin_dir = self._plugins_dir / slug
            if not plugin_dir.exists():
                raise FileNotFoundError(f"Plugin directory not found: {plugin_dir}")

        plugin = LoadedPlugin(
            manifest=manifest,
            path=plugin_dir,
            checksum=_compute_checksum(plugin_dir),
        )

        # Load main module
        init_file = plugin_dir / "__init__.py"
        main_file = plugin_dir / "main.py"
        module_file = init_file if init_file.exists() else main_file if main_file.exists() else None

        if module_file:
            try:
                spec = importlib.util.spec_from_file_location(
                    f"zaseon_plugin_{manifest.name}",
                    module_file,
                )
                if spec and spec.loader:
                    module = importlib.util.module_from_spec(spec)
                    sys.modules[spec.name] = module
                    spec.loader.exec_module(module)
                    plugin.module = module
            except Exception as e:
                plugin.load_errors.append(f"Module load: {e}")
                logger.warning("Failed to load module for plugin '%s': %s", manifest.name, e)

        # Discover detectors
        detectors_dir = plugin_dir / "detectors"
        if manifest.provides_detectors and detectors_dir.exists():
            plugin.detectors = _discover_subclasses(detectors_dir, BaseDetector)

        # Discover mutation strategies
        mutations_dir = plugin_dir / "mutations"
        if manifest.provides_mutations and mutations_dir.exists():
            plugin.mutations = _discover_subclasses(mutations_dir, BaseMutationPlugin)

        # Register hooks
        hooks_dir = plugin_dir / "hooks"
        if hooks_dir.exists():
            _register_hooks(hooks_dir, manifest.hooks, plugin, self._hook_registry)
        elif plugin.module:
            # Check module-level hook registrations
            for hook_name in manifest.hooks:
                try:
                    hook = PluginHook(hook_name)
                    handler = getattr(plugin.module, f"on_{hook.value}", None)
                    if handler and callable(handler):
                        plugin.hook_handlers.setdefault(hook, []).append(handler)
                        self._hook_registry[hook].append(handler)
                except ValueError:
                    plugin.load_errors.append(f"Unknown hook: {hook_name}")

        self._plugins[manifest.name] = plugin
        logger.info(
            "Loaded plugin '%s': %d detectors, %d mutations, %d hooks",
            manifest.name,
            len(plugin.detectors),
            len(plugin.mutations),
            sum(len(v) for v in plugin.hook_handlers.values()),
        )
        return plugin

    def get_detectors(self) -> list[Type[BaseDetector]]:
        """Return all detector classes from loaded plugins."""
        detectors = []
        for plugin in self._plugins.values():
            if plugin.is_enabled:
                detectors.extend(plugin.detectors)
        return detectors

    def get_mutations(self) -> list[Type[BaseMutationPlugin]]:
        """Return all mutation strategy classes from loaded plugins."""
        mutations = []
        for plugin in self._plugins.values():
            if plugin.is_enabled:
                mutations.extend(plugin.mutations)
        return mutations

    async def fire_hook(self, hook: PluginHook, context: dict[str, Any]) -> dict[str, Any]:
        """Fire a lifecycle hook, chaining context through all handlers.

        Each handler receives the (potentially modified) context from the
        previous handler. Returns the final context.
        """
        for handler in self._hook_registry.get(hook, []):
            try:
                result = handler(context)
                if isinstance(result, dict):
                    context = result
            except Exception as e:
                logger.warning("Hook handler for %s failed: %s", hook.value, e)
        return context

    def unload_plugin(self, name: str) -> bool:
        """Unload a plugin and deregister its hooks."""
        plugin = self._plugins.pop(name, None)
        if not plugin:
            return False

        # Remove hooks
        for hook, handlers in plugin.hook_handlers.items():
            for handler in handlers:
                try:
                    self._hook_registry[hook].remove(handler)
                except ValueError:
                    pass

        # Remove module from sys.modules
        mod_name = f"zaseon_plugin_{name}"
        sys.modules.pop(mod_name, None)

        logger.info("Unloaded plugin '%s'", name)
        return True

    def enable_plugin(self, name: str) -> bool:
        if name in self._plugins:
            self._plugins[name].is_enabled = True
            return True
        return False

    def disable_plugin(self, name: str) -> bool:
        if name in self._plugins:
            self._plugins[name].is_enabled = False
            return True
        return False


# ── Helpers ──────────────────────────────────────────────────────────────────


def _parse_manifest(path: Path) -> PluginManifest:
    """Parse a plugin.yaml file into a PluginManifest."""
    with open(path) as f:
        data = yaml.safe_load(f)

    if not isinstance(data, dict):
        raise ValueError(f"Invalid plugin.yaml: expected mapping at {path}")

    return PluginManifest(
        name=data.get("name", path.parent.name),
        version=data.get("version", "0.0.0"),
        description=data.get("description", ""),
        author=data.get("author", ""),
        license=data.get("license", ""),
        min_engine_version=data.get("min_engine_version", "0.1.0"),
        max_engine_version=data.get("max_engine_version", ""),
        hooks=data.get("hooks", []),
        provides_detectors=data.get("provides_detectors", False),
        provides_mutations=data.get("provides_mutations", False),
        dependencies=data.get("dependencies", []),
        config_schema=data.get("config_schema", {}),
    )


def _compute_checksum(plugin_dir: Path) -> str:
    """Compute SHA-256 checksum of all Python files in a plugin directory."""
    hasher = hashlib.sha256()
    for py_file in sorted(plugin_dir.rglob("*.py")):
        hasher.update(py_file.read_bytes())
    return hasher.hexdigest()


def _discover_subclasses(
    directory: Path, base_class: type,
) -> list[type]:
    """Import all Python files in a directory and collect subclasses of base_class."""
    classes = []
    for py_file in sorted(directory.glob("*.py")):
        if py_file.name.startswith("_"):
            continue
        try:
            mod_name = f"zaseon_plugin_discovery_{py_file.stem}"
            spec = importlib.util.spec_from_file_location(mod_name, py_file)
            if spec and spec.loader:
                module = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(module)
                for attr_name in dir(module):
                    attr = getattr(module, attr_name)
                    if (
                        isinstance(attr, type)
                        and issubclass(attr, base_class)
                        and attr is not base_class
                    ):
                        classes.append(attr)
        except Exception as e:
            logger.warning("Failed to load %s: %s", py_file, e)
    return classes


def _register_hooks(
    hooks_dir: Path,
    hook_names: list[str],
    plugin: LoadedPlugin,
    registry: dict[PluginHook, list[Callable]],
) -> None:
    """Load hook handler files and register them."""
    for hook_name in hook_names:
        try:
            hook = PluginHook(hook_name)
        except ValueError:
            plugin.load_errors.append(f"Unknown hook: {hook_name}")
            continue

        handler_file = hooks_dir / f"{hook.value}.py"
        if not handler_file.exists():
            continue

        try:
            mod_name = f"zaseon_plugin_hook_{plugin.manifest.name}_{hook.value}"
            spec = importlib.util.spec_from_file_location(mod_name, handler_file)
            if spec and spec.loader:
                module = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(module)
                handler = getattr(module, "handle", None)
                if handler and callable(handler):
                    plugin.hook_handlers.setdefault(hook, []).append(handler)
                    registry[hook].append(handler)
        except Exception as e:
            plugin.load_errors.append(f"Hook {hook_name}: {e}")
