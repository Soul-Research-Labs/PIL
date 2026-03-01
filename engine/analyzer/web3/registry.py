"""Detector registry — discovers and loads all available detectors."""

from __future__ import annotations

import importlib
import pkgutil
from typing import Type

from engine.analyzer.web3.base_detector import BaseDetector


class DetectorRegistry:
    """Registry for all smart contract vulnerability detectors.

    Discovers detectors from the `detectors` package and provides
    methods to list, filter, and instantiate them.
    """

    def __init__(self) -> None:
        self._detectors: dict[str, Type[BaseDetector]] = {}
        self._loaded = False

    def discover(self) -> None:
        """Auto-discover all detector classes from the detectors package."""
        if self._loaded:
            return

        import engine.analyzer.web3.detectors as detectors_pkg

        for _finder, module_name, _is_pkg in pkgutil.walk_packages(
            detectors_pkg.__path__,
            prefix=detectors_pkg.__name__ + ".",
        ):
            try:
                module = importlib.import_module(module_name)
                for attr_name in dir(module):
                    attr = getattr(module, attr_name)
                    if (
                        isinstance(attr, type)
                        and issubclass(attr, BaseDetector)
                        and attr is not BaseDetector
                        and attr.DETECTOR_ID  # Must have an ID
                    ):
                        self._detectors[attr.DETECTOR_ID] = attr
            except Exception as e:
                print(f"Warning: Failed to load detector module {module_name}: {e}")

        self._loaded = True

    def get_all(self) -> list[Type[BaseDetector]]:
        """Return all registered detector classes."""
        self.discover()
        return list(self._detectors.values())

    def get_by_id(self, detector_id: str) -> Type[BaseDetector] | None:
        """Get a specific detector by its ID."""
        self.discover()
        return self._detectors.get(detector_id)

    def get_by_category(self, category: str) -> list[Type[BaseDetector]]:
        """Get all detectors in a given category."""
        self.discover()
        return [d for d in self._detectors.values() if d.CATEGORY == category]

    def get_by_scwe(self, scwe_id: str) -> list[Type[BaseDetector]]:
        """Get all detectors for a given SCWE ID."""
        self.discover()
        return [d for d in self._detectors.values() if d.SCWE_ID == scwe_id]

    def count(self) -> int:
        """Return the total number of registered detectors."""
        self.discover()
        return len(self._detectors)

    def categories(self) -> list[str]:
        """Return all unique detector categories."""
        self.discover()
        return sorted(set(d.CATEGORY for d in self._detectors.values() if d.CATEGORY))


# Global registry singleton
registry = DetectorRegistry()
