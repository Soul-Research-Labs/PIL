"""Solidity compiler integration for smart contract analysis."""

from __future__ import annotations

import json
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


@dataclass
class CompilationResult:
    """Result of compiling Solidity source code."""

    success: bool
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    contracts: dict[str, "CompiledContract"] = field(default_factory=dict)
    sources_ast: dict[str, Any] = field(default_factory=dict)


@dataclass
class CompiledContract:
    """A single compiled contract."""

    name: str
    abi: list[dict[str, Any]] = field(default_factory=list)
    bytecode: str = ""
    deployed_bytecode: str = ""
    storage_layout: dict[str, Any] = field(default_factory=dict)
    ast: dict[str, Any] = field(default_factory=dict)
    method_identifiers: dict[str, str] = field(default_factory=dict)


class SolidityCompiler:
    """Compile Solidity source code using solc."""

    def __init__(self, version: str | None = None) -> None:
        self.version = version

    def compile_source(
        self,
        source_code: str,
        filename: str = "Contract.sol",
        optimization: bool = True,
        optimization_runs: int = 200,
    ) -> CompilationResult:
        """Compile Solidity source code and return AST + ABI + bytecode.

        Args:
            source_code: Solidity source code string
            filename: Name for the source file
            optimization: Whether to enable optimizer
            optimization_runs: Number of optimization runs

        Returns:
            CompilationResult with AST, ABI, bytecode per contract
        """
        try:
            import solcx

            # Ensure the compiler version is installed
            if self.version:
                solcx.install_solc(self.version)
                solc_version = self.version
            else:
                # Try to detect version from pragma
                solc_version = self._detect_version(source_code)
                if solc_version:
                    solcx.install_solc(solc_version)
                else:
                    installed = solcx.get_installed_solc_versions()
                    if installed:
                        solc_version = str(installed[0])
                    else:
                        solcx.install_solc("0.8.28")
                        solc_version = "0.8.28"

            # Build standard JSON input
            standard_input = {
                "language": "Solidity",
                "sources": {
                    filename: {"content": source_code}
                },
                "settings": {
                    "optimizer": {
                        "enabled": optimization,
                        "runs": optimization_runs,
                    },
                    "outputSelection": {
                        "*": {
                            "*": [
                                "abi",
                                "evm.bytecode.object",
                                "evm.deployedBytecode.object",
                                "evm.methodIdentifiers",
                                "storageLayout",
                            ],
                            "": ["ast"],
                        }
                    },
                },
            }

            output = solcx.compile_standard(
                standard_input,
                solc_version=solc_version,
                allow_paths=".",
            )

            return self._parse_output(output)

        except Exception as e:
            return CompilationResult(
                success=False,
                errors=[str(e)],
            )

    def compile_files(
        self,
        source_files: dict[str, str],
        optimization: bool = True,
        optimization_runs: int = 200,
    ) -> CompilationResult:
        """Compile multiple Solidity source files.

        Args:
            source_files: Mapping of filename -> source code
            optimization: Whether to enable optimizer
            optimization_runs: Number of optimization runs

        Returns:
            CompilationResult
        """
        try:
            import solcx

            solc_version = None
            for source in source_files.values():
                solc_version = self._detect_version(source)
                if solc_version:
                    break

            if not solc_version:
                solc_version = "0.8.28"

            solcx.install_solc(solc_version)

            standard_input = {
                "language": "Solidity",
                "sources": {
                    name: {"content": code} for name, code in source_files.items()
                },
                "settings": {
                    "optimizer": {
                        "enabled": optimization,
                        "runs": optimization_runs,
                    },
                    "outputSelection": {
                        "*": {
                            "*": [
                                "abi",
                                "evm.bytecode.object",
                                "evm.deployedBytecode.object",
                                "evm.methodIdentifiers",
                                "storageLayout",
                            ],
                            "": ["ast"],
                        }
                    },
                },
            }

            output = solcx.compile_standard(
                standard_input,
                solc_version=solc_version,
                allow_paths=".",
            )

            return self._parse_output(output)

        except Exception as e:
            return CompilationResult(
                success=False,
                errors=[str(e)],
            )

    def _parse_output(self, output: dict[str, Any]) -> CompilationResult:
        """Parse solc standard JSON output into CompilationResult."""
        errors: list[str] = []
        warnings: list[str] = []
        contracts: dict[str, CompiledContract] = {}
        sources_ast: dict[str, Any] = {}

        # Collect errors and warnings
        for error in output.get("errors", []):
            if error.get("severity") == "error":
                errors.append(error.get("formattedMessage", error.get("message", "")))
            else:
                warnings.append(error.get("formattedMessage", error.get("message", "")))

        # Extract ASTs
        for source_name, source_data in output.get("sources", {}).items():
            sources_ast[source_name] = source_data.get("ast", {})

        # Extract compiled contracts
        for source_name, file_contracts in output.get("contracts", {}).items():
            for contract_name, contract_data in file_contracts.items():
                evm = contract_data.get("evm", {})
                contracts[f"{source_name}:{contract_name}"] = CompiledContract(
                    name=contract_name,
                    abi=contract_data.get("abi", []),
                    bytecode=evm.get("bytecode", {}).get("object", ""),
                    deployed_bytecode=evm.get("deployedBytecode", {}).get("object", ""),
                    storage_layout=contract_data.get("storageLayout", {}),
                    ast=sources_ast.get(source_name, {}),
                    method_identifiers=evm.get("methodIdentifiers", {}),
                )

        return CompilationResult(
            success=len(errors) == 0,
            errors=errors,
            warnings=warnings,
            contracts=contracts,
            sources_ast=sources_ast,
        )

    @staticmethod
    def _detect_version(source_code: str) -> str | None:
        """Detect Solidity compiler version from pragma statement."""
        import re

        match = re.search(r"pragma\s+solidity\s+[\^~>=<]*\s*([\d.]+)", source_code)
        if match:
            return match.group(1)
        return None
