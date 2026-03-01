"""Fetch verified smart contract source code from block explorers."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any

import httpx

from engine.core.chains import ChainConfig, get_chain_config
from engine.core.config import get_settings


@dataclass
class ContractSource:
    """Fetched contract source code and metadata."""

    address: str
    chain: str
    contract_name: str = ""
    compiler_version: str = ""
    optimization_used: bool = False
    optimization_runs: int = 200
    evm_version: str = ""
    source_code: str = ""
    abi: list[dict[str, Any]] = field(default_factory=list)
    constructor_arguments: str = ""
    is_proxy: bool = False
    implementation_address: str = ""
    # Multi-file sources (Solidity standard JSON input)
    source_files: dict[str, str] = field(default_factory=dict)
    license_type: str = ""


class ContractFetcher:
    """Fetch verified contract source code from block explorer APIs."""

    def __init__(self) -> None:
        self.settings = get_settings()
        self._client = httpx.AsyncClient(timeout=30.0)

    async def fetch_contract_source(
        self,
        address: str,
        chain: str,
    ) -> ContractSource:
        """Fetch verified source code for a contract from its block explorer.

        Args:
            address: Contract address (0x...)
            chain: Chain identifier (e.g., 'ethereum', 'polygon')

        Returns:
            ContractSource with source code and metadata

        Raises:
            ValueError: If chain is unsupported, address is invalid, or contract is not verified
        """
        # Validate Ethereum address format
        import re
        if not re.match(r'^0x[0-9a-fA-F]{40}$', address):
            raise ValueError(f"Invalid contract address format: {address}")

        chain_config = get_chain_config(chain)
        if not chain_config:
            raise ValueError(f"Unsupported chain: {chain}")

        api_key = self._get_api_key(chain_config)

        # Etherscan-compatible API call
        params = {
            "module": "contract",
            "action": "getsourcecode",
            "address": address,
        }
        if api_key:
            params["apikey"] = api_key

        response = await self._client.get(chain_config.explorer_api_url, params=params)
        response.raise_for_status()
        data = response.json()

        if data.get("status") != "1" or not data.get("result"):
            raise ValueError(
                f"Contract not verified or not found at {address} on {chain}"
            )

        result = data["result"][0]
        source_code = result.get("SourceCode", "")
        source_files: dict[str, str] = {}

        # Handle Solidity standard JSON input (double-wrapped in braces)
        if source_code.startswith("{{"):
            try:
                json_input = json.loads(source_code[1:-1])
                sources = json_input.get("sources", {})
                source_files = {
                    name: src.get("content", "")
                    for name, src in sources.items()
                }
                # Use the main source as the flat source_code
                if source_files:
                    source_code = "\n\n".join(source_files.values())
            except json.JSONDecodeError:
                pass
        elif source_code.startswith("{"):
            try:
                json_input = json.loads(source_code)
                sources = json_input.get("sources", {})
                source_files = {
                    name: src.get("content", "")
                    for name, src in sources.items()
                }
                if source_files:
                    source_code = "\n\n".join(source_files.values())
            except json.JSONDecodeError:
                pass

        # Parse ABI
        abi: list[dict[str, Any]] = []
        try:
            abi = json.loads(result.get("ABI", "[]"))
        except json.JSONDecodeError:
            pass

        # Detect proxy
        implementation = result.get("Implementation", "")
        is_proxy = bool(implementation)

        return ContractSource(
            address=address,
            chain=chain,
            contract_name=result.get("ContractName", ""),
            compiler_version=result.get("CompilerVersion", ""),
            optimization_used=result.get("OptimizationUsed", "0") == "1",
            optimization_runs=int(result.get("Runs", 200)),
            evm_version=result.get("EVMVersion", ""),
            source_code=source_code,
            abi=abi,
            constructor_arguments=result.get("ConstructorArguments", ""),
            is_proxy=is_proxy,
            implementation_address=implementation,
            source_files=source_files,
            license_type=result.get("LicenseType", ""),
        )

    async def fetch_proxy_implementation(
        self,
        contract: ContractSource,
    ) -> ContractSource | None:
        """If the contract is a proxy, also fetch the implementation source."""
        if not contract.is_proxy or not contract.implementation_address:
            return None
        return await self.fetch_contract_source(
            contract.implementation_address,
            contract.chain,
        )

    def _get_api_key(self, chain_config: ChainConfig) -> str:
        """Resolve the API key for a chain's explorer."""
        import os
        if chain_config.explorer_api_key_env:
            return os.environ.get(chain_config.explorer_api_key_env, "")
        return ""

    async def close(self) -> None:
        """Close the HTTP client."""
        await self._client.aclose()
