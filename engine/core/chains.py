"""Supported EVM chain configurations."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class ChainConfig:
    """Configuration for a supported EVM chain."""

    chain_id: int
    name: str
    short_name: str
    rpc_url_template: str  # Use {api_key} placeholder
    explorer_url: str
    explorer_api_url: str
    explorer_api_key_env: str
    native_currency: str = "ETH"
    is_testnet: bool = False


# ── Chain Registry ───────────────────────────────────────────────────────────

CHAINS: dict[str, ChainConfig] = {
    "ethereum": ChainConfig(
        chain_id=1,
        name="Ethereum Mainnet",
        short_name="eth",
        rpc_url_template="https://eth-mainnet.g.alchemy.com/v2/{api_key}",
        explorer_url="https://etherscan.io",
        explorer_api_url="https://api.etherscan.io/api",
        explorer_api_key_env="ZASEON_ETHERSCAN_API_KEY",
    ),
    "polygon": ChainConfig(
        chain_id=137,
        name="Polygon Mainnet",
        short_name="matic",
        rpc_url_template="https://polygon-mainnet.g.alchemy.com/v2/{api_key}",
        explorer_url="https://polygonscan.com",
        explorer_api_url="https://api.polygonscan.com/api",
        explorer_api_key_env="ZASEON_POLYGONSCAN_API_KEY",
        native_currency="MATIC",
    ),
    "bsc": ChainConfig(
        chain_id=56,
        name="BNB Smart Chain",
        short_name="bsc",
        rpc_url_template="https://bsc-dataseed.binance.org",
        explorer_url="https://bscscan.com",
        explorer_api_url="https://api.bscscan.com/api",
        explorer_api_key_env="ZASEON_BSCSCAN_API_KEY",
        native_currency="BNB",
    ),
    "avalanche": ChainConfig(
        chain_id=43114,
        name="Avalanche C-Chain",
        short_name="avax",
        rpc_url_template="https://api.avax.network/ext/bc/C/rpc",
        explorer_url="https://snowtrace.io",
        explorer_api_url="https://api.snowtrace.io/api",
        explorer_api_key_env="ZASEON_SNOWTRACE_API_KEY",
        native_currency="AVAX",
    ),
    "arbitrum": ChainConfig(
        chain_id=42161,
        name="Arbitrum One",
        short_name="arb",
        rpc_url_template="https://arb-mainnet.g.alchemy.com/v2/{api_key}",
        explorer_url="https://arbiscan.io",
        explorer_api_url="https://api.arbiscan.io/api",
        explorer_api_key_env="ZASEON_ARBISCAN_API_KEY",
    ),
    "optimism": ChainConfig(
        chain_id=10,
        name="Optimism",
        short_name="op",
        rpc_url_template="https://opt-mainnet.g.alchemy.com/v2/{api_key}",
        explorer_url="https://optimistic.etherscan.io",
        explorer_api_url="https://api-optimistic.etherscan.io/api",
        explorer_api_key_env="ZASEON_OPTIMISM_API_KEY",
    ),
    "base": ChainConfig(
        chain_id=8453,
        name="Base",
        short_name="base",
        rpc_url_template="https://base-mainnet.g.alchemy.com/v2/{api_key}",
        explorer_url="https://basescan.org",
        explorer_api_url="https://api.basescan.org/api",
        explorer_api_key_env="ZASEON_BASESCAN_API_KEY",
    ),
    "zksync": ChainConfig(
        chain_id=324,
        name="zkSync Era",
        short_name="zksync",
        rpc_url_template="https://mainnet.era.zksync.io",
        explorer_url="https://explorer.zksync.io",
        explorer_api_url="https://block-explorer-api.mainnet.zksync.io/api",
        explorer_api_key_env="",
    ),
    "linea": ChainConfig(
        chain_id=59144,
        name="Linea",
        short_name="linea",
        rpc_url_template="https://linea-mainnet.infura.io/v3/{api_key}",
        explorer_url="https://lineascan.build",
        explorer_api_url="https://api.lineascan.build/api",
        explorer_api_key_env="ZASEON_LINEASCAN_API_KEY",
    ),
    "fantom": ChainConfig(
        chain_id=250,
        name="Fantom Opera",
        short_name="ftm",
        rpc_url_template="https://rpc.ftm.tools",
        explorer_url="https://ftmscan.com",
        explorer_api_url="https://api.ftmscan.com/api",
        explorer_api_key_env="ZASEON_FTMSCAN_API_KEY",
        native_currency="FTM",
    ),
    "gnosis": ChainConfig(
        chain_id=100,
        name="Gnosis Chain",
        short_name="gno",
        rpc_url_template="https://rpc.gnosischain.com",
        explorer_url="https://gnosisscan.io",
        explorer_api_url="https://api.gnosisscan.io/api",
        explorer_api_key_env="ZASEON_GNOSISSCAN_API_KEY",
        native_currency="xDAI",
    ),
    "scroll": ChainConfig(
        chain_id=534352,
        name="Scroll",
        short_name="scroll",
        rpc_url_template="https://rpc.scroll.io",
        explorer_url="https://scrollscan.com",
        explorer_api_url="https://api.scrollscan.com/api",
        explorer_api_key_env="ZASEON_SCROLLSCAN_API_KEY",
    ),
}


def get_chain_config(chain_name: str) -> ChainConfig | None:
    """Get chain configuration by name."""
    return CHAINS.get(chain_name.lower())


def get_all_chains() -> list[ChainConfig]:
    """Return all supported chains."""
    return list(CHAINS.values())
