# File: hawki/core/chain_config.py
"""
Chain configuration for EVM-compatible blockchains.
Provides chain IDs, default RPC endpoints, explorer API URLs, and chain names.
"""

from typing import Optional

CHAIN_CONFIG = {
    "ethereum": {
        "chain_id": 1,
        "default_rpc": "https://eth.llamarpc.com",
        "explorer_api": "https://api.etherscan.io/api",
        "explorer_name": "Etherscan",
        "name": "Ethereum Mainnet",
    },
    "polygon": {
        "chain_id": 137,
        "default_rpc": "https://polygon.llamarpc.com",
        "explorer_api": "https://api.polygonscan.com/api",
        "explorer_name": "Polygonscan",
        "name": "Polygon Mainnet",
    },
    "arbitrum": {
        "chain_id": 42161,
        "default_rpc": "https://arbitrum.llamarpc.com",
        "explorer_api": "https://api.arbiscan.io/api",
        "explorer_name": "Arbiscan",
        "name": "Arbitrum One",
    },
    "optimism": {
        "chain_id": 10,
        "default_rpc": "https://optimism.llamarpc.com",
        "explorer_api": "https://api-optimistic.etherscan.io/api",
        "explorer_name": "Optimism Explorer",
        "name": "Optimism",
    },
    "base": {
        "chain_id": 8453,
        "default_rpc": "https://mainnet.base.org",
        "explorer_api": "https://api.basescan.org/api",
        "explorer_name": "Basescan",
        "name": "Base Mainnet",
    },
    "bnb": {
        "chain_id": 56,
        "default_rpc": "https://binance.nodereal.io",
        "explorer_api": "https://api.bscscan.com/api",
        "explorer_name": "BscScan",
        "name": "BNB Smart Chain",
    },
    "avalanche": {
        "chain_id": 43114,
        "default_rpc": "https://avalanche-c-chain.publicnode.com",
        "explorer_api": "https://api.snowtrace.io/api",
        "explorer_name": "Snowtrace",
        "name": "Avalanche C-Chain",
    },
    "sepolia": {
        "chain_id": 11155111,
        "default_rpc": "https://sepolia.gateway.tenderly.co",
        "explorer_api": "https://api-sepolia.etherscan.io/api",
        "explorer_name": "Etherscan (Sepolia)",
        "name": "Sepolia Testnet",
    },
    "local": {
        "chain_id": 31337,
        "default_rpc": "http://localhost:8545",
        "explorer_api": None,
        "explorer_name": None,
        "name": "Local (Anvil/Hardhat)",
    },
}

def get_chain_config(chain: str) -> dict:
    if chain not in CHAIN_CONFIG:
        raise ValueError(f"Unknown chain: {chain}. Supported: {list(CHAIN_CONFIG.keys())}")
    return CHAIN_CONFIG[chain]

def get_chain_id(chain: str) -> int:
    return get_chain_config(chain)["chain_id"]

def get_default_rpc(chain: str) -> str:
    return get_chain_config(chain)["default_rpc"]

def get_explorer_api(chain: str) -> Optional[str]:
    return get_chain_config(chain).get("explorer_api")
# EOF
