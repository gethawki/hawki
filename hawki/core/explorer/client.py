# File: hawki/core/explorer/client.py
"""
Generic explorer client for fetching verified source code from EVM block explorers.
Supports multiple chains via chain-specific API endpoints.
"""

import logging
from typing import Any, Dict, Optional

import requests

logger = logging.getLogger(__name__)

class ExplorerClient:
    """Client for block explorers (Etherscan, Polygonscan, Arbiscan, etc.)."""

    def __init__(self, chain: str, api_key: Optional[str] = None):
        from ..chain_config import get_explorer_api
        self.api_url = get_explorer_api(chain)
        if not self.api_url:
            raise ValueError(f"No explorer API available for chain: {chain}")
        self.api_key = api_key or ""
        self.chain = chain

    def get_contract_source(self, address: str) -> Optional[Dict[str, Any]]:
        """
        Fetch verified source code for a contract address.
        Returns a dict with source code and metadata, or None if not verified.
        """
        params = {
            "module": "contract",
            "action": "getsourcecode",
            "address": address,
            "apikey": self.api_key,
        }
        try:
            resp = requests.get(self.api_url, params=params, timeout=30)
            resp.raise_for_status()
            data = resp.json()
            if data.get("status") != "1":
                logger.warning(f"Explorer returned error: {data.get('message', 'Unknown')}")
                return None
            result = data.get("result", [])
            if not result:
                return None
            contract_data = result[0]
            if contract_data.get("SourceCode") == "":
                return None
            return contract_data
        except Exception as e:
            logger.error(f"Failed to fetch contract source from explorer ({self.chain}): {e}")
            return None
# EOF
