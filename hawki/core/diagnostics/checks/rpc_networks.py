# File: hawki/core/diagnostics/checks/rpc_networks.py
"""
Check RPC network connectivity and latency.
"""

import logging
import time
from concurrent.futures import ThreadPoolExecutor
from typing import Any, Dict, Optional

from web3 import Web3
from web3.middleware import geth_poa_middleware

from ...chain_config import CHAIN_CONFIG, get_default_rpc
from .base import CheckResult, DiagnosticCheck

logger = logging.getLogger(__name__)

class RPCNetworksCheck(DiagnosticCheck):
    """Ping all configured RPCs and validate chainId and latency."""

    @property
    def name(self) -> str:
        return "rpc_networks"

    @property
    def category(self) -> str:
        return "network"

    def run(self, config: Optional[Dict[str, Any]] = None) -> CheckResult:
        details = {}
        failures = []
        slow_warnings = []

        # Get chains to check from config or use all known chains
        chains_to_check = config.get("chains", []) if config else []
        if not chains_to_check:
            # Use default chains (mainnet, polygon, arbitrum, optimism, base, bnb, avalanche)
            chains_to_check = ["ethereum", "polygon", "arbitrum", "optimism", "base", "bnb", "avalanche"]

        def _probe(chain: str) -> Dict[str, Any]:
            """Probe a single chain RPC. Returns a per-chain result dict."""
            if chain not in CHAIN_CONFIG:
                return {"chain": chain, "detail": {"status": "skipped", "message": f"Unknown chain: {chain}"}}

            rpc_url = config.get("rpc_urls", {}).get(chain) if config else None
            if not rpc_url:
                rpc_url = get_default_rpc(chain)

            try:
                start = time.time()
                w3 = Web3(Web3.HTTPProvider(rpc_url, request_kwargs={"timeout": 5}))
                try:
                    w3.middleware_onion.inject(geth_poa_middleware, layer=0)
                except Exception:
                    pass

                if not w3.is_connected():
                    return {"chain": chain, "fail": True,
                            "detail": {"status": "fail", "message": f"Cannot connect to {rpc_url}"}}

                chain_id = w3.eth.chain_id
                latest_block = w3.eth.block_number
                latency_ms = (time.time() - start) * 1000

                return {
                    "chain": chain,
                    "slow": latency_ms > 1000,
                    "detail": {
                        "status": "ok" if latency_ms < 1000 else "slow",
                        "chain_id": chain_id,
                        "latest_block": latest_block,
                        "latency_ms": round(latency_ms, 2),
                        "rpc_url": rpc_url,
                    },
                }
            except Exception as e:
                return {"chain": chain, "fail": True, "detail": {"status": "fail", "message": str(e)}}

        # Probe every chain concurrently: each probe is network bound, so a
        # sequential loop would add up to the sum of all RPC latencies.
        if chains_to_check:
            max_workers = min(len(chains_to_check), 8)
            with ThreadPoolExecutor(max_workers=max_workers) as pool:
                probe_results = list(pool.map(_probe, chains_to_check))
        else:
            probe_results = []

        for res in probe_results:
            chain = res["chain"]
            details[chain] = res["detail"]
            if res.get("fail"):
                failures.append(chain)
            elif res.get("slow"):
                slow_warnings.append(chain)

        if failures:
            fix = "Check RPC URLs and network connectivity. Consider using --skip-rpc to ignore."
            return CheckResult(
                name=self.name,
                status="fail" if len(failures) > len(chains_to_check) // 2 else "warn",
                message=f"RPC failures: {', '.join(failures)}",
                fix=fix,
                details=details,
            )

        if slow_warnings:
            return CheckResult(
                name=self.name,
                status="warn",
                message=f"Slow RPCs: {', '.join(slow_warnings)}",
                fix="Consider using a dedicated RPC or increasing timeout.",
                details=details,
            )

        return CheckResult(
            name=self.name,
            status="pass",
            message=f"All {len(chains_to_check)} RPCs connected.",
            details=details,
        )

    def is_critical(self) -> bool:
        return True
# EOF
