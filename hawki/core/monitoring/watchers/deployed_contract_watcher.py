# --------------------
# File: hawki/core/monitoring/watchers/deployed_contract_watcher.py
# --------------------
"""
Watcher that monitors a deployed contract for code changes (via bytecode).

This watcher connects to a blockchain RPC endpoint and continuously monitors
the bytecode of a deployed smart contract.

If the contract bytecode changes (e.g., proxy upgrade, self-destruct + redeploy,
malicious replacement), the watcher emits an alert event.

Supports both legacy (Web3 v5/v6) and modern (Web3 v7+) middleware APIs.

Configuration Parameters:
    rpc_url (str)            → Blockchain RPC endpoint
    contract_address (str)  → Target contract address
    poa (bool, optional)    → Inject POA middleware (default: True)

Use Cases:
    • Proxy upgrade detection
    • Governance attack monitoring
    • Contract replacement alerts
    • Production security monitoring
"""

import logging
from typing import Any, Dict, Optional

from web3 import Web3

# -------------------------------------------------------------------
# POA Middleware Compatibility Layer
# Handles Web3 v5 → v7 import differences gracefully
# -------------------------------------------------------------------
try:
    # Web3 v6 and below
    from web3.middleware import geth_poa_middleware
    POA_MIDDLEWARE = geth_poa_middleware
except ImportError:
    # Web3 v7+
    from web3.middleware.proof_of_authority import ExtraDataToPOAMiddleware
    POA_MIDDLEWARE = ExtraDataToPOAMiddleware

from ..watcher_base import Watcher

logger = logging.getLogger(__name__)


class DeployedContractWatcher(Watcher):
    """
    Monitors a deployed smart contract for bytecode changes.

    Detection Method:
        Pulls contract bytecode via RPC and compares against
        previously stored state snapshot.

    Alert Trigger:
        Emits event if bytecode hash differs from last recorded value.
    """

    # -------------------------------------------------------------------
    # Initialization
    # -------------------------------------------------------------------
    def __init__(self, name: str, config: Dict[str, Any]):
        """
        Initialize deployed contract watcher.

        Args:
            name   → Watcher instance name
            config → Watcher configuration dictionary
        """
        super().__init__(name, config)

        # ---------------------------------------------------------------
        # Configuration Extraction
        # ---------------------------------------------------------------
        self.rpc_url: str = config.get("rpc_url", "http://localhost:8545")
        self.contract_address: Optional[str] = config.get("contract_address")
        self.enable_poa: bool = config.get("poa", True)

        if not self.contract_address:
            raise ValueError(
                "contract_address required for DeployedContractWatcher"
            )

        # ---------------------------------------------------------------
        # Web3 Connection Setup
        # ---------------------------------------------------------------
        self.w3 = Web3(Web3.HTTPProvider(self.rpc_url))

        # Inject POA middleware if enabled
        if self.enable_poa:
            try:
                self.w3.middleware_onion.inject(
                    POA_MIDDLEWARE,
                    layer=0
                )
                logger.debug(
                    "POA middleware injected successfully"
                )
            except Exception as e:
                logger.warning(
                    f"Failed to inject POA middleware: {e}"
                )

        # Validate RPC connectivity
        if not self.w3.is_connected():
            raise ConnectionError(
                f"Could not connect to RPC endpoint: {self.rpc_url}"
            )

        logger.info(
            f"Initialized DeployedContractWatcher → "
            f"{self.contract_address} @ {self.rpc_url}"
        )

    # -------------------------------------------------------------------
    # Core Monitoring Logic
    # -------------------------------------------------------------------
    def check(self) -> Optional[Dict[str, Any]]:
        """
        Check contract bytecode for changes.

        Returns:
            Event dictionary if change detected, else None.
        """
        try:
            # -----------------------------------------------------------
            # Fetch Current Bytecode
            # -----------------------------------------------------------
            checksum_address = Web3.to_checksum_address(
                self.contract_address
            )

            code_bytes = self.w3.eth.get_code(checksum_address)
            code_hex = code_bytes.hex()

            # -----------------------------------------------------------
            # Retrieve Previous State Snapshot
            # -----------------------------------------------------------
            previous_code = self.state.get("code_hash")

            # First observation → establish baseline
            if previous_code is None:
                self.state["code_hash"] = code_hex

                logger.debug(
                    f"Baseline bytecode stored for "
                    f"{self.contract_address}"
                )

                return None

            # -----------------------------------------------------------
            # Detect Bytecode Change
            # -----------------------------------------------------------
            if code_hex != previous_code:
                event = {
                    "type": "contract_code_change",
                    "contract_address": self.contract_address,
                    "rpc_url": self.rpc_url,
                    "previous_code_hash": previous_code[:12] + "...",
                    "new_code_hash": code_hex[:12] + "...",
                    "message": (
                        f"Contract {self.contract_address} "
                        f"bytecode changed"
                    ),
                }

                # Update stored state
                self.state["code_hash"] = code_hex

                logger.warning(
                    f"Bytecode change detected → "
                    f"{self.contract_address}"
                )

                return event

            # No change detected
            return None

        except Exception as e:
            logger.error(
                f"DeployedContractWatcher error: {e}"
            )
            return None


# EOF: hawki/core/monitoring/watchers/deployed_contract_watcher.py
