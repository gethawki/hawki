# File: tests/test_cov_chain_config.py
"""
Coverage for core.chain_config: per-chain lookups and the accessor helpers.
Pure dict logic, no I/O.
"""

import unittest

from hawki.core.chain_config import (
    CHAIN_CONFIG,
    get_chain_config,
    get_chain_id,
    get_default_rpc,
    get_explorer_api,
)


class TestChainConfig(unittest.TestCase):
    def test_get_chain_config_valid(self):
        cfg = get_chain_config("ethereum")
        self.assertEqual(cfg["chain_id"], 1)
        self.assertEqual(cfg["explorer_name"], "Etherscan")

    def test_get_chain_config_unknown_raises(self):
        with self.assertRaises(ValueError):
            get_chain_config("dogechain")

    def test_get_chain_id(self):
        self.assertEqual(get_chain_id("polygon"), 137)
        self.assertEqual(get_chain_id("arbitrum"), 42161)
        self.assertEqual(get_chain_id("local"), 31337)

    def test_get_default_rpc(self):
        self.assertEqual(get_default_rpc("base"), "https://mainnet.base.org")
        self.assertTrue(get_default_rpc("optimism").startswith("https://"))

    def test_get_explorer_api_present(self):
        self.assertEqual(get_explorer_api("bnb"), "https://api.bscscan.com/api")

    def test_get_explorer_api_none_for_local(self):
        self.assertIsNone(get_explorer_api("local"))

    def test_every_chain_has_required_keys(self):
        required = {"chain_id", "default_rpc", "explorer_api", "explorer_name", "name"}
        for chain, cfg in CHAIN_CONFIG.items():
            self.assertTrue(required.issubset(cfg.keys()), f"{chain} missing keys")
            self.assertIsInstance(cfg["chain_id"], int)


if __name__ == "__main__":
    unittest.main()
