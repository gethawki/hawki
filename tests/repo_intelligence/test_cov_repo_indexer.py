# --------------------
# File: tests/repo_intelligence/test_cov_repo_indexer.py
# --------------------
"""
Coverage tests for RepositoryIndexer.

Local indexing runs for REAL against tmp dirs holding small .sol files
(the parser is local and safe). Every network path -- remote git clone,
from_contract RPC / explorer -- is fully mocked; no real network, git,
or RPC is ever touched.
"""

import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

from hawki.core.repo_intelligence.indexer import RepositoryIndexer

SIMPLE_SOL = """
pragma solidity ^0.8.0;
contract Sample {
    uint256 public value;
    function setValue(uint256 v) public { value = v; }
}
"""


class TestIndexerLocal(unittest.TestCase):
    def setUp(self):
        self.indexer = RepositoryIndexer()

    def test_index_local_directory(self, tmp=None):
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            (Path(d) / "Sample.sol").write_text(SIMPLE_SOL)
            result = self.indexer.index(d)
            self.assertEqual(result["type"], "local")
            self.assertEqual(result["path"], str(Path(d)))
            self.assertEqual(len(result["contracts"]), 1)
            self.assertEqual(result["contracts"][0]["contracts"][0]["name"], "Sample")

    def test_index_local_recurses_subdirs(self):
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            sub = Path(d) / "nested" / "deep"
            sub.mkdir(parents=True)
            (sub / "A.sol").write_text(SIMPLE_SOL)
            (Path(d) / "B.sol").write_text(SIMPLE_SOL)
            result = self.indexer.index(d)
            self.assertEqual(len(result["contracts"]), 2)

    def test_index_empty_directory(self):
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            result = self.indexer.index(d)
            self.assertEqual(result["type"], "local")
            self.assertEqual(result["contracts"], [])

    def test_index_non_directory_raises(self):
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            f = Path(d) / "not_a_dir.sol"
            f.write_text(SIMPLE_SOL)
            with self.assertRaises(ValueError):
                self.indexer.index(str(f))


class TestIndexerRemote(unittest.TestCase):
    def setUp(self):
        self.indexer = RepositoryIndexer()

    @patch("hawki.core.repo_intelligence.indexer.git")
    def test_index_remote_clones_and_scans(self, mock_git):
        def fake_clone(url, dest):
            (Path(dest) / "Cloned.sol").write_text(SIMPLE_SOL)

        mock_git.Repo.clone_from.side_effect = fake_clone
        result = self.indexer.index("https://github.com/example/repo.git")
        self.assertEqual(result["type"], "remote")
        self.assertEqual(result["url"], "https://github.com/example/repo.git")
        self.assertEqual(len(result["contracts"]), 1)
        mock_git.Repo.clone_from.assert_called_once()
        # temp dir exists until cleanup.
        self.assertTrue(Path(result["path"]).exists())
        self.indexer.cleanup()
        self.assertFalse(Path(result["path"]).exists())

    @patch("hawki.core.repo_intelligence.indexer.git")
    def test_index_remote_clone_failure_raises(self, mock_git):
        mock_git.Repo.clone_from.side_effect = Exception("network down")
        with self.assertRaises(RuntimeError):
            self.indexer.index("https://github.com/example/repo.git")

    def test_cleanup_is_safe_when_no_temp_dir(self):
        # No remote clone happened -> _temp_dir is None -> cleanup is a no-op.
        self.indexer.cleanup()
        self.assertIsNone(self.indexer._temp_dir)


class TestIndexerFromContract(unittest.TestCase):
    def setUp(self):
        self.indexer = RepositoryIndexer()

    def test_invalid_address_raises(self):
        # Uses the real Web3.is_address -> False -> ValueError, no network.
        with self.assertRaises(ValueError):
            self.indexer.from_contract("not-an-address")

    def _patched(self):
        """Return an ExitStack-style set of patches for from_contract."""
        patches = {
            "web3": patch("hawki.core.repo_intelligence.indexer.Web3"),
            "explorer": patch("hawki.core.repo_intelligence.indexer.ExplorerClient"),
            "chain": patch("hawki.core.repo_intelligence.indexer.get_chain_config"),
            "analyze": patch("hawki.core.repo_intelligence.indexer.analyze_bytecode"),
        }
        started = {k: p.start() for k, p in patches.items()}
        self.addCleanup(lambda: [p.stop() for p in patches.values()])

        # Chain config
        started["chain"].return_value = {
            "default_rpc": "http://localhost:8545",
            "chain_id": 1,
        }
        # Web3 static + instance behavior
        web3 = started["web3"]
        web3.is_address.return_value = True
        web3.to_checksum_address.side_effect = lambda a: a
        w3_instance = MagicMock()
        w3_instance.is_connected.return_value = True
        w3_instance.eth.get_code.return_value = b"\x60\x60\x60"
        web3.return_value = w3_instance
        return started, w3_instance

    def test_from_contract_verified_single_file(self):
        started, _ = self._patched()
        explorer_instance = started["explorer"].return_value
        explorer_instance.get_contract_source.return_value = {
            "SourceCode": "pragma solidity ^0.8.0;\ncontract Verified { function f() public {} }",
            "ContractName": "Verified",
        }
        result = self.indexer.from_contract("0x" + "ab" * 20, chain="ethereum")
        self.assertEqual(result["type"], "deployed")
        self.assertTrue(result["source_available"])
        self.assertTrue(result["verified_source"])
        self.assertEqual(result["source_type"], "verified_single")
        # Real parser ran over the fetched source.
        names = [c["name"] for pc in result["contracts"] for c in pc["contracts"]]
        self.assertIn("Verified", names)

    def test_from_contract_verified_multifile(self):
        started, _ = self._patched()
        explorer_instance = started["explorer"].return_value
        multifile_json = (
            '{"sources": {"contracts/Multi.sol": '
            '{"content": "pragma solidity ^0.8.0;\\ncontract Multi { function g() external {} }"}}}'
        )
        explorer_instance.get_contract_source.return_value = {
            "SourceCode": multifile_json,
            "ContractName": "Multi",
        }
        result = self.indexer.from_contract("0x" + "cd" * 20)
        self.assertTrue(result["source_available"])
        self.assertEqual(result["source_type"], "verified_multifile")
        names = [c["name"] for pc in result["contracts"] for c in pc["contracts"]]
        self.assertIn("Multi", names)

    def test_from_contract_no_source_runs_bytecode_analysis(self):
        started, _ = self._patched()
        started["explorer"].return_value.get_contract_source.return_value = None
        started["analyze"].return_value = [{"title": "suspicious opcode"}]
        result = self.indexer.from_contract("0x" + "ef" * 20)
        self.assertFalse(result["source_available"])
        self.assertEqual(result["bytecode_findings"], [{"title": "suspicious opcode"}])
        started["analyze"].assert_called_once()

    def test_from_contract_user_provided_source_overrides(self):
        started, _ = self._patched()
        started["explorer"].return_value.get_contract_source.return_value = None
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            (Path(d) / "User.sol").write_text(SIMPLE_SOL)
            result = self.indexer.from_contract(
                "0x" + "12" * 20, source_path=Path(d)
            )
        self.assertTrue(result["source_available"])
        self.assertEqual(result["source_type"], "user_provided")
        names = [c["name"] for pc in result["contracts"] for c in pc["contracts"]]
        self.assertIn("Sample", names)

    def test_from_contract_not_connected_raises(self):
        started, w3_instance = self._patched()
        w3_instance.is_connected.return_value = False
        with self.assertRaises(ConnectionError):
            self.indexer.from_contract("0x" + "34" * 20)

    def test_from_contract_empty_bytecode_raises(self):
        started, w3_instance = self._patched()
        w3_instance.eth.get_code.return_value = b""
        with self.assertRaises(ValueError):
            self.indexer.from_contract("0x" + "56" * 20)


if __name__ == "__main__":
    unittest.main()
