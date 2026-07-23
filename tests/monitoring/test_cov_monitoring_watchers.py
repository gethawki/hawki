# --------------------
# File: tests/monitoring/test_cov_monitoring_watchers.py
# --------------------
"""
Coverage tests for the individual watcher implementations.

All git / web3 / RPC access is mocked -- there are no skip guards in this
suite, so any real network/git call would fail, not skip.
"""

import unittest
from unittest.mock import MagicMock, patch

from hawki.core.monitoring.watchers.ci_cd_watcher import CICDWatcher
from hawki.core.monitoring.watchers.deployed_contract_watcher import (
    DeployedContractWatcher,
)
from hawki.core.monitoring.watchers.repo_commit_watcher import RepoCommitWatcher
from hawki.core.monitoring.watchers.vulnerability_event_watcher import (
    VulnerabilityEventWatcher,
)


class TestPlaceholderWatchers(unittest.TestCase):
    def test_cicd_watcher_check_returns_none(self):
        w = CICDWatcher(name="cicdwatcher", config={})
        self.assertIsNone(w.check())
        self.assertEqual(w.get_id(), "CICDWatcher:cicdwatcher")

    def test_vulnerability_watcher_check_returns_none(self):
        w = VulnerabilityEventWatcher(name="vulnerabilityeventwatcher", config={})
        self.assertIsNone(w.check())

    def test_inherited_state_roundtrip(self):
        w = CICDWatcher(name="cicdwatcher", config={})
        w.load_state({"seen": 3})
        self.assertEqual(w.save_state(), {"seen": 3})


@patch("hawki.core.monitoring.watchers.repo_commit_watcher.git")
class TestRepoCommitWatcher(unittest.TestCase):
    def _watcher(self, tmp_path="/tmp/some_repo"):
        return RepoCommitWatcher(
            name="repocommitwatcher",
            config={"repo_path": tmp_path, "branch": "main"},
        )

    def test_not_a_git_repo_returns_none(self, mock_git):
        mock_git.Repo.side_effect = Exception("not a repo")
        w = self._watcher()
        self.assertIsNone(w.check())
        # validity is cached after first probe
        self.assertFalse(w._is_git_repo())

    def test_first_run_stores_baseline(self, mock_git):
        repo = MagicMock()
        repo.remotes = []  # falsy -> no fetch
        repo.commit.return_value.hexsha = "commit_a"
        mock_git.Repo.return_value = repo
        w = self._watcher()
        self.assertIsNone(w.check())
        self.assertEqual(w.state["last_commit"], "commit_a")

    def test_new_commit_emits_event_and_fetches(self, mock_git):
        repo = MagicMock()
        # truthy remotes -> origin.fetch() path exercised
        repo.remotes.origin.fetch = MagicMock()
        head = MagicMock()
        head.hexsha = "commit_b"
        head.message = "feat: new thing\n"
        head.author = "alice"
        head.committed_datetime.isoformat.return_value = "2026-01-01T00:00:00"
        repo.commit.return_value = head
        mock_git.Repo.return_value = repo

        w = self._watcher()
        w.state = {"last_commit": "commit_a"}
        event = w.check()
        self.assertIsNotNone(event)
        self.assertEqual(event["type"], "new_commit")
        self.assertEqual(event["commit_hash"], "commit_b")
        self.assertEqual(event["message"], "feat: new thing")
        self.assertEqual(event["branch"], "main")
        self.assertEqual(w.state["last_commit"], "commit_b")
        repo.remotes.origin.fetch.assert_called_once()

    def test_no_change_returns_none(self, mock_git):
        repo = MagicMock()
        repo.remotes = []
        repo.commit.return_value.hexsha = "commit_a"
        mock_git.Repo.return_value = repo
        w = self._watcher()
        w.state = {"last_commit": "commit_a"}
        self.assertIsNone(w.check())

    def test_check_swallows_errors(self, mock_git):
        # Repo is valid but commit lookup blows up -> None, no exception.
        repo = MagicMock()
        repo.remotes = []
        repo.commit.side_effect = RuntimeError("boom")
        mock_git.Repo.return_value = repo
        w = self._watcher()
        self.assertIsNone(w.check())


@patch("hawki.core.monitoring.watchers.deployed_contract_watcher.Web3")
class TestDeployedContractWatcher(unittest.TestCase):
    def _mock_connected(self, mock_web3, code=b"\x60\x60"):
        w3 = MagicMock()
        w3.is_connected.return_value = True
        w3.eth.get_code.return_value = code
        mock_web3.return_value = w3
        mock_web3.to_checksum_address.side_effect = lambda a: a
        return w3

    def test_missing_address_raises(self, mock_web3):
        with self.assertRaises(ValueError):
            DeployedContractWatcher(name="d", config={})

    def test_not_connected_raises(self, mock_web3):
        w3 = MagicMock()
        w3.is_connected.return_value = False
        mock_web3.return_value = w3
        with self.assertRaises(ConnectionError):
            DeployedContractWatcher(
                name="d", config={"contract_address": "0xabc", "poa": False}
            )

    def test_first_check_stores_baseline(self, mock_web3):
        self._mock_connected(mock_web3, code=b"\xaa\xbb")
        w = DeployedContractWatcher(
            name="d", config={"contract_address": "0xabc"}
        )
        self.assertIsNone(w.check())
        self.assertEqual(w.state["code_hash"], b"\xaa\xbb".hex())

    def test_bytecode_change_emits_event(self, mock_web3):
        self._mock_connected(mock_web3, code=b"\xde\xad")
        w = DeployedContractWatcher(
            name="d", config={"contract_address": "0xabc"}
        )
        w.state = {"code_hash": "0000oldhash0000"}
        event = w.check()
        self.assertIsNotNone(event)
        self.assertEqual(event["type"], "contract_code_change")
        self.assertEqual(event["contract_address"], "0xabc")
        self.assertEqual(w.state["code_hash"], b"\xde\xad".hex())

    def test_no_change_returns_none(self, mock_web3):
        self._mock_connected(mock_web3, code=b"\xde\xad")
        w = DeployedContractWatcher(
            name="d", config={"contract_address": "0xabc"}
        )
        w.state = {"code_hash": b"\xde\xad".hex()}
        self.assertIsNone(w.check())

    def test_check_swallows_errors(self, mock_web3):
        w3 = self._mock_connected(mock_web3)
        w = DeployedContractWatcher(
            name="d", config={"contract_address": "0xabc"}
        )
        w.state = {"code_hash": "baseline"}
        w3.eth.get_code.side_effect = RuntimeError("rpc error")
        self.assertIsNone(w.check())

    def test_poa_injection_failure_is_non_fatal(self, mock_web3):
        w3 = MagicMock()
        w3.is_connected.return_value = True
        w3.middleware_onion.inject.side_effect = Exception("poa fail")
        mock_web3.return_value = w3
        # Should still construct despite POA injection failing.
        w = DeployedContractWatcher(
            name="d", config={"contract_address": "0xabc", "poa": True}
        )
        self.assertIsNotNone(w)


if __name__ == "__main__":
    unittest.main()
