# File: tests/deep/test_cov_deep_orchestrator_continuous.py
"""
Coverage for DeepOrchestrator continuous-mode branches and the background commit
watcher. RepoCommitWatcher and RepositoryIndexer are patched so no git/network/
Docker is touched; time.sleep is neutralised so the watcher thread spins fast.
"""

import asyncio
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

from hawki.core.deep.budget import BudgetManager
from hawki.core.deep.memory.sqlite_store import SQLiteStore
from hawki.core.deep.orchestrator import DeepOrchestrator
from hawki.core.deep.planner.base import AttackPlan


class _FakePlanner:
    def __init__(self, plans):
        self._plans = list(plans)

    def next_attack(self, memory, goal, force=False, repo_summary=""):
        return self._plans.pop(0) if self._plans else None


class _FakeExecutor:
    def execute(self, plan, repo_path, goal=""):
        return {"success": False, "gas_used": 0, "estimated_tokens": 0}


def _rule_plan(sig="a.py"):
    return AttackPlan(plan_type="rule", rule_name=sig.replace(".py", ""), signature=sig)


def _patch_indexer():
    mock = MagicMock()
    mock.index.return_value = {"contracts": []}
    return patch("hawki.core.deep.orchestrator.RepositoryIndexer", return_value=mock)


def _patch_watcher():
    """Silence the background watcher thread (no real git polling)."""
    w = MagicMock()
    w.check.return_value = None
    return patch("hawki.core.deep.orchestrator.RepoCommitWatcher", return_value=w)


class _Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.repo = Path(self.tmp.name)

    def memory(self):
        return SQLiteStore(db_path=self.repo / "mem.db")


class TestContinuousRun(_Base):
    def test_change_detected_clears_rule_memory_then_runs(self):
        mem = self.memory()
        # Pre-seed a rule attempt that the change-detection branch should clear.
        mem.record({"type": "rule", "rule_name": "old", "signature": "old.py"}, {"success": False})
        planner = _FakePlanner([_rule_plan("a.py")])
        orch = DeepOrchestrator(
            repo_path=self.repo, goal="drain", memory=mem, planner=planner,
            executor=_FakeExecutor(), budget=BudgetManager(max_attempts=1),
            continuous=True, interval=0,
        )
        orch._change_detected.set()  # force the clear branch on first iteration
        with _patch_indexer(), _patch_watcher(), \
             patch("hawki.core.deep.orchestrator.time.sleep", return_value=None):
            asyncio.run(orch.run())
        self.assertFalse(orch._change_detected.is_set())
        self.assertTrue(orch._stop_continuous.is_set())  # continuous shutdown reached
        # Old rule attempt was cleared; only the new one recorded this run remains.
        sigs = [r["attack_signature"] for r in mem.get_all()]
        self.assertNotIn("old.py", sigs)
        self.assertIn("a.py", sigs)

    def test_no_attacks_available_sleeps_and_continues(self):
        # planner immediately returns None -> continuous mode sleeps then loops.
        planner = _FakePlanner([])

        class _Break(Exception):
            pass

        async def _sleep_then_break(_):
            raise _Break

        orch = DeepOrchestrator(
            repo_path=self.repo, goal="drain", memory=self.memory(), planner=planner,
            executor=_FakeExecutor(), budget=BudgetManager(max_attempts=5),
            continuous=True, interval=0,
        )
        with _patch_indexer(), _patch_watcher(), \
             patch("hawki.core.deep.orchestrator.time.sleep", return_value=None), \
             patch("hawki.core.deep.orchestrator.asyncio.sleep", _sleep_then_break):
            with self.assertRaises(_Break):
                asyncio.run(orch.run())


class TestWatchRepo(_Base):
    def _orch(self):
        return DeepOrchestrator(
            repo_path=self.repo, goal="g", memory=self.memory(),
            planner=_FakePlanner([]), executor=_FakeExecutor(),
            budget=BudgetManager(), continuous=True, interval=0,
        )

    def test_watch_repo_detects_new_commit(self):
        orch = self._orch()
        watcher = MagicMock()
        # initial check, then a new-commit event, then stop the loop.
        events = [None, {"type": "new_commit", "commit_hash": "abcd12345678"}]

        def _check():
            if events:
                return events.pop(0)
            orch._stop_continuous.set()
            return None

        watcher.check.side_effect = _check
        with patch("hawki.core.deep.orchestrator.RepoCommitWatcher", return_value=watcher), \
             patch("hawki.core.deep.orchestrator.time.sleep", return_value=None):
            orch._watch_repo()
        self.assertTrue(orch._change_detected.is_set())

    def test_watch_repo_swallows_check_errors(self):
        orch = self._orch()
        watcher = MagicMock()
        calls = {"n": 0}

        def _check():
            calls["n"] += 1
            if calls["n"] == 1:
                return None  # initial check
            if calls["n"] == 2:
                raise RuntimeError("git blew up")  # error branch, must be swallowed
            orch._stop_continuous.set()
            return None

        watcher.check.side_effect = _check
        with patch("hawki.core.deep.orchestrator.RepoCommitWatcher", return_value=watcher), \
             patch("hawki.core.deep.orchestrator.time.sleep", return_value=None):
            orch._watch_repo()  # must not raise
        self.assertFalse(orch._change_detected.is_set())


if __name__ == "__main__":
    unittest.main()
