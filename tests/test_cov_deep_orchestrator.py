# File: tests/deep/test_cov_deep_orchestrator.py
"""
Unit tests for DeepOrchestrator.run (async loop) and _build_repo_summary.

The RepositoryIndexer is patched so no repo is actually indexed; the planner and
executor are lightweight fakes so no LLM or Docker is involved. Memory is a real
store backed by a temp path (both SQLite and JSON exercised). run() is driven via
asyncio.run with a bounded budget.
"""

import asyncio
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

from hawki.core.deep.budget import BudgetManager
from hawki.core.deep.memory.json_store import JSONStore
from hawki.core.deep.memory.sqlite_store import SQLiteStore
from hawki.core.deep.orchestrator import DeepOrchestrator
from hawki.core.deep.planner.base import AttackPlan


class _FakePlanner:
    """Duck-typed HybridPlanner: yields queued plans then None."""
    def __init__(self, plans):
        self._plans = list(plans)
        self.calls = 0

    def next_attack(self, memory, goal, force=False, repo_summary=""):
        self.calls += 1
        return self._plans.pop(0) if self._plans else None


class _FakeExecutor:
    def __init__(self, result=None):
        self.result = result or {"success": True, "gas_used": 100, "estimated_tokens": 5}
        self.calls = 0

    def execute(self, plan, repo_path, goal=""):
        self.calls += 1
        return self.result


def _rule_plan(sig):
    return AttackPlan(plan_type="rule", rule_name=sig.replace(".py", ""), signature=sig)


def _novel_plan(sig="novel:x", estimated_tokens=0):
    return AttackPlan(
        plan_type="novel",
        signature=sig,
        parameters={"name": "x", "estimated_tokens": estimated_tokens},
    )


def _patch_indexer(contracts=None):
    """Patch RepositoryIndexer in the orchestrator module."""
    mock_indexer = MagicMock()
    mock_indexer.index.return_value = {"contracts": contracts or []}
    mock_indexer.cleanup.return_value = None
    return patch(
        "hawki.core.deep.orchestrator.RepositoryIndexer",
        return_value=mock_indexer,
    )


class _OrchestratorBase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.repo = Path(self.tmp.name)

    def make_memory(self):
        return SQLiteStore(db_path=self.repo / "mem.db")


class TestOrchestratorRun(_OrchestratorBase):
    def test_rule_then_novel_handoff_records_all(self):
        planner = _FakePlanner([_rule_plan("a.py"), _rule_plan("b.py"), _novel_plan("novel:1")])
        executor = _FakeExecutor()
        memory = self.make_memory()
        orch = DeepOrchestrator(
            repo_path=self.repo, goal="drain", memory=memory, planner=planner,
            executor=executor, budget=BudgetManager(max_attempts=10),
        )
        with _patch_indexer():
            asyncio.run(orch.run())
        stats = memory.get_stats()
        self.assertEqual(stats["total_attempts"], 3)
        self.assertEqual(stats["rule_attempts"], 2)
        self.assertEqual(stats["novel_attempts"], 1)
        self.assertEqual(executor.calls, 3)

    def test_budget_exhaustion_stops_loop(self):
        # Infinite supply of plans; budget of 2 attempts must stop it.
        planner = _FakePlanner([_rule_plan(f"s{i}.py") for i in range(100)])
        executor = _FakeExecutor(result={"success": False, "gas_used": 0, "estimated_tokens": 0})
        memory = self.make_memory()
        orch = DeepOrchestrator(
            repo_path=self.repo, goal="drain", memory=memory, planner=planner,
            executor=executor, budget=BudgetManager(max_attempts=2),
        )
        with _patch_indexer():
            asyncio.run(orch.run())
        self.assertEqual(memory.get_stats()["total_attempts"], 2)
        self.assertEqual(executor.calls, 2)

    def test_code_only_mode_skips_executor(self):
        planner = _FakePlanner([_rule_plan("a.py")])
        executor = _FakeExecutor()
        memory = self.make_memory()
        orch = DeepOrchestrator(
            repo_path=self.repo, goal="drain", memory=memory, planner=planner,
            executor=executor, budget=BudgetManager(max_attempts=5), code_only=True,
        )
        with _patch_indexer():
            asyncio.run(orch.run())
        self.assertEqual(executor.calls, 0)  # executor never invoked
        rec = memory.get_all()[0]
        self.assertFalse(rec["success"])
        self.assertEqual(memory.get_stats()["total_attempts"], 1)

    def test_novel_skipped_when_over_token_budget(self):
        # Novel plan needs 1000 tokens but only ~10 remain -> skipped, then None -> stop.
        planner = _FakePlanner([_novel_plan("novel:big", estimated_tokens=1000)])
        executor = _FakeExecutor()
        memory = self.make_memory()
        orch = DeepOrchestrator(
            repo_path=self.repo, goal="drain", memory=memory, planner=planner,
            executor=executor, budget=BudgetManager(max_attempts=5, max_tokens=10),
        )
        with _patch_indexer():
            asyncio.run(orch.run())
        # Skipped: nothing executed or recorded.
        self.assertEqual(executor.calls, 0)
        self.assertEqual(memory.get_stats()["total_attempts"], 0)

    def test_no_attacks_available_breaks_immediately(self):
        planner = _FakePlanner([])  # returns None on first call
        executor = _FakeExecutor()
        memory = self.make_memory()
        orch = DeepOrchestrator(
            repo_path=self.repo, goal="drain", memory=memory, planner=planner,
            executor=executor, budget=BudgetManager(max_attempts=5),
        )
        with _patch_indexer():
            asyncio.run(orch.run())
        self.assertEqual(memory.get_stats()["total_attempts"], 0)

    def test_run_with_json_store_backend(self):
        planner = _FakePlanner([_rule_plan("a.py"), _novel_plan("novel:1")])
        executor = _FakeExecutor()
        memory = JSONStore(file_path=self.repo / "mem.jsonl")
        orch = DeepOrchestrator(
            repo_path=self.repo, goal="drain", memory=memory, planner=planner,
            executor=executor, budget=BudgetManager(max_attempts=5),
            target_contract="Vault",
        )
        with _patch_indexer(contracts=[{"name": "Vault", "functions": [{"name": "withdraw"}]}]):
            asyncio.run(orch.run())
        self.assertEqual(memory.get_stats()["total_attempts"], 2)


class TestBuildRepoSummary(_OrchestratorBase):
    def _orch(self, target=None):
        return DeepOrchestrator(
            repo_path=self.repo, goal="g", memory=self.make_memory(),
            planner=_FakePlanner([]), executor=_FakeExecutor(),
            budget=BudgetManager(), target_contract=target,
        )

    def test_no_contracts(self):
        self.assertEqual(self._orch()._build_repo_summary({"contracts": []}), "No Solidity contracts found.")

    def test_normal_summary(self):
        info = {"contracts": [
            {"name": "Vault", "functions": [{"name": "deposit"}, {"name": "withdraw"}]},
        ]}
        summary = self._orch()._build_repo_summary(info)
        self.assertIn("Contract Vault", summary)
        self.assertIn("deposit", summary)
        self.assertIn("withdraw", summary)

    def test_target_contract_filter_match(self):
        info = {"contracts": [
            {"name": "Vault", "functions": [{"name": "deposit"}]},
            {"name": "Token", "functions": [{"name": "transfer"}]},
        ]}
        summary = self._orch(target="vault")._build_repo_summary(info)  # case-insensitive
        self.assertIn("Contract Vault", summary)
        self.assertNotIn("Token", summary)

    def test_target_contract_not_found(self):
        info = {"contracts": [{"name": "Vault", "functions": []}]}
        summary = self._orch(target="Missing")._build_repo_summary(info)
        self.assertIn("No contract named 'Missing'", summary)
        self.assertIn("Vault", summary)  # lists available


if __name__ == "__main__":
    unittest.main()
