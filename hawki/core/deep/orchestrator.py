# File: hawki/core/deep/orchestrator.py
"""
DeepOrchestrator - main loop with continuous mode and target-contract support.
"""

import asyncio
import logging
import threading
import time
from pathlib import Path
from typing import Optional

from ..monitoring.watchers.repo_commit_watcher import RepoCommitWatcher
from ..repo_intelligence.indexer import RepositoryIndexer
from .budget import BudgetManager
from .executor.base import Executor
from .memory.base import MemoryStore
from .planner.hybrid_planner import HybridPlanner

logger = logging.getLogger(__name__)


class DeepOrchestrator:
    def __init__(
        self,
        repo_path: Path,
        goal: str,
        memory: MemoryStore,
        planner: HybridPlanner,
        executor: Executor,
        budget: BudgetManager,
        force: bool = False,
        continuous: bool = False,
        interval: int = 60,
        code_only: bool = False,
        target_contract: Optional[str] = None,  # NEW
    ):
        self.repo_path = repo_path
        self.goal = goal
        self.memory = memory
        self.planner = planner
        self.executor = executor
        self.budget = budget
        self.force = force
        self.continuous = continuous
        self.interval = interval
        self.code_only = code_only
        self.target_contract = target_contract  # NEW
        self._stop_continuous = threading.Event()
        self._change_detected = threading.Event()

    async def run(self):
        logger.info("Starting Hawk-i Deep agent")
        logger.info(f"Goal: {self.goal}")
        logger.info(f"Budget: attempts={self.budget.max_attempts}, tokens={self.budget.max_tokens}")
        if self.code_only:
            logger.info("Code-only mode: no live execution")
        if self.continuous:
            logger.info(f"Continuous mode enabled - polling every {self.interval}s")
            watcher_thread = threading.Thread(target=self._watch_repo, daemon=True)
            watcher_thread.start()
        if self.target_contract:
            logger.info(f"Targeting contract: {self.target_contract}")

        # Index repo for initial summary (filtered by target_contract)
        indexer = RepositoryIndexer()
        repo_info = indexer.index(str(self.repo_path))
        repo_summary = self._build_repo_summary(repo_info)
        indexer.cleanup()

        # Main attack loop
        while self.budget.can_continue():
            if self.continuous and self._change_detected.is_set():
                logger.info("Repository change detected - clearing rule attack memory")
                self.memory.clear_rule_attempts()
                self._change_detected.clear()

            plan = self.planner.next_attack(self.memory, self.goal, self.force, repo_summary)
            if plan is None:
                if self.continuous:
                    logger.info("No more attacks currently available - waiting for changes...")
                    await asyncio.sleep(self.interval)
                    continue
                else:
                    logger.info("No more attacks to try")
                    break

            # Estimate token cost if novel
            estimated_tokens = 0
            if plan.type == "novel":
                estimated_tokens = plan.parameters.get("estimated_tokens", 0)
                if not self.budget.can_continue() or (self.budget.max_tokens and estimated_tokens > self.budget.remaining_tokens()):
                    logger.info(f"Skipping novel attack due to token budget (needs {estimated_tokens} tokens)")
                    continue

            logger.info(f"Executing attack: {plan.rule_name if plan.rule_name else plan.parameters.get('name', 'unknown')}")
            if self.code_only:
                result = {
                    "success": False,
                    "logs": "Code-only mode: no execution",
                    "estimated_tokens": estimated_tokens,
                }
            else:
                result = self.executor.execute(plan, self.repo_path, self.goal)

            self.memory.record(plan.to_dict(), result)

            tokens_used = result.get("estimated_tokens", estimated_tokens)
            self.budget.consume(attempts=1, tokens=tokens_used)

            logger.info(f"Attack result: success={result.get('success')}, gas={result.get('gas_used')}, tokens_used={tokens_used}")

        # End of budget / no attacks
        if self.continuous:
            self._stop_continuous.set()
        stats = self.memory.get_stats()
        logger.info(f"Agent finished. Stats: {stats}")

    def _watch_repo(self):
        """Background thread: poll for new commits and signal changes."""
        watcher = RepoCommitWatcher(
            name="deep_agent_watcher",
            config={"repo_path": str(self.repo_path), "branch": "main"}
        )
        watcher.check()
        while not self._stop_continuous.is_set():
            time.sleep(self.interval)
            if self._stop_continuous.is_set():
                break
            try:
                event = watcher.check()
                if event and event.get("type") == "new_commit":
                    logger.info(f"Detected new commit: {event.get('commit_hash', 'unknown')[:8]}")
                    self._change_detected.set()
            except Exception as e:
                logger.error(f"Error in commit watcher: {e}")

    def _build_repo_summary(self, repo_info: dict) -> str:
        """Build repository summary, optionally filtering by target_contract."""
        contracts = repo_info.get("contracts", [])
        if self.target_contract:
            # Filter to only the target contract (case-insensitive)
            contracts = [c for c in contracts if c.get("name", "").lower() == self.target_contract.lower()]
            if not contracts:
                return f"No contract named '{self.target_contract}' found. Available contracts: {', '.join(c.get('name', 'unknown') for c in repo_info.get('contracts', []))}"
        if not contracts:
            return "No Solidity contracts found."
        summary_parts = []
        for contract in contracts[:5]:
            name = contract.get("name", "unknown")
            functions = [f.get("name") for f in contract.get("functions", [])[:10]]
            summary_parts.append(f"Contract {name}: functions {', '.join(functions)}")
        return "\n".join(summary_parts)

# EOF: hawki/core/deep/orchestrator.py