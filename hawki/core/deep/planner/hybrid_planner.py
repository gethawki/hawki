# File: hawki/core/deep/planner/hybrid_planner.py
"""
Planner that first uses rule-based attacks, then falls back to LLM novel attacks.
"""

import logging
from typing import Optional

from .base import AttackPlan, Planner
from .llm_planner import LLMPlanner
from .rule_planner import RulePlanner

logger = logging.getLogger(__name__)

class HybridPlanner(Planner):
    def __init__(self, rule_planner: RulePlanner, llm_planner: Optional[LLMPlanner] = None):
        self.rule_planner = rule_planner
        self.llm_planner = llm_planner
        self.rule_exhausted = False

    def next_attack(self, memory, goal: str, force: bool = False,
                    repo_summary: str = "") -> Optional[AttackPlan]:
        # First, try rule-based attacks
        if not self.rule_exhausted or force:
            plan = self.rule_planner.next_attack(memory, goal, force)
            if plan:
                return plan
            else:
                self.rule_exhausted = True
                logger.info("Rule-based attacks exhausted, switching to LLM novel attacks")

        # Then, LLM novel attacks
        if self.llm_planner:
            return self.llm_planner.next_attack(memory, goal, force, repo_summary)
        return None

# EOF