# File: tests/deep/test_cov_deep_hybrid_planner.py
"""
Unit tests for HybridPlanner: rule attacks first, then LLM novel fallback once
rules are exhausted. Uses simple fakes; no LLM or filesystem access.
"""

import unittest

from hawki.core.deep.planner.base import AttackPlan
from hawki.core.deep.planner.hybrid_planner import HybridPlanner


class _FakeRulePlanner:
    def __init__(self, plans):
        self._plans = list(plans)
        self.calls = 0

    def next_attack(self, memory, goal, force=False):
        self.calls += 1
        return self._plans.pop(0) if self._plans else None


class _FakeLLMPlanner:
    def __init__(self, plan):
        self._plan = plan
        self.calls = 0
        self.last_repo_summary = None

    def next_attack(self, memory, goal, force=False, repo_summary=""):
        self.calls += 1
        self.last_repo_summary = repo_summary
        return self._plan


_RULE = AttackPlan(plan_type="rule", rule_name="reentrancy_attack", signature="reentrancy_attack.py")
_NOVEL = AttackPlan(plan_type="novel", signature="novel:x", parameters={"name": "x"})


class TestHybridPlanner(unittest.TestCase):
    def test_returns_rule_plan_first(self):
        rule = _FakeRulePlanner([_RULE])
        llm = _FakeLLMPlanner(_NOVEL)
        hp = HybridPlanner(rule, llm)
        plan = hp.next_attack(memory=None, goal="drain")
        self.assertIs(plan, _RULE)
        self.assertEqual(llm.calls, 0)
        self.assertFalse(hp.rule_exhausted)

    def test_switches_to_llm_when_rules_exhausted(self):
        rule = _FakeRulePlanner([])  # no rule plans
        llm = _FakeLLMPlanner(_NOVEL)
        hp = HybridPlanner(rule, llm)
        plan = hp.next_attack(memory=None, goal="drain", repo_summary="Contract V")
        self.assertIs(plan, _NOVEL)
        self.assertTrue(hp.rule_exhausted)
        self.assertEqual(llm.calls, 1)
        self.assertEqual(llm.last_repo_summary, "Contract V")

    def test_no_llm_planner_returns_none_when_exhausted(self):
        rule = _FakeRulePlanner([])
        hp = HybridPlanner(rule, llm_planner=None)
        self.assertIsNone(hp.next_attack(memory=None, goal="drain"))
        self.assertTrue(hp.rule_exhausted)

    def test_after_exhaustion_does_not_recall_rule_planner(self):
        rule = _FakeRulePlanner([])
        llm = _FakeLLMPlanner(_NOVEL)
        hp = HybridPlanner(rule, llm)
        hp.next_attack(memory=None, goal="drain")  # exhausts rules, calls -> 1
        hp.next_attack(memory=None, goal="drain")  # should skip rule planner
        self.assertEqual(rule.calls, 1)
        self.assertEqual(llm.calls, 2)

    def test_force_keeps_trying_rule_planner(self):
        rule = _FakeRulePlanner([_RULE])
        llm = _FakeLLMPlanner(_NOVEL)
        hp = HybridPlanner(rule, llm)
        hp.rule_exhausted = True  # even if flagged exhausted, force retries rules
        plan = hp.next_attack(memory=None, goal="drain", force=True)
        self.assertIs(plan, _RULE)


if __name__ == "__main__":
    unittest.main()
