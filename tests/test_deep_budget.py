"""
Unit tests for the deep-agent BudgetManager (dual attempts+tokens budget) and
the AttackPlan value object. Pure logic, no external services.
"""

import unittest

from hawki.core.deep.budget import BudgetManager
from hawki.core.deep.planner.base import AttackPlan


class TestBudgetManager(unittest.TestCase):
    def test_unlimited_always_continues(self):
        b = BudgetManager()  # both limits None
        self.assertTrue(b.can_continue())
        b.consume(attempts=1000, tokens=10_000_000)
        self.assertTrue(b.can_continue())
        self.assertIsNone(b.remaining_attempts())
        self.assertIsNone(b.remaining_tokens())

    def test_attempts_limit_blocks(self):
        b = BudgetManager(max_attempts=2)
        self.assertTrue(b.can_continue())
        b.consume(attempts=1)
        self.assertTrue(b.can_continue())
        self.assertEqual(b.remaining_attempts(), 1)
        b.consume(attempts=1)
        self.assertFalse(b.can_continue())
        self.assertEqual(b.remaining_attempts(), 0)

    def test_tokens_limit_blocks_independently(self):
        b = BudgetManager(max_tokens=100)
        self.assertTrue(b.can_continue())
        b.consume(tokens=100)
        self.assertFalse(b.can_continue())
        self.assertEqual(b.remaining_tokens(), 0)

    def test_dual_limit_either_stops(self):
        # Attempts exhausted first even though tokens remain.
        b = BudgetManager(max_attempts=1, max_tokens=10_000)
        b.consume(attempts=1, tokens=10)
        self.assertFalse(b.can_continue())

    def test_remaining_never_negative(self):
        b = BudgetManager(max_attempts=1, max_tokens=10)
        b.consume(attempts=5, tokens=50)
        self.assertEqual(b.remaining_attempts(), 0)
        self.assertEqual(b.remaining_tokens(), 0)

    def test_estimate_tokens(self):
        # Rough 1 token ~ 4 chars.
        self.assertEqual(BudgetManager.estimate_tokens("abcd"), 1)
        self.assertEqual(BudgetManager.estimate_tokens("a" * 40), 10)
        self.assertEqual(BudgetManager.estimate_tokens(""), 0)


class TestAttackPlan(unittest.TestCase):
    def test_to_dict_roundtrip(self):
        plan = AttackPlan(
            plan_type="rule",
            rule_name="reentrancy_attack",
            signature="reentrancy_attack.py",
            parameters={"depth": 2},
            description="Rule attack",
        )
        d = plan.to_dict()
        self.assertEqual(d["type"], "rule")
        self.assertEqual(d["rule_name"], "reentrancy_attack")
        self.assertEqual(d["signature"], "reentrancy_attack.py")
        self.assertEqual(d["parameters"], {"depth": 2})
        self.assertEqual(d["description"], "Rule attack")

    def test_defaults(self):
        plan = AttackPlan(plan_type="novel")
        self.assertEqual(plan.type, "novel")
        self.assertIsNone(plan.rule_name)
        self.assertEqual(plan.parameters, {})


if __name__ == "__main__":
    unittest.main()
