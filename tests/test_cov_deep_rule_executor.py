# File: tests/deep/test_cov_deep_rule_executor.py
"""
Unit tests for RuleExecutor. SandboxManager is patched in the rule_executor
module namespace so Docker is never launched.
"""

import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

from hawki.core.deep.executor.rule_executor import RuleExecutor
from hawki.core.deep.planner.base import AttackPlan


def _plan(rule_name="reentrancy_attack"):
    return AttackPlan(plan_type="rule", rule_name=rule_name, signature=f"{rule_name}.py")


class TestRuleExecutor(unittest.TestCase):
    def test_execute_success_runs_script_and_cleans_up(self):
        sandbox = MagicMock()
        sandbox.run_script.return_value = {
            "success": True, "before_balance": 10, "after_balance": 0, "gas_used": 21000,
        }
        with patch("hawki.core.deep.executor.rule_executor.SandboxManager", return_value=sandbox) as SM:
            result = RuleExecutor().execute(_plan(), Path("/repo"), goal="drain")
        SM.assert_called_once()
        sandbox.run_script.assert_called_once_with("reentrancy_attack.py")
        sandbox.cleanup.assert_called_once()
        self.assertTrue(result["success"])

    def test_execute_sandbox_error_returns_fail_dict(self):
        with patch(
            "hawki.core.deep.executor.rule_executor.SandboxManager",
            side_effect=RuntimeError("docker down"),
        ):
            result = RuleExecutor().execute(_plan("overflow_attack"), Path("/repo"))
        self.assertFalse(result["success"])
        self.assertIn("docker down", result["logs"])
        self.assertEqual(result["attack_name"], "overflow_attack")
        # No sandbox instance was created, so cleanup is not reached (no crash).

    def test_execute_run_error_still_cleans_up(self):
        sandbox = MagicMock()
        sandbox.run_script.side_effect = ValueError("boom")
        with patch("hawki.core.deep.executor.rule_executor.SandboxManager", return_value=sandbox):
            result = RuleExecutor().execute(_plan(), Path("/repo"))
        self.assertFalse(result["success"])
        self.assertIn("boom", result["logs"])
        sandbox.cleanup.assert_called_once()


if __name__ == "__main__":
    unittest.main()
