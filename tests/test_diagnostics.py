"""
Unit tests for the diagnostics layer: the CheckResult value object, the
BudgetLimitsCheck logic, and the JSON reporter. No system-dependency probing
that touches solc/RPC/network is exercised here.
"""

import json
import unittest

from hawki.core.diagnostics.checks.base import CheckResult
from hawki.core.diagnostics.checks.budget_limits import BudgetLimitsCheck
from hawki.core.diagnostics.reporters.json_reporter import JSONReporter


class TestCheckResult(unittest.TestCase):
    def test_to_dict_shape(self):
        r = CheckResult(name="x", status="pass", message="ok")
        d = r.to_dict()
        self.assertEqual(d["name"], "x")
        self.assertEqual(d["status"], "pass")
        self.assertEqual(d["message"], "ok")
        self.assertIsNone(d["fix"])
        self.assertEqual(d["details"], {})
        self.assertEqual(d["duration_ms"], 0.0)


class TestBudgetLimitsCheck(unittest.TestCase):
    def setUp(self):
        self.check = BudgetLimitsCheck()

    def test_metadata(self):
        self.assertEqual(self.check.name, "budget_limits")
        self.assertEqual(self.check.category, "budget")
        self.assertFalse(self.check.is_critical())

    def test_nonpositive_attempts_warns(self):
        result = self.check.run({"budget_attempts": 0, "openai_api_key": "k"})
        self.assertEqual(result.status, "warn")
        self.assertIn("budget_attempts", result.message)

    def test_low_tokens_warns(self):
        result = self.check.run({"budget_tokens": 10, "openai_api_key": "k"})
        self.assertEqual(result.status, "warn")

    def test_valid_config_passes(self):
        # Supplying an LLM key via config avoids the no-key warning path, so a
        # sane attempts/tokens config yields a clean pass regardless of env.
        result = self.check.run({
            "budget_attempts": 100,
            "budget_tokens": 50_000,
            "openai_api_key": "sk-test",
        })
        self.assertEqual(result.status, "pass")


class TestJSONReporter(unittest.TestCase):
    def test_serializes_summary(self):
        summary = {"overall": "pass", "checks": [{"name": "a", "status": "pass"}]}
        out = JSONReporter().report(summary)
        self.assertEqual(json.loads(out), summary)


if __name__ == "__main__":
    unittest.main()
