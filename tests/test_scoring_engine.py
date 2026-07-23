"""
Unit tests for SecurityScoreEngine deductions and severity normalization.

The scoring layer is a cloud-relevant contract: it starts at 100, subtracts
severity-weighted deductions (Critical 15 / High 8 / Medium 4 / Low 1) plus
flat penalties, clamps to [0,100], and maps to a risk band. Canonical severity
casing is Title case ("Critical").
"""

import unittest

from hawki.core.data_layer.reporting.scoring_engine import (
    SecurityScoreEngine,
    normalize_severity,
)


class TestNormalizeSeverity(unittest.TestCase):
    def test_canonical_title_case(self):
        self.assertEqual(normalize_severity("critical"), "Critical")
        self.assertEqual(normalize_severity("CRITICAL"), "Critical")
        self.assertEqual(normalize_severity("High"), "High")
        self.assertEqual(normalize_severity("moderate"), "Medium")
        self.assertEqual(normalize_severity("informational"), "Info")

    def test_empty_and_none_default_to_info(self):
        self.assertEqual(normalize_severity(""), "Info")
        self.assertEqual(normalize_severity(None), "Info")


class TestScoreDeductions(unittest.TestCase):
    def setUp(self):
        self.engine = SecurityScoreEngine()

    def test_no_findings_is_perfect(self):
        result = self.engine.calculate(findings=[])
        self.assertEqual(result["score"], 100)
        self.assertEqual(result["classification"], "Secure")

    def test_single_critical(self):
        result = self.engine.calculate(findings=[{"severity": "Critical"}])
        self.assertEqual(result["score"], 85)  # 100 - 15
        self.assertEqual(result["classification"], "Minor Risk")

    def test_mixed_severities_weighted(self):
        findings = [
            {"severity": "Critical"},  # 15
            {"severity": "High"},      # 8
            {"severity": "Medium"},    # 4
            {"severity": "Low"},       # 1
            {"severity": "Info"},      # 0
        ]
        result = self.engine.calculate(findings=findings)
        self.assertEqual(result["score"], 72)  # 100 - 28

    def test_severity_casing_normalized_before_weighting(self):
        # Lowercase input must weight the same as canonical Title case.
        result = self.engine.calculate(findings=[{"severity": "critical"}])
        self.assertEqual(result["score"], 85)

    def test_score_clamped_at_zero(self):
        findings = [{"severity": "Critical"} for _ in range(20)]  # 300 deduction
        result = self.engine.calculate(findings=findings)
        self.assertEqual(result["score"], 0)
        self.assertEqual(result["classification"], "Critical Risk")

    def test_dependency_penalty(self):
        result = self.engine.calculate(
            findings=[],
            dependency_findings=[{"package": "a"}, {"package": "b"}],
        )
        self.assertEqual(result["score"], 80)  # 100 - 2*10
        self.assertTrue(result["deps_checked"])

    def test_bytecode_mismatch_penalty(self):
        result = self.engine.calculate(
            findings=[],
            bytecode_result={"match": False},
        )
        self.assertEqual(result["score"], 80)  # 100 - 20
        self.assertTrue(result["bytecode_checked"])

    def test_bytecode_match_no_penalty(self):
        result = self.engine.calculate(findings=[], bytecode_result={"match": True})
        self.assertEqual(result["score"], 100)

    def test_upgrade_collision_penalty_only_counts_collisions(self):
        upgrade_findings = [
            {"title": "Storage collision between A and B"},
            {"title": "Upgradeable proxy pattern: UUPS"},  # not a collision
        ]
        result = self.engine.calculate(findings=[], upgrade_findings=upgrade_findings)
        self.assertEqual(result["score"], 85)  # 100 - 1*15

    def test_novel_attack_success_penalty(self):
        result = self.engine.calculate(
            findings=[],
            deep_agent_stats={"novel_successes": 2},
        )
        self.assertEqual(result["score"], 80)  # 100 - 2*10
        self.assertTrue(result["deep_agent_used"])

    def test_sandbox_success_penalty(self):
        result = self.engine.calculate(
            findings=[],
            sandbox_results=[{"success": True}, {"success": False}],
        )
        self.assertEqual(result["score"], 95)  # 100 - 1*5
        self.assertTrue(result["simulation_used"])


if __name__ == "__main__":
    unittest.main()
