# --------------------
# File: tests/core/static_rule_engine/test_rule_engine.py
# --------------------
from unittest.mock import Mock

from hawki.core.static_rule_engine import RuleEngine
from hawki.core.static_rule_engine.rules import BaseRule


class MockRule(BaseRule):
    severity = "High"
    explanation_template = "explanation"
    impact_template = "impact"
    fix_template = "fix"

    def run_check(self, contract_data):
        return [self._create_finding("Test finding", "file.sol", 1, "code")]

def test_rule_engine_enriches_findings():
    engine = RuleEngine()
    # Replace rules with mock
    engine.rules = [MockRule()]
    # Mock remediation engine to return a fix
    engine.remediation.get_fix = Mock(return_value="fixed code")

    contract_data = [{"path": "file.sol"}]
    findings = engine.run_all(contract_data)

    assert len(findings) == 1
    f = findings[0]
    assert f["explanation"] == "explanation"
    assert f["impact"] == "impact"
    assert f["fix_snippet"] == "fixed code"