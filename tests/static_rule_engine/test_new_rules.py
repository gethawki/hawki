# --------------------
# File: tests/core/static_rule_engine/rules/test_missing_initializer.py
# --------------------
from hawki.core.static_rule_engine.rules.missing_initializer import MissingInitializerRule


def test_detects_missing_initializer():
    rule = MissingInitializerRule()
    contract_data = [{
        "path": "test.sol",
        "source": "contract Test is UUPSUpgradeable { function initialize() public { } }",
        "functions": [{"name": "initialize", "modifiers": []}]
    }]
    findings = rule.run_check(contract_data)
    assert len(findings) == 1
    assert "Missing initializer" in findings[0]["title"]

def test_no_finding_when_initializer_present():
    rule = MissingInitializerRule()
    contract_data = [{
        "path": "test.sol",
        "source": "contract Test is UUPSUpgradeable { function initialize() public initializer { } }",
        "functions": [{"name": "initialize", "modifiers": ["initializer"]}]
    }]
    findings = rule.run_check(contract_data)
    assert len(findings) == 0