# --------------------
# File: tests/core/static_rule_engine/rules/test_missing_initializer.py
# --------------------
from hawki.core.static_rule_engine.rules.missing_initializer import MissingInitializerRule


def test_missing_initializer_detection():
    rule = MissingInitializerRule()
    contract_data = [{
        "path": "test.sol",
        "source": """
contract MyContract is UUPSUpgradeable {
    function initialize() public {
        // missing initializer modifier
    }
}
""",
        "functions": [{"name": "initialize", "modifiers": []}]
    }]
    findings = rule.run_check(contract_data)
    assert len(findings) == 1
    assert findings[0]["title"] == "Missing initializer in upgradeable contract"