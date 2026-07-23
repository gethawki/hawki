# --------------------
# File: tests/test_rules.py (updated)
# --------------------
"""
Unit tests for static rules.
"""

import unittest

from hawki.core.static_rule_engine import RuleEngine
from hawki.core.static_rule_engine.rules.reentrancy import ReentrancyRule


class TestRules(unittest.TestCase):
    def test_reentrancy_rule(self):
        rule = ReentrancyRule()
        # Source-based detection: external .call before a state write, unguarded.
        src = (
            "contract Vault {\n"
            "  mapping(address => uint) bal;\n"
            "  function withdraw() public {\n"
            "    (bool ok, ) = msg.sender.call{value: bal[msg.sender]}(\"\");\n"
            "    bal[msg.sender] = 0;\n"
            "  }\n"
            "}"
        )
        contract_data = [{"path": "Vault.sol", "source": src}]
        findings = rule.run_check(contract_data)
        self.assertEqual(len(findings), 1)
        # Check fields set by the rule itself
        self.assertEqual(findings[0]["title"], "Potential reentrancy vulnerability")
        self.assertEqual(findings[0]["severity"], "Critical")
        self.assertIn("function_name", findings[0])
        self.assertEqual(findings[0]["function_name"], "withdraw")

    def test_engine_discovery(self):
        engine = RuleEngine()
        # At least the 10 rules we defined should be loaded
        self.assertGreaterEqual(len(engine.rules), 10)

if __name__ == "__main__":
    unittest.main()