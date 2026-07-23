# --------------------
# File: hawki/core/static_rule_engine/rules/gas_griefing.py
# --------------------
"""
Gas griefing: forcing a contract to use excessive gas by causing expensive operations.
"""

import re

from . import BaseRule


class GasGriefingRule(BaseRule):
    severity = "High"
    explanation_template = (
        "If a contract performs operations that cost gas proportional to user-supplied data (e.g., iterating over an array), "
        "an attacker can cause the transaction to run out of gas or cost the victim a lot of gas."
    )
    impact_template = (
        "An attacker can grief users by making their transactions fail or become extremely expensive, effectively blocking them."
    )
    fix_template = (
        "Limit the size of loops or arrays that can be processed in a single transaction. Use pagination or off-chain computation."
    )

    def run_check(self, contract_data):
        findings = []
        # Look for loops over dynamic arrays without length limit
        for contract in contract_data:
            source = contract.get("source", "")
            # Find loops that use .length
            loop_pattern = re.compile(r'(for|while)\s*\(.*\.length.*\)')
            matches = loop_pattern.finditer(source)
            for match in matches:
                line = source[:match.start()].count('\n') + 1
                snippet = source[match.start():match.end()]
                findings.append(self._create_finding(
                    title="Potential gas griefing (unbounded loop)",
                    file=contract.get("path", ""),
                    line=line,
                    vulnerable_snippet=snippet,
                ))
        return findings
# EOF: hawki/core/static_rule_engine/rules/gas_griefing.py