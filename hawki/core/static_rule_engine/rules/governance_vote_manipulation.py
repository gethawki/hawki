# --------------------
# File: hawki/core/static_rule_engine/rules/governance_vote_manipulation.py
# --------------------
"""
Governance vote manipulation: detect voting mechanisms that can be manipulated via flash loans or token borrows.
"""

import re

from . import BaseRule


class GovernanceVoteManipulationRule(BaseRule):
    severity = "Critical"
    explanation_template = (
        "If voting power is based on token balance at the time of voting, an attacker can borrow tokens via flash loan, "
        "vote, and return the tokens, gaining undue influence."
    )
    impact_template = (
        "An attacker can pass malicious proposals or block legitimate ones, compromising the DAO."
    )
    fix_template = (
        "Use snapshots (e.g., OpenZeppelin's `ERC20Snapshot`) or measure voting power at a past block to prevent flash loan attacks."
    )

    def run_check(self, contract_data):
        findings = []
        # Look for voting functions that use current balance
        patterns = [
            r'balanceOf\(msg\.sender\)',
            r'getVotes\(msg\.sender\)',
            r'votingPower\s*=\s*\w+\.balanceOf\(',
        ]
        for contract in contract_data:
            source = contract.get("source", "")
            for pattern in patterns:
                matches = re.finditer(pattern, source)
                for match in matches:
                    line = source[:match.start()].count('\n') + 1
                    snippet = source[match.start():match.end()]
                    # Check if there's a snapshot mechanism
                    if "getPastVotes" not in source and "snapshot" not in source:
                        findings.append(self._create_finding(
                            title="Governance vote manipulation via flash loan",
                            file=contract.get("path", ""),
                            line=line,
                            vulnerable_snippet=snippet,
                        ))
        return findings
# EOF : hawki/core/static_rule_engine/rules/governance_vote_manipulation.py