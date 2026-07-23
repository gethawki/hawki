# --------------------
# File: hawki/core/static_rule_engine/rules/flash_loan_manipulation.py
# --------------------
"""
Flash loan manipulation: detect price calculations that can be manipulated via flash loans.
"""

import re

from . import BaseRule


class FlashLoanManipulationRule(BaseRule):
    severity = "Critical"
    explanation_template = (
        "Using spot prices derived from pool reserves in the same transaction allows an attacker to take a flash loan, "
        "manipulate the price, and profit before repaying the loan."
    )
    impact_template = (
        "An attacker can drain funds by artificially inflating/deflating prices and trading against the protocol."
    )
    fix_template = (
        "Use time-weighted average prices (TWAP) or oracles like Chainlink. Avoid relying on instantaneous spot prices."
    )

    def run_check(self, contract_data):
        findings = []
        # Only flag genuine spot-price smells, not every balance read. A bare
        # `token.balanceOf(address(this))` (extremely common and benign, e.g. a
        # staking pool checking its own balance) is NOT flagged; the manipulable
        # pattern is a reserve/balance value that feeds a ratio or price
        # computation. `getReserves()` is the canonical AMM spot-price source and
        # is flagged directly; a self-balance read is flagged only when it sits
        # next to a `*`/`/` (i.e. it participates in a price calculation).
        patterns = [
            r"\.getReserves\(\)",
            r"balanceOf\(address\(this\)\)\s*[*/]",
            r"[*/]\s*\w+\.balanceOf\(address\(this\)\)",
        ]
        for contract in contract_data:
            source = contract.get("source", "")
            for pattern in patterns:
                for match in re.finditer(pattern, source):
                    line = source[:match.start()].count("\n") + 1
                    findings.append(self._create_finding(
                        title="Potential flash loan manipulation",
                        file=contract.get("path", ""),
                        line=line,
                        vulnerable_snippet=match.group(0).strip(),
                    ))
        return findings
# EOF: hawki/core/static_rule_engine/rules/flash_loan_manipulation.py