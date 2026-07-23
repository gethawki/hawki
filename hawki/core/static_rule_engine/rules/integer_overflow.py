# --------------------
# File: hawki/core/static_rule_engine/rules/integer_overflow.py
# --------------------
"""
Integer overflow/underflow: detect usage of arithmetic operations without SafeMath or Solidity >=0.8.0.
"""

import re

from . import BaseRule

# First (major, minor) of a `pragma solidity` directive, e.g. 0.8 from ^0.8.24.
_PRAGMA = re.compile(r"pragma\s+solidity[^;]*?(\d+)\.(\d+)")
_ARITH = re.compile(r"[+\-*/]")


class IntegerOverflowRule(BaseRule):
    severity = "Medium"
    explanation_template = (
        "Arithmetic operations in Solidity versions prior to 0.8.0 can overflow/underflow silently, "
        "leading to incorrect balances or logic. Even in 0.8.x, `unchecked` blocks can reintroduce overflow."
    )
    impact_template = (
        "An attacker could manipulate arithmetic to gain unexpected tokens or break contract invariants."
    )
    fix_template = (
        "Use Solidity 0.8.0 or later (which includes built-in overflow checks), or use SafeMath library. "
        "If `unchecked` is necessary, ensure values are bounded and cannot overflow."
    )

    def run_check(self, contract_data):
        findings = []
        for contract in contract_data:
            source = contract.get("source", "")
            # Solidity >=0.8.0 reverts on overflow by default, so unguarded
            # arithmetic there is safe (the `unchecked { }` escape hatch is the
            # integer_overflow_unchecked rule's job). Only flag pre-0.8 code
            # that also lacks SafeMath. A contract with no pragma is treated
            # conservatively as potentially pre-0.8.
            pragma = _PRAGMA.search(source)
            if pragma and (int(pragma.group(1)), int(pragma.group(2))) >= (0, 8):
                continue
            if "using SafeMath" in source:
                continue
            match = _ARITH.search(source)
            if not match:
                continue
            line = source[:match.start()].count("\n") + 1
            findings.append(self._create_finding(
                title="Potential integer overflow/underflow",
                file=contract.get("path", ""),
                line=line,
                vulnerable_snippet=source[match.start():match.start() + 10],
            ))
        return findings
# EOF: hawki/core/static_rule_engine/rules/integer_overflow.py