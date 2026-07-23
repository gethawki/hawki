# --------------------
# File: hawki/core/static_rule_engine/rules/unchecked_send.py
# --------------------
"""
Unchecked send: detect send() or transfer() calls without checking return value.
"""

import re

from . import BaseRule


class UncheckedSendRule(BaseRule):
    severity = "Medium"
    explanation_template = (
        "`send()` and `transfer()` return a boolean indicating success. If you don't check this return value, "
        "the function may silently fail, leading to incorrect contract state."
    )
    impact_template = (
        "Failed transfers could leave the contract in an inconsistent state, possibly locking funds or "
        "allowing users to withdraw more than they should."
    )
    fix_template = (
        "Always check the return value of `send()` or `transfer()` with `require`:\n"
        "```solidity\n"
        "bool success = address(...).send(amount);\n"
        "require(success, \"Transfer failed\");\n"
        "```"
    )

    def run_check(self, contract_data):
        findings = []
        # A genuine unchecked send/transfer is a MEMBER call on an address/token,
        # e.g. `msg.sender.transfer(x)` or `token.send(x)`. Requiring a leading
        # `.` deliberately excludes the two biggest false-positive classes that a
        # bare `transfer(`/`send(` substring match produces on real code:
        #   - function DEFINITIONS / interface declarations
        #     (`function transfer(address,uint) returns (bool);`), and
        #   - calls to internal helpers whose name merely ends in "transfer"
        #     (`_transfer(from, to, value)`),
        # neither of which is a value transfer whose return value is being dropped.
        call_pattern = re.compile(r'\.\s*(send|transfer)\s*\(')
        # A return value wrapped in if/require/assert is checked, not "unchecked".
        guard_pattern = re.compile(r'(if|require|assert)\s*\(')
        for contract in contract_data:
            source = contract.get("source", "")
            lines = source.split('\n')
            for i, line in enumerate(lines):
                stripped = line.strip()
                if stripped.startswith('//') or stripped.startswith('*'):
                    continue
                if call_pattern.search(line) and not guard_pattern.search(line):
                    findings.append(self._create_finding(
                        title="Unchecked send/transfer",
                        file=contract.get("path", ""),
                        line=i+1,
                        vulnerable_snippet=stripped,
                    ))
        return findings
# EOF 