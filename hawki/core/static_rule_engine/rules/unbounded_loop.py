# --------------------
# File: hawki/core/static_rule_engine/rules/unbounded_loop.py
# --------------------
"""
Unbounded loop: loops that iterate over dynamic arrays may exceed block gas limit.
"""

import re

from . import BaseRule


class UnboundedLoopRule(BaseRule):
    severity = "High"
    explanation_template = (
        "Loops that iterate over dynamic arrays of unbounded length can exceed the block gas limit, "
        "causing the function to always revert and effectively locking funds."
    )
    impact_template = (
        "An attacker could fill the array to make the function uncallable, leading to denial of service."
    )
    fix_template = (
        "Avoid loops over dynamic arrays, or implement pagination so that only a limited number of items "
        "are processed per transaction. Use mappings instead of arrays where possible."
    )

    def run_check(self, contract_data):
        findings = []
        for contract in contract_data:
            source = contract.get("source", "")
            loop_pattern = re.compile(r'(for|while)\s*\(.*\.length.*\)')
            matches = loop_pattern.finditer(source)
            for match in matches:
                line = source[:match.start()].count('\n') + 1
                snippet = source[match.start():match.end()]
                findings.append(self._create_finding(
                    title="Unbounded loop may cause gas exhaustion",
                    file=contract.get("path", ""),
                    line=line,
                    vulnerable_snippet=snippet,
                ))
        return findings
# EOF: hawki/core/static_rule_engine/rules/unbounded_loop.py