# --------------------
# File: hawki/core/static_rule_engine/rules/front_running.py
# --------------------
"""
Front-running vulnerability: detect transaction ordering dependency.
"""

import re

from . import BaseRule


class FrontRunningRule(BaseRule):
    severity = "Low"
    explanation_template = (
        "Using `block.timestamp` or `block.number` for critical logic can allow miners or bots to "
        "front-run transactions by manipulating the block parameters or ordering."
    )
    impact_template = (
        "Attackers can exploit front-running to gain unfair advantage, e.g., by seeing a pending trade "
        "and inserting their own transaction first."
    )
    fix_template = (
        "Avoid relying on block.timestamp or block.number for critical decisions. "
        "Use commit-reveal schemes or other mechanisms that are resistant to front-running."
    )

    def run_check(self, contract_data):
        findings = []
        # Dependence on block.timestamp/number is an ordering/manipulation smell,
        # but it is pervasive and benign in most contracts (reward accounting,
        # timelocks). Report it at most ONCE per contract as a low-severity
        # heads-up rather than flagging every occurrence, which floods real
        # codebases. (Timestamp-as-security-control is covered in more depth by
        # the timestamp_dependency rule.)
        pattern = re.compile(r"block\.(timestamp|number)")
        for contract in contract_data:
            source = contract.get("source", "")
            match = pattern.search(source)
            if not match:
                continue
            line = source[:match.start()].count("\n") + 1
            findings.append(self._create_finding(
                title="Potential front-running via block.timestamp/number",
                file=contract.get("path", ""),
                line=line,
                vulnerable_snippet=match.group(0),
            ))
        return findings
# EOF: hawki/core/static_rule_engine/rules/front_running.py