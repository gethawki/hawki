# --------------------
# File: hawki/core/static_rule_engine/rules/tx_origin_dependency.py
# --------------------
"""
tx.origin authentication: detect use of tx.origin in authorization logic.

Comments are stripped before matching, the safe EOA check
(`msg.sender == tx.origin` and variants) is not reported, and findings are
deduplicated per line.
"""

import re

from . import BaseRule
from .access_control_bypass import strip_comments

_TX_ORIGIN_RE = re.compile(r'tx\.origin')
_EOA_CHECK_RE = re.compile(
    r'msg\.sender\s*[=!]=\s*tx\.origin|tx\.origin\s*[=!]=\s*msg\.sender'
)


class TxOriginRule(BaseRule):
    severity = "High"
    explanation_template = (
        "Using `tx.origin` for authentication is dangerous because it represents the original sender of "
        "the transaction, which can be different from `msg.sender` in a chain of calls. An attacker can "
        "trick a contract into using the caller's `tx.origin` to bypass checks."
    )
    impact_template = (
        "Phishing attacks can trick users into interacting with malicious contracts that then call the "
        "vulnerable contract, appearing as if the user is calling directly."
    )
    fix_template = (
        "Use `msg.sender` instead of `tx.origin` for authentication. If you need to know the original "
        "sender, consider other patterns or clearly document the risks."
    )

    def run_check(self, contract_data):
        findings = []
        for contract in contract_data:
            source = strip_comments(contract.get("source", ""))
            path = contract.get("path", "")
            seen_lines = set()
            for match in _TX_ORIGIN_RE.finditer(source):
                line = source[:match.start()].count('\n') + 1
                if line in seen_lines:
                    continue
                surrounding = source[max(0, match.start() - 60):min(len(source), match.end() + 60)]
                if _EOA_CHECK_RE.search(surrounding):
                    continue
                seen_lines.add(line)
                snippet = source[match.start():match.end()]
                findings.append(self._create_finding(
                    title="Use of tx.origin for authentication",
                    file=path,
                    line=line,
                    vulnerable_snippet=snippet,
                ))
        return findings
# EOF: hawki/core/static_rule_engine/rules/tx_origin_dependency.py
