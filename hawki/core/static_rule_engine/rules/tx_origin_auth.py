# --------------------
# File: hawki/core/static_rule_engine/rules/tx_origin_auth.py
# --------------------
"""
tx.origin used for authentication - critical risk.

Comments are stripped before matching, the safe EOA check
(`msg.sender == tx.origin` and variants) is not reported, and findings are
deduplicated per line.
"""

import re

from . import BaseRule
from .access_control_bypass import strip_comments

_TX_ORIGIN_RE = re.compile(r'tx\.origin')
# Safe pattern: comparing msg.sender against tx.origin is the standard
# "no contracts" EOA check, not user authentication.
_EOA_CHECK_RE = re.compile(
    r'msg\.sender\s*[=!]=\s*tx\.origin|tx\.origin\s*[=!]=\s*msg\.sender'
)
_AUTH_CONTEXT_RE = re.compile(r'\b(require|if|revert)\b')


class TxOriginAuthRule(BaseRule):
    severity = "Critical"
    explanation_template = (
        "Using `tx.origin` for authentication is dangerous because it represents the original sender of the transaction. "
        "If a contract uses `tx.origin` to authorize critical actions, an attacker can trick a user into interacting with a malicious "
        "contract that then calls the vulnerable contract, appearing as if the user is calling directly."
    )
    impact_template = (
        "An attacker can perform privileged actions on behalf of the user, such as stealing funds or changing ownership."
    )
    fix_template = (
        "Use `msg.sender` instead of `tx.origin` for authentication. If you must know the original sender, consider using "
        "`tx.origin` only for specific use cases like preventing multi-contract attacks, but never for authorization."
    )

    def run_check(self, contract_data):
        findings = []
        for contract in contract_data:
            source = strip_comments(contract.get("source", ""))
            path = contract.get("path", "")
            seen_lines = set()
            # Find occurrences of tx.origin, especially in require statements or if conditions
            for match in _TX_ORIGIN_RE.finditer(source):
                line = source[:match.start()].count('\n') + 1
                if line in seen_lines:
                    continue
                snippet = source[match.start():match.end()]
                # Check if it's used in a condition (likely for auth)
                surrounding = source[max(0, match.start() - 60):min(len(source), match.end() + 60)]
                if _EOA_CHECK_RE.search(surrounding):
                    continue
                if _AUTH_CONTEXT_RE.search(surrounding):
                    seen_lines.add(line)
                    findings.append(self._create_finding(
                        title="tx.origin used for authentication",
                        file=path,
                        line=line,
                        vulnerable_snippet=snippet,
                    ))
        return findings
# EOF: hawki/core/static_rule_engine/rules/tx_origin_auth.py
