# --------------------
# File: hawki/core/static_rule_engine/rules/reused_nonce.py
# --------------------
"""
Reused nonce in signatures: missing nonce tracking allows signature replay.
"""

import re

from . import BaseRule


class ReusedNonceRule(BaseRule):
    severity = "High"
    explanation_template = (
        "When using signatures for authorization, a nonce should be included and tracked to prevent replay attacks. "
        "If the same signature can be used multiple times, an attacker can reuse it."
    )
    impact_template = (
        "An attacker can replay a valid signature to perform actions multiple times, such as withdrawing funds multiple times."
    )
    fix_template = (
        "Include a nonce in the signed message, and store used nonces in a mapping. Increment the nonce after each use."
    )

    def run_check(self, contract_data):
        findings = []
        for contract in contract_data:
            source = contract.get("source", "")
            # Look for signature verification without nonce
            if "ecrecover" in source and "nonce" not in source:
                # crude
                match = re.search(r'ecrecover\s*\(', source)
                line = source[:match.start()].count('\n') + 1 if match else 1
                findings.append(self._create_finding(
                    title="Missing nonce in signature verification",
                    file=contract.get("path", ""),
                    line=line,
                    vulnerable_snippet="Signature verification without nonce",
                ))
        return findings
# EOF: hawki/core/static_rule_engine/rules/reused_nonce.py