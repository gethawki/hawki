# --------------------
# File: hawki/core/static_rule_engine/rules/signature_malleability.py
# --------------------
"""
Signature malleability: using ecrecover without checking for signature malleability.
"""

import re

from . import BaseRule


class SignatureMalleabilityRule(BaseRule):
    severity = "High"
    explanation_template = (
        "The `ecrecover` function returns an address, but signatures can be malleable: there exist multiple valid signatures "
        "for the same message and private key. If the contract does not prevent reuse, an attacker could replay a modified signature."
    )
    impact_template = (
        "An attacker could reuse a signature multiple times or craft a different signature that still passes, leading to replay attacks."
    )
    fix_template = (
        "Use OpenZeppelin's `ECDSA` library which handles signature malleability by requiring that `s` is in the lower half order, "
        "and `v` is 27 or 28. Also, include a nonce to prevent replay."
    )

    def run_check(self, contract_data):
        findings = []
        for contract in contract_data:
            source = contract.get("source", "")
            if "ecrecover" in source:
                # Check if they use OpenZeppelin's ECDSA
                if "ECDSA" not in source:
                    # Find line
                    match = re.search(r'ecrecover\s*\(', source)
                    line = source[:match.start()].count('\n') + 1 if match else 1
                    findings.append(self._create_finding(
                        title="Potential signature malleability",
                        file=contract.get("path", ""),
                        line=line,
                        vulnerable_snippet="ecrecover(...) used without malleability checks",
                    ))
        return findings
# EOF: hawki/core/static_rule_engine/rules/signature_malleability.py