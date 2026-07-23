# --------------------
# File: hawki/core/static_rule_engine/rules/permit_replay.py
# --------------------
"""
Permit signature replay: detect missing nonce/replay protection in EIP-2612 permit.
"""

import re

from . import BaseRule


class PermitReplayRule(BaseRule):
    severity = "Critical"
    explanation_template = (
        "EIP-2612 `permit` functions must include a nonce to prevent signature replay across chains or after the permit is used. "
        "Without proper nonce tracking, the same signature can be reused multiple times."
    )
    impact_template = (
        "An attacker can replay a permit signature to spend tokens multiple times, draining user funds."
    )
    fix_template = (
        "Implement a nonce mapping and increment it after each use, as specified in EIP-2612."
    )

    def run_check(self, contract_data):
        findings = []
        for contract in contract_data:
            source = contract.get("source", "")
            # Look for a function named permit
            if "function permit" in source:
                # Check if it uses nonces
                if "nonces" not in source or "nonce" not in source:
                    # Find line of permit function
                    match = re.search(r'function\s+permit\s*\(', source)
                    line = source[:match.start()].count('\n') + 1 if match else 1
                    snippet = "function permit(...) ..."
                    findings.append(self._create_finding(
                        title="Missing nonce in permit (signature replay)",
                        file=contract.get("path", ""),
                        line=line,
                        vulnerable_snippet=snippet,
                    ))
        return findings
# EOF: hawki/core/static_rule_engine/rules/permit_replay.py