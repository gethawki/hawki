# --------------------
# File: hawki/core/static_rule_engine/rules/uninitialized_storage.py
# --------------------
"""
Uninitialized storage pointers: detect local storage variables that point to default slot 0.
"""

import re

from . import BaseRule


class UninitializedStorageRule(BaseRule):
    severity = "High"
    explanation_template = (
        "Local storage variables that are not initialized will point to storage slot 0 by default. "
        "This can accidentally overwrite important contract state if the variable is used without assignment."
    )
    impact_template = (
        "An attacker could exploit this to corrupt contract storage, leading to loss of funds or contract takeover."
    )
    fix_template = (
        "Always initialize local storage variables explicitly, or avoid using storage pointers when not needed. "
        "If you need a storage reference, ensure it points to a valid state variable."
    )

    def run_check(self, contract_data):
        findings = []
        # A genuinely uninitialized storage pointer is a LOCAL declaration that
        # is terminated (`;`) with no assignment, e.g. `User storage user;`.
        # The common, SAFE pattern `User storage user = map[key];` assigns the
        # pointer and must not be flagged, so the match requires the declaration
        # to end at `;` and explicitly excludes an `=` before it. `storage` used
        # as a function-parameter data location ends at `,`/`)` and is likewise
        # excluded.
        pattern = re.compile(r"\b[A-Za-z_]\w*\s+storage\s+[A-Za-z_]\w*\s*;")
        for contract in contract_data:
            source = contract.get("source", "")
            for match in pattern.finditer(source):
                line = source[:match.start()].count("\n") + 1
                findings.append(self._create_finding(
                    title="Uninitialized storage pointer",
                    file=contract.get("path", ""),
                    line=line,
                    vulnerable_snippet=match.group(0).strip(),
                ))
        return findings
# EOF: hawki/core/static_rule_engine/rules/uninitialized_storage.py