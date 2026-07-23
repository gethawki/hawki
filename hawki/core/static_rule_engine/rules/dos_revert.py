# --------------------
# File: hawki/core/static_rule_engine/rules/dos_revert.py
# --------------------
"""
Denial of Service via unexpected revert: functions that can be forced to revert by an attacker.
"""

import re

from . import BaseRule

# A low-level external call (`x.call(...)`, `x.call{...}(...)`, `x.call.value(...)`).
_CALL = re.compile(r'\.call\b')
# The result is handled (and cannot silently DoS) when the surrounding lines
# guard it with require/if/assert or an explicit revert.
_GUARD = re.compile(r'\b(require|assert|revert)\b|\bif\s*\(')


class DoSRevertRule(BaseRule):
    severity = "High"
    explanation_template = (
        "If a function can be forced to revert by an attacker (e.g., by making an external call that fails, "
        "or by manipulating state), it can lead to denial of service, locking funds or preventing legitimate use."
    )
    impact_template = (
        "An attacker could block critical contract functionality, such as withdrawals or governance votes, "
        "causing financial loss or governance paralysis."
    )
    fix_template = (
        "Avoid relying on external calls that can fail without alternatives. Use pull-over-push patterns, "
        "or handle failures gracefully (e.g., log and continue)."
    )

    def run_check(self, contract_data):
        findings = []
        # Look for patterns where an external call is not checked and could revert the whole function
        # For example: `address.call(...);` without `require` or `if`
        for contract in contract_data:
            source = contract.get("source", "")
            lines = source.split('\n')
            for i, line in enumerate(lines):
                stripped = line.strip()
                # Skip comments: a commented-out `.call` is not live code.
                if stripped.startswith('//') or stripped.startswith('*'):
                    continue
                if not _CALL.search(line):
                    continue
                # The real DoS smell is a call whose success is never inspected.
                # In production the captured result is almost always checked on
                # the very next line (`(bool ok,) = t.call(...); require(ok);`),
                # so consider a small window around the call: if it is guarded by
                # require/assert/revert/if there, it is handled, not a DoS risk.
                window = "\n".join(lines[i:i + 3])
                if _GUARD.search(window):
                    continue
                findings.append(self._create_finding(
                    title="Potential DoS via unchecked external call",
                    file=contract.get("path", ""),
                    line=i+1,
                    vulnerable_snippet=stripped,
                ))
        return findings
# EOF: hawki/core/static_rule_engine/rules/dos_revert.py