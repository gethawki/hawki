# --------------------
# File: hawki/core/static_rule_engine/rules/timestamp_dependency.py
# --------------------
"""
Timestamp dependency: using block.timestamp for critical logic may be manipulated by miners.
"""

import re

from . import BaseRule

# A comparison/branch operator. `block.timestamp` is only manipulable-relevant
# when it *gates* logic (a deadline/window check), i.e. it participates in a
# comparison. Merely stamping state (`lastUpdate = block.timestamp`) or
# emitting it in an event is pervasive and benign, so those are not flagged.
_COMPARISON = re.compile(r"(?:[<>]=?|[!=]=)")

# Branch/guard constructs whose condition is evaluated on the same line.
_BRANCH = re.compile(r"\b(?:require|if|while)\s*\(")

_TIMESTAMP = "block.timestamp"

# Blank out comments while preserving offsets/line numbers.
_COMMENT = re.compile(r"//[^\n]*|/\*.*?\*/", re.DOTALL)


def _strip_comments(source: str) -> str:
    return _COMMENT.sub(lambda m: re.sub(r"[^\n]", " ", m.group(0)), source)


class TimestampDependencyRule(BaseRule):
    severity = "Medium"
    explanation_template = (
        "Miners have some influence over `block.timestamp`. Using it for critical logic (e.g., time-based "
        "transitions, deadlines) can be manipulated within a range of about 15 seconds."
    )
    impact_template = (
        "An attacker could manipulate timestamps to gain unfair advantages, such as delaying or accelerating "
        "time-sensitive operations."
    )
    fix_template = (
        "Avoid relying on `block.timestamp` for precise logic. If necessary, accept a small variance "
        "or use a trusted oracle like Chainlink VRF for randomness."
    )

    def run_check(self, contract_data):
        findings = []
        for contract in contract_data:
            source = contract.get("source", "")
            if _TIMESTAMP not in source:
                continue
            clean = _strip_comments(source)
            for line_no, line in enumerate(clean.splitlines(), start=1):
                if _TIMESTAMP not in line:
                    continue
                # Only flag manipulable "critical logic": the timestamp must
                # participate in a comparison or gate a branch. Benign
                # storage/accounting uses (`lastRewardTime = block.timestamp;`,
                # `return block.timestamp;`) are skipped.
                if not (_COMPARISON.search(line) or _BRANCH.search(line)):
                    continue
                findings.append(self._create_finding(
                    title="Timestamp dependency",
                    file=contract.get("path", ""),
                    line=line_no,
                    vulnerable_snippet=line.strip(),
                ))
                # Dedupe: one finding per contract is enough to signal the issue.
                break
        return findings
# EOF: hawki/core/static_rule_engine/rules/timestamp_dependency.py
