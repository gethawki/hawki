# --------------------
# File: hawki/core/static_rule_engine/rules/array_length_assignment.py
# --------------------
"""
Direct array length assignment detection.

Before Solidity 0.6, storage array sizes could be changed by writing to
``.length`` directly (``arr.length = n`` / ``arr.length += 1``). Shrinking wipes
elements, growing exposes stale storage, and an unchecked decrement can
underflow to 2**256-1, granting writable access to (almost) all of storage.
The parser exposes no expression trees, so this rule works on the raw
``source`` text: comments/strings are blanked out, then each line is scanned
for an assignment to ``.length`` (comparisons like ``.length ==`` or
``.length <=`` never match).
"""

import re
from typing import Any, Dict, List

from . import BaseRule

# `.length` followed by an assignment operator; `=(?!=)` rejects `==`, and
# `<=`, `>=`, `!=` never match because their first char is not `=`, `+` or `-`.
_LENGTH_ASSIGN = re.compile(r"\.\s*length\s*(?:\+=|-=|=(?!=)|\+\+|--)")


def _sanitize(source: str) -> str:
    """Blank out comments and string contents, preserving length and newlines."""
    out = list(source)
    i, n = 0, len(source)
    while i < n:
        ch = source[i]
        if ch == "/" and i + 1 < n and source[i + 1] == "/":
            j = source.find("\n", i)
            j = n if j == -1 else j
            for k in range(i, j):
                out[k] = " "
            i = j
        elif ch == "/" and i + 1 < n and source[i + 1] == "*":
            j = source.find("*/", i + 2)
            j = n if j == -1 else j + 2
            for k in range(i, j):
                if out[k] != "\n":
                    out[k] = " "
            i = j
        elif ch in ('"', "'"):
            j = i + 1
            while j < n and source[j] != ch:
                if source[j] == "\\":
                    j += 1
                j += 1
            j = min(j + 1, n)
            for k in range(i + 1, j - 1):
                if out[k] != "\n":
                    out[k] = " "
            i = j
        else:
            i += 1
    return "".join(out)


class ArrayLengthAssignmentRule(BaseRule):
    severity = "Medium"
    explanation_template = (
        "The contract writes directly to a storage array's `.length` (a pre-0.6 "
        "Solidity feature). Manually resizing arrays this way bypasses element "
        "initialization and bounds handling."
    )
    impact_template = (
        "Growing the array exposes stale storage as live elements; an unchecked "
        "`length--` on an empty array underflows to 2**256-1, effectively making the "
        "whole storage space addressable and overwritable through the array."
    )
    fix_template = (
        "Use `push()`/`pop()` to resize storage arrays (the only supported way since "
        "Solidity 0.6), and guard any shrink with an explicit emptiness check."
    )

    def run_check(self, contract_data: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        findings = []
        for entry in contract_data:
            source = entry.get("source", "")
            path = entry.get("path", "")
            if not source:
                continue
            for lineno, line in enumerate(_sanitize(source).split("\n"), start=1):
                if _LENGTH_ASSIGN.search(line):
                    findings.append(self._create_finding(
                        title="Direct array length assignment",
                        file=path,
                        line=lineno,
                        vulnerable_snippet=line.strip(),
                    ))
        return findings
# EOF: hawki/core/static_rule_engine/rules/array_length_assignment.py
