# --------------------
# File: hawki/core/static_rule_engine/rules/divide_before_multiply.py
# --------------------
"""
Division-before-multiplication detection.

Solidity integer division truncates, so ``a / b * c`` silently loses precision
compared to ``a * c / b``. The parser exposes no expression trees, so this rule
works on the raw ``source`` text: comments and string literals are blanked out
first (preserving offsets), then each line is scanned for a division operator
followed later on the same line by a multiplication operator.
"""

import re
from typing import Any, Dict, List

from . import BaseRule

# A real division: an operand character, `/`, then an operand character.
# Excludes `//`, `/*`, `*/` and `/=` because the char after `/` must be \w or `(`.
_DIV = re.compile(r"[\w)\]]\s*/\s*[\w(]")
# A real multiplication after the division: `*` that is not `**`, `*=`, `*/` or `/*`.
_MUL = re.compile(r"(?<![*/])\*(?![*=/])")


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


class DivideBeforeMultiplyRule(BaseRule):
    severity = "Medium"
    explanation_template = (
        "Solidity integer division truncates toward zero, so performing a division "
        "before a multiplication (e.g. `a / b * c`) discards the remainder before it "
        "can be scaled back up, producing a smaller result than the mathematically "
        "equivalent `a * c / b`."
    )
    impact_template = (
        "Accumulated rounding errors can systematically short-change users in reward, "
        "share, or price calculations, and in edge cases truncate small amounts to zero."
    )
    fix_template = (
        "Reorder the arithmetic so multiplications happen before divisions "
        "(`a * c / b` instead of `a / b * c`), or use a higher-precision "
        "fixed-point library."
    )

    def run_check(self, contract_data: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        findings = []
        for entry in contract_data:
            source = entry.get("source", "")
            path = entry.get("path", "")
            if not source:
                continue
            for lineno, line in enumerate(_sanitize(source).split("\n"), start=1):
                div = _DIV.search(line)
                if not div:
                    continue
                if not _MUL.search(line, div.end()):
                    continue
                findings.append(self._create_finding(
                    title="Division before multiplication",
                    file=path,
                    line=lineno,
                    vulnerable_snippet=line.strip(),
                ))
        return findings
# EOF: hawki/core/static_rule_engine/rules/divide_before_multiply.py
