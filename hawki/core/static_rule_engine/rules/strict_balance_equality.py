# --------------------
# File: hawki/core/static_rule_engine/rules/strict_balance_equality.py
# --------------------
"""
Strict balance equality detection.

Works on the raw contract ``source`` text (comments and strings masked out):
flags strict ``==`` comparisons against an ether balance, i.e.
``<expr>.balance == ...`` or ``... == address(this).balance``. Ether can be
force-sent to any contract (``selfdestruct``, pre-funded addresses, coinbase
rewards), so a strict equality on a balance can be broken by anyone sending
1 wei, permanently wedging the guarded logic.
"""

import re
from typing import Any, Dict, Iterator, List, Tuple

from . import BaseRule

# `<expr>.balance == ...` (not >=, <=, != and not ===-like typos), or
# `... == address(this).balance`.
_BALANCE_EQ = re.compile(
    r"\.balance\b\s*==(?!=)|==\s*address\s*\(\s*this\s*\)\s*\.\s*balance\b"
)


def _mask_comments_and_strings(source: str) -> str:
    """Blank comments and string literals with spaces, preserving offsets/newlines."""
    out = list(source)
    i, n = 0, len(source)
    while i < n:
        ch = source[i]
        nxt = source[i + 1] if i + 1 < n else ""
        if ch == "/" and nxt == "/":
            while i < n and source[i] != "\n":
                out[i] = " "
                i += 1
        elif ch == "/" and nxt == "*":
            out[i] = out[i + 1] = " "
            i += 2
            while i < n and not (source[i] == "*" and i + 1 < n and source[i + 1] == "/"):
                if source[i] != "\n":
                    out[i] = " "
                i += 1
            if i < n:
                out[i] = " "
            if i + 1 < n:
                out[i + 1] = " "
            i += 2
        elif ch in ('"', "'"):
            quote = ch
            out[i] = " "
            i += 1
            while i < n and source[i] != quote and source[i] != "\n":
                if source[i] == "\\" and i + 1 < n:
                    out[i] = " "
                    i += 1
                if source[i] != "\n":
                    out[i] = " "
                i += 1
            if i < n and source[i] == quote:
                out[i] = " "
                i += 1
        else:
            i += 1
    return "".join(out)


class StrictBalanceEqualityRule(BaseRule):
    severity = "Medium"
    explanation_template = (
        "The code compares an ether balance with strict equality (`==`). A contract's balance can be "
        "changed by anyone without triggering any of its code: `selfdestruct` force-sends, funding the "
        "address before deployment, or block-reward accrual. The assumed exact value therefore cannot be "
        "relied on."
    )
    impact_template = (
        "An attacker can force-send 1 wei to make the strict equality permanently false (or "
        "prematurely true), wedging state machines, blocking withdrawals/settlements, or unlocking "
        "logic that should have stayed closed."
    )
    fix_template = (
        "Replace strict equality with an inequality that tolerates extra ether, e.g. "
        "`require(address(this).balance >= expected)`, or track deposits in a dedicated accounting "
        "variable updated only by the contract's own logic."
    )

    def _iter_sources(self, contract_data: List[Dict[str, Any]]) -> Iterator[Tuple[str, str]]:
        for entry in contract_data:
            source = entry.get("source")
            if source:
                yield entry.get("path", ""), source

    def run_check(self, contract_data: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        findings = []
        seen = set()
        for path, source in self._iter_sources(contract_data):
            masked = _mask_comments_and_strings(source)
            lines = source.splitlines()
            for match in _BALANCE_EQ.finditer(masked):
                line = masked[: match.start()].count("\n") + 1
                key = (path, line)
                if key in seen:
                    continue
                seen.add(key)
                snippet = lines[line - 1].strip() if 0 < line <= len(lines) else match.group(0)
                findings.append(self._create_finding(
                    title="Strict equality on contract balance",
                    file=path,
                    line=line,
                    vulnerable_snippet=snippet,
                ))
        return findings
# EOF: hawki/core/static_rule_engine/rules/strict_balance_equality.py
