# --------------------
# File: hawki/core/static_rule_engine/rules/tx_gasprice_dependency.py
# --------------------
"""
Dependence on ``tx.gasprice``.

`tx.gasprice` is entirely attacker-chosen (the transaction sender sets it), so
any logic keyed on it, refunds, gates, or "anti-bot" checks, can be steered by
whoever submits the transaction. This rule works on the raw ``source`` text:
comments/strings are blanked out, then every remaining `tx.gasprice` reference
is flagged.
"""

import re
from typing import Any, Dict, List

from . import BaseRule

_TX_GASPRICE = re.compile(r"\btx\s*\.\s*gasprice\b")


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


class TxGaspriceDependencyRule(BaseRule):
    severity = "Low"
    explanation_template = (
        "The contract reads `tx.gasprice`, a value chosen freely by the transaction "
        "sender. Any refund, reward, or access decision derived from it is under the "
        "caller's control, and post-EIP-1559 its meaning differs across networks."
    )
    impact_template = (
        "A caller can set an arbitrary gas price to inflate gas-based refunds or "
        "rewards, or to slip past gas-price-based bot protections."
    )
    fix_template = (
        "Remove logic that depends on `tx.gasprice`; if gas compensation is required, "
        "cap it with a contract-controlled constant instead of trusting the "
        "sender-supplied price."
    )

    def run_check(self, contract_data: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        findings = []
        for entry in contract_data:
            source = entry.get("source", "")
            path = entry.get("path", "")
            if not source:
                continue
            clean = _sanitize(source)
            for match in _TX_GASPRICE.finditer(clean):
                lineno = clean[:match.start()].count("\n") + 1
                findings.append(self._create_finding(
                    title="Dependence on tx.gasprice",
                    file=path,
                    line=lineno,
                    vulnerable_snippet=match.group(0),
                ))
        return findings
# EOF: hawki/core/static_rule_engine/rules/tx_gasprice_dependency.py
