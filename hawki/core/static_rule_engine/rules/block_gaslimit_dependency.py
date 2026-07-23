# --------------------
# File: hawki/core/static_rule_engine/rules/block_gaslimit_dependency.py
# --------------------
"""
Dependence on ``block.gaslimit``.

`block.gaslimit` drifts as validators vote it up or down and differs wildly
between chains and forks, so contract logic keyed on it is fragile and, on some
networks, miner-influenceable. This rule works on the raw ``source`` text:
comments/strings are blanked out, then every remaining `block.gaslimit`
reference is flagged.
"""

import re
from typing import Any, Dict, List

from . import BaseRule

_BLOCK_GASLIMIT = re.compile(r"\bblock\s*\.\s*gaslimit\b")


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


class BlockGaslimitDependencyRule(BaseRule):
    severity = "Low"
    explanation_template = (
        "The contract reads `block.gaslimit`. Block producers adjust the gas limit "
        "within protocol bounds and its value varies across chains, so any check or "
        "computation built on it behaves unpredictably and can be nudged by "
        "validators."
    )
    impact_template = (
        "Logic gated on `block.gaslimit` (batch sizing, pseudo-randomness, "
        "environment checks) can break after network upgrades or be influenced by "
        "block producers to steer contract behavior."
    )
    fix_template = (
        "Replace `block.gaslimit` with an explicit, owner-configurable constant or "
        "parameter that expresses the intended bound directly."
    )

    def run_check(self, contract_data: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        findings = []
        for entry in contract_data:
            source = entry.get("source", "")
            path = entry.get("path", "")
            if not source:
                continue
            clean = _sanitize(source)
            for match in _BLOCK_GASLIMIT.finditer(clean):
                lineno = clean[:match.start()].count("\n") + 1
                findings.append(self._create_finding(
                    title="Dependence on block.gaslimit",
                    file=path,
                    line=lineno,
                    vulnerable_snippet=match.group(0),
                ))
        return findings
# EOF: hawki/core/static_rule_engine/rules/block_gaslimit_dependency.py
