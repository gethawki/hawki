# --------------------
# File: hawki/core/static_rule_engine/rules/weak_randomness_modulo.py
# --------------------
"""
Weak randomness via modulo on block values.

Taking a value derived from `block.timestamp`, `block.number`,
`block.difficulty`, `block.prevrandao`, or `blockhash(...)` modulo some bound is
the classic on-chain "random number" anti-pattern: every input is known to (or
influenced by) miners/validators and other transactions in the same block. The
parser exposes no expression trees, so this rule works on the raw ``source``
text: comments/strings are blanked out, then each statement is scanned for a
`%` operator co-occurring with a block-derived value.
"""

import re
from typing import Any, Dict, List

from . import BaseRule

_BLOCK_VALUE = re.compile(
    r"\bblock\s*\.\s*(?:timestamp|number|difficulty|prevrandao)\b|\bblockhash\s*\("
)


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


class WeakRandomnessModuloRule(BaseRule):
    severity = "High"
    explanation_template = (
        "The contract derives a pseudo-random number by taking a block value "
        "(timestamp, number, difficulty/prevrandao, or blockhash) modulo a bound. "
        "All of these inputs are visible on-chain before execution and several can "
        "be influenced by block producers, so the 'random' outcome is predictable."
    )
    impact_template = (
        "An attacker (or a colluding validator) can predict or bias the outcome of "
        "lotteries, raffles, loot drops, or any selection logic built on this value, "
        "winning at will and draining the associated funds."
    )
    fix_template = (
        "Use a verifiable randomness source such as Chainlink VRF, or a "
        "commit-reveal scheme; never derive randomness from block metadata."
    )

    def run_check(self, contract_data: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        findings = []
        for entry in contract_data:
            source = entry.get("source", "")
            path = entry.get("path", "")
            if not source:
                continue
            clean = _sanitize(source)
            seen_lines = set()
            # A "statement" is a run of text between `;`, `{` and `}` so that a
            # modulo and the block value only pair up inside one expression.
            for stmt in re.finditer(r"[^;{}]+", clean):
                text = stmt.group(0)
                if "%" not in text:
                    continue
                block_ref = _BLOCK_VALUE.search(text)
                if not block_ref:
                    continue
                offset = stmt.start() + block_ref.start()
                lineno = clean[:offset].count("\n") + 1
                if (path, lineno) in seen_lines:
                    continue
                seen_lines.add((path, lineno))
                findings.append(self._create_finding(
                    title="Weak randomness from block values",
                    file=path,
                    line=lineno,
                    vulnerable_snippet=" ".join(text.split()),
                ))
        return findings
# EOF: hawki/core/static_rule_engine/rules/weak_randomness_modulo.py
