# --------------------
# File: hawki/core/static_rule_engine/rules/selfdestruct_usage.py
# --------------------
"""
Selfdestruct usage detection.

Works on the raw contract ``source`` text (the parser does not emit function
bodies): comments and string literals are blanked out first, then any call to
``selfdestruct(...)`` or the legacy ``suicide(...)`` alias is flagged.
``selfdestruct`` irreversibly removes the contract code and force-sends its
balance, so any reachable path to it is a severe hazard (cf. the Parity
multisig freeze).
"""

import re
from typing import Any, Dict, Iterator, List, Tuple

from . import BaseRule

_SELFDESTRUCT = re.compile(r"\b(?:selfdestruct|suicide)\s*\(")


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


class SelfdestructUsageRule(BaseRule):
    severity = "High"
    explanation_template = (
        "The contract contains a `selfdestruct` (or legacy `suicide`) call. Selfdestruct removes the "
        "contract code from the chain and force-sends its entire balance to the target address. If the "
        "call is reachable by an attacker, or triggered by mistake, the contract and any funds routed "
        "through it are permanently destroyed."
    )
    impact_template = (
        "Anyone able to reach the selfdestruct path can permanently disable the contract, brick every "
        "dependent integration, and redirect the remaining balance. Since EIP-6780 the semantics also "
        "differ between chains, making behavior unpredictable."
    )
    fix_template = (
        "Remove the `selfdestruct` call. If a kill-switch is genuinely required, replace it with a "
        "pausable pattern (e.g. OpenZeppelin `Pausable`) plus an owner-gated withdrawal function."
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
            for match in _SELFDESTRUCT.finditer(masked):
                line = masked[: match.start()].count("\n") + 1
                key = (path, line)
                if key in seen:
                    continue
                seen.add(key)
                snippet = lines[line - 1].strip() if 0 < line <= len(lines) else match.group(0)
                findings.append(self._create_finding(
                    title="Use of selfdestruct",
                    file=path,
                    line=line,
                    vulnerable_snippet=snippet,
                ))
        return findings
# EOF: hawki/core/static_rule_engine/rules/selfdestruct_usage.py
