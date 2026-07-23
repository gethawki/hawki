# --------------------
# File: hawki/core/static_rule_engine/rules/reentrancy.py
# --------------------
"""
Reentrancy detection.

The tree-sitter parser exposes function metadata but not function bodies, so this
rule works on the raw contract ``source`` text: it isolates each function body by
brace matching and flags the classic checks-effects-interactions violation, a
gas-forwarding low-level ``.call`` followed by a state write, when the function is
not protected by a reentrancy guard. ``.transfer``/``.send`` are treated as safe
(they forward only 2300 gas), so they are not flagged.
"""

import re
from typing import Any, Dict, Iterator, List, Tuple

from . import BaseRule

# Start of a function definition, up to the opening brace of its body.
_FUNC_HEADER = re.compile(r"function\s+(\w+)\s*\([^;{}]*?\)([^;{}]*?)\{", re.DOTALL)
# A gas-forwarding low-level call in any of its forms: `.call(`, `.call{value:..}(`,
# `.call.value(..)(`. Does not match `.staticcall`/`.delegatecall`/`.transfer`/`.send`.
_LOWLEVEL_CALL = re.compile(r"\.call\b")
# An assignment to a (possibly indexed / member) name, i.e. a likely state write.
_STATE_WRITE = re.compile(r"^\s*[A-Za-z_]\w*(?:\.\w+|\s*\[[^\]]*\])*\s*(?:=|\+=|-=|\*=)(?!=)")
# A local variable declaration (not a state write) to be skipped.
_LOCAL_DECL = re.compile(r"^\s*(?:uint\d*|int\d*|address|bool|bytes\d*|string|mapping|var)\b")
_GUARD = re.compile(r"nonReentrant|noReentrancy|nonreentrant")


def _iter_function_bodies(source: str) -> Iterator[Tuple[str, str, str, int]]:
    """Yield (name, header, body, start_line) for each function via brace matching."""
    for match in _FUNC_HEADER.finditer(source):
        name, header = match.group(1), match.group(2)
        brace_start = match.end() - 1
        depth, i = 0, brace_start
        while i < len(source):
            if source[i] == "{":
                depth += 1
            elif source[i] == "}":
                depth -= 1
                if depth == 0:
                    break
            i += 1
        body = source[brace_start + 1:i]
        start_line = source[:match.start()].count("\n") + 1
        yield name, header, body, start_line


class ReentrancyRule(BaseRule):
    severity = "Critical"
    explanation_template = (
        "Reentrancy occurs when a function makes an external call before updating its own state. "
        "The external call can invoke the same function again, leading to recursive calls and draining funds."
    )
    impact_template = (
        "An attacker can steal all funds from the contract by recursively calling the vulnerable function."
    )
    fix_template = (
        "Apply the checks-effects-interactions pattern: update state before making external calls, "
        "and consider using a reentrancy guard modifier like OpenZeppelin's `nonReentrant`."
    )

    def _iter_sources(self, contract_data: List[Dict[str, Any]]) -> Iterator[Tuple[str, str]]:
        """Yield (path, source) from the indexer's file-level dicts (or any dict carrying source)."""
        for entry in contract_data:
            source = entry.get("source")
            if source:
                yield entry.get("path", ""), source

    def run_check(self, contract_data: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        findings = []
        for path, source in self._iter_sources(contract_data):
            for name, header, body, start_line in _iter_function_bodies(source):
                if _GUARD.search(header):
                    continue
                call = _LOWLEVEL_CALL.search(body)
                if not call:
                    continue
                # A state write that appears AFTER the external call is the
                # checks-effects-interactions violation. State writes before the
                # call (the fixed pattern) are safe and must not be flagged.
                after = body[call.end():]
                writes_after = False
                for bline in after.split("\n"):
                    if _LOCAL_DECL.match(bline):
                        continue
                    if _STATE_WRITE.match(bline):
                        writes_after = True
                        break
                if not writes_after:
                    continue
                call_line = start_line + body[:call.start()].count("\n")
                findings.append(self._create_finding(
                    title="Potential reentrancy vulnerability",
                    file=path,
                    line=call_line,
                    vulnerable_snippet="external .call before state update in "
                                       f"{name}()",
                    function_name=name,
                    visibility="public",
                ))
        return findings
# EOF: hawki/core/static_rule_engine/rules/reentrancy.py
