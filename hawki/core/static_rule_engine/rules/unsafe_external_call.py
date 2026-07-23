# --------------------
# File: hawki/core/static_rule_engine/rules/unsafe_external_call.py
# --------------------
"""
Unchecked low-level external call detection.

The tree-sitter parser exposes function metadata but not function bodies, so
this rule works on the raw contract ``source`` text produced by the indexer:
it isolates each function body by brace matching and flags a low-level
``.call(`` / ``.call{value:..}(`` / ``.call.value(..)(`` whose boolean success
result is never checked (not wrapped in ``require``/``if``/``assert``/
``return`` and not consulted within the next few lines). The legacy metadata
path (top-level ``functions`` entries carrying a ``body`` string, as used by
unit tests) is preserved.
"""

import re
from typing import Iterator, Tuple

from . import BaseRule
from .access_control_bypass import strip_comments

# Start of a function definition, up to the opening brace of its body.
_FUNC_HEADER = re.compile(r"function\s+(\w+)\s*\([^;{}]*?\)([^;{}]*?)\{", re.DOTALL)
# A gas-forwarding low-level call: `.call(`, `.call{value:..}(`, `.call.value(..)(`.
# Does not match `.staticcall` / `.delegatecall` / `.transfer` / `.send`.
_LOWLEVEL_CALL = re.compile(r"\.call\b")
# The statement prefix wraps the call in a control-flow check or returns it.
_WRAPPED_CHECK = re.compile(r"\b(?:require|assert|if|while|return)\b")
# First assigned identifier in the statement prefix: `(bool ok, ...) =` / `ok =`.
_ASSIGN_TARGET = re.compile(r"\(?\s*(?:bool\s+)?([A-Za-z_]\w*)")


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


def _success_checked(body: str, call_pos: int) -> bool:
    """True if the low-level call at ``call_pos`` has its success result checked."""
    stmt_start = max(
        body.rfind(";", 0, call_pos),
        body.rfind("{", 0, call_pos),
        body.rfind("}", 0, call_pos),
    ) + 1
    prefix = body[stmt_start:call_pos]
    # `require(x.call(..))`, `if (!x.call(..))`, `return x.call(..)` etc.
    if _WRAPPED_CHECK.search(prefix):
        return True
    # A bare statement drops the success value entirely.
    if "=" not in prefix:
        return False
    target = _ASSIGN_TARGET.search(prefix)
    if not target:
        return False
    ok = re.escape(target.group(1))
    stmt_end = body.find(";", call_pos)
    if stmt_end == -1:
        stmt_end = len(body)
    # The captured success flag must be consulted within the next few lines.
    window = "\n".join(body[stmt_end + 1:].split("\n")[:4])
    return bool(re.search(
        rf"\b(?:require|assert|if|revert|return)\b[^;{{]*\b{ok}\b", window
    ))


class UnsafeExternalCallRule(BaseRule):
    severity = "Critical"
    explanation_template = (
        "Making an external call (e.g., transferring ETH) before updating internal state allows the called contract to re-enter "
        "and exploit the incomplete state, leading to reentrancy attacks."
    )
    impact_template = (
        "An attacker can drain funds by re-entering the function before state updates."
    )
    fix_template = (
        "Apply the checks-effects-interactions pattern: update state before making external calls, or use a reentrancy guard."
    )

    def run_check(self, contract_data):
        findings = []
        seen = set()
        for contract in contract_data:
            path = contract.get("path", "")
            # Source-text path: the shape the RepositoryIndexer produces.
            source = contract.get("source", "")
            if source:
                clean = strip_comments(source)
                for name, _header, body, start_line in _iter_function_bodies(clean):
                    for call in _LOWLEVEL_CALL.finditer(body):
                        if _success_checked(body, call.start()):
                            continue
                        call_line = start_line + body[:call.start()].count("\n")
                        key = (path, call_line)
                        if key in seen:
                            continue
                        seen.add(key)
                        line_text = body.split("\n")[body[:call.start()].count("\n")]
                        findings.append(self._create_finding(
                            title="External call before state update (reentrancy risk)",
                            file=path,
                            line=call_line,
                            vulnerable_snippet=line_text.strip()
                                               or f"unchecked .call in {name}()",
                            function_name=name,
                        ))
            # Legacy metadata path: unit tests supply top-level `functions`
            # dicts with a `body` string (the real parser never fills these).
            for func in contract.get("functions", []):
                func_body = func.get("body", "")
                if ".call" not in func_body:
                    continue
                lines = func_body.split("\n")
                call_line = None
                for i, line in enumerate(lines):
                    if ".call" in line:
                        call_line = i
                        break
                if call_line is None or call_line >= len(lines) - 1:
                    continue
                for j in range(call_line + 1, len(lines)):
                    if "=" in lines[j] and not lines[j].strip().startswith("//"):
                        line_num = func.get("line", 0) + call_line + 1
                        key = (path, line_num)
                        if key in seen:
                            break
                        seen.add(key)
                        findings.append(self._create_finding(
                            title="External call before state update (reentrancy risk)",
                            file=path,
                            line=line_num,
                            vulnerable_snippet=lines[call_line].strip(),
                            function_name=func.get("name"),
                        ))
                        break
        return findings
# EOF: hawki/core/static_rule_engine/rules/unsafe_external_call.py
