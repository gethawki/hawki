# --------------------
# File: hawki/core/static_rule_engine/rules/missing_event_admin.py
# --------------------
"""
Missing event on privileged state change.

Flags externally reachable functions that assign to an ownership/admin state
variable (`owner`, `admin`, `_owner`, `_admin`, `pendingOwner`, `pendingAdmin`)
without emitting any event. Off-chain monitors rely on events to track
ownership handovers; a silent change is invisible to them. The rule stays
deliberately conservative (only owner/admin-style assignments, internal and
private helpers skipped) to avoid false positives. Works on the raw contract
``source`` text via brace-matched function-body extraction, with comments and
string literals masked out.
"""

import re
from typing import Any, Dict, Iterator, List, Tuple

from . import BaseRule

# Start of a function definition, up to the opening brace of its body.
_FUNC_HEADER = re.compile(r"function\s+(\w+)\s*\([^;{}]*?\)([^;{}]*?)\{", re.DOTALL)
# An assignment (not comparison) to an owner/admin-style state variable.
_ADMIN_ASSIGN = re.compile(
    r"(?:^|[\s;{}()])(_?owner|_?admin|pendingOwner|pendingAdmin)\b\s*=(?!=)"
)
_EMIT = re.compile(r"\bemit\s")
_NON_EXTERNAL = re.compile(r"\b(?:internal|private)\b")


def _mask_source(source: str) -> str:
    """Blank out comments and string literals, preserving offsets/newlines."""
    out = []
    i, n = 0, len(source)
    while i < n:
        ch = source[i]
        if ch == "/" and i + 1 < n and source[i + 1] == "/":
            j = source.find("\n", i)
            j = n if j == -1 else j
            out.append(" " * (j - i))
            i = j
        elif ch == "/" and i + 1 < n and source[i + 1] == "*":
            j = source.find("*/", i + 2)
            j = n if j == -1 else j + 2
            out.append("".join(c if c == "\n" else " " for c in source[i:j]))
            i = j
        elif ch in "\"'":
            j = i + 1
            while j < n and source[j] != ch:
                if source[j] == "\\":
                    j += 1
                j += 1
            j = min(j + 1, n)
            out.append("".join(c if c == "\n" else " " for c in source[i:j]))
            i = j
        else:
            out.append(ch)
            i += 1
    return "".join(out)


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


class MissingEventAdminRule(BaseRule):
    severity = "Low"
    explanation_template = (
        "A privileged function changes an ownership/admin state variable without "
        "emitting an event. Off-chain infrastructure (monitors, indexers, alerting) "
        "relies on events to observe critical configuration changes; a silent "
        "ownership or admin handover is invisible to them."
    )
    impact_template = (
        "A malicious or compromised admin can transfer control of the contract "
        "without leaving an easily observable on-chain trail, delaying detection and "
        "incident response."
    )
    fix_template = (
        "Emit a dedicated event for every admin/ownership change, e.g. "
        "`emit OwnershipTransferred(oldOwner, newOwner);` immediately after the "
        "assignment, or inherit OpenZeppelin's `Ownable` which does this for you."
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
            masked = _mask_source(source)
            for name, header, body, start_line in _iter_function_bodies(masked):
                # Internal/private helpers are usually wrapped by a public
                # function that emits; skip them to stay conservative.
                if _NON_EXTERNAL.search(header):
                    continue
                if _EMIT.search(body):
                    continue
                assign = _ADMIN_ASSIGN.search(body)
                if not assign:
                    continue
                key = (path, name)
                if key in seen:
                    continue
                seen.add(key)
                line = start_line + body[: assign.start()].count("\n")
                findings.append(self._create_finding(
                    title="State change without event",
                    file=path,
                    line=line,
                    vulnerable_snippet=(
                        f"`{assign.group(1)}` assigned in {name}() with no `emit`"
                    ),
                    function_name=name,
                ))
        return findings
# EOF: hawki/core/static_rule_engine/rules/missing_event_admin.py
