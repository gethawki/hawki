# --------------------
# File: hawki/core/static_rule_engine/rules/inline_assembly.py
# --------------------
"""
Inline assembly usage detection (informational).

Flags every `assembly { ... }` block (including dialect-tagged blocks such as
`assembly "evmasm" { ... }`). Inline assembly bypasses Solidity's type system
and safety checks, so each occurrence deserves reviewer attention even though
it is not a vulnerability by itself. Works on the raw contract ``source`` text
with comments and string literals masked out.
"""

import re
from typing import Any, Dict, Iterator, List, Tuple

from . import BaseRule

_ASSEMBLY = re.compile(r"\bassembly\s*(?:\"[^\"]*\")?\s*\{")


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


class InlineAssemblyRule(BaseRule):
    severity = "Info"
    explanation_template = (
        "The contract contains an inline `assembly` block. Assembly bypasses "
        "Solidity's type system, overflow checks and memory-safety guarantees, so any "
        "mistake inside the block goes undetected by the compiler."
    )
    impact_template = (
        "Errors in hand-written assembly (wrong memory offsets, missing checks, "
        "unchecked external call results) can corrupt state or leak funds without any "
        "compiler warning. This is informational; assembly is often legitimate."
    )
    fix_template = (
        "Prefer high-level Solidity where possible. If assembly is required, keep the "
        "block minimal, mark it `memory-safe` when applicable, document the invariants "
        "it relies on, and cover it with targeted tests."
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
            for match in _ASSEMBLY.finditer(masked):
                line = masked[: match.start()].count("\n") + 1
                key = (path, line)
                if key in seen:
                    continue
                seen.add(key)
                findings.append(self._create_finding(
                    title="Inline assembly used",
                    file=path,
                    line=line,
                    vulnerable_snippet=match.group(0).strip(),
                ))
        return findings
# EOF: hawki/core/static_rule_engine/rules/inline_assembly.py
