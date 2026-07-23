# --------------------
# File: hawki/core/static_rule_engine/rules/floating_pragma.py
# --------------------
"""
Floating pragma detection.

Flags `pragma solidity` statements that use a version *range* (`^`, `~`, `>=`,
`>`, `<`, `<=`) instead of an exact pin. Works on the raw contract ``source``
text; comments and string literals are masked out first so a commented-out
pragma is never flagged. Emits at most one finding per file.
"""

import re
from typing import Any, Dict, Iterator, List, Tuple

from . import BaseRule

_PRAGMA = re.compile(r"pragma\s+solidity\s+([^;]+);")
_RANGE_MARKER = re.compile(r"[\^~<>]")


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


class FloatingPragmaRule(BaseRule):
    severity = "Low"
    explanation_template = (
        "The contract uses a floating pragma (a version range such as `^0.8.0` or "
        "`>=0.6.0`). The exact compiler version used for deployment is therefore not "
        "locked, so the contract may be compiled with a newer compiler than it was "
        "tested with, potentially introducing behavioral differences or new bugs."
    )
    impact_template = (
        "Deployments become non-reproducible: different compiler versions can produce "
        "different bytecode, and an untested compiler release may contain bugs or "
        "changed semantics that affect the contract."
    )
    fix_template = (
        "Pin the pragma to the exact compiler version the contract was tested with, "
        "e.g. `pragma solidity 0.8.24;` instead of `pragma solidity ^0.8.24;`."
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
            if path in seen:
                continue
            masked = _mask_source(source)
            for match in _PRAGMA.finditer(masked):
                version_expr = match.group(1)
                if not _RANGE_MARKER.search(version_expr):
                    continue
                line = masked[: match.start()].count("\n") + 1
                findings.append(self._create_finding(
                    title="Floating pragma",
                    file=path,
                    line=line,
                    vulnerable_snippet=match.group(0).strip(),
                ))
                seen.add(path)
                break  # one finding per file
        return findings
# EOF: hawki/core/static_rule_engine/rules/floating_pragma.py
