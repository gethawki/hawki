# --------------------
# File: hawki/core/static_rule_engine/rules/outdated_solidity.py
# --------------------
"""
Outdated Solidity compiler version detection.

Flags `pragma solidity` statements whose first version number is below 0.8.
Compilers before 0.8 lack built-in overflow/underflow checks and miss years of
compiler bug fixes. Works on the raw contract ``source`` text with comments and
strings masked out. Emits at most one finding per file.
"""

import re
from typing import Any, Dict, Iterator, List, Tuple

from . import BaseRule

_PRAGMA = re.compile(r"pragma\s+solidity\s+([^;]+);")
_VERSION = re.compile(r"(\d+)\.(\d+)")
_MODERN = (0, 8)


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


class OutdatedSolidityRule(BaseRule):
    severity = "Low"
    explanation_template = (
        "The contract targets a Solidity compiler older than 0.8. Pre-0.8 compilers do "
        "not perform automatic arithmetic overflow/underflow checks and lack numerous "
        "compiler bug fixes and safety improvements introduced since."
    )
    impact_template = (
        "Arithmetic silently wraps on overflow/underflow unless a library like SafeMath "
        "is used consistently, and the contract remains exposed to known bugs fixed in "
        "newer compiler releases."
    )
    fix_template = (
        "Upgrade the contract to a modern compiler, e.g. `pragma solidity 0.8.24;`, and "
        "re-test: 0.8+ reverts on arithmetic overflow/underflow by default."
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
                version = _VERSION.search(match.group(1))
                if not version:
                    continue
                major, minor = int(version.group(1)), int(version.group(2))
                if (major, minor) >= _MODERN:
                    continue
                line = masked[: match.start()].count("\n") + 1
                findings.append(self._create_finding(
                    title="Outdated Solidity version",
                    file=path,
                    line=line,
                    vulnerable_snippet=match.group(0).strip(),
                ))
                seen.add(path)
                break  # one finding per file
        return findings
# EOF: hawki/core/static_rule_engine/rules/outdated_solidity.py
