# --------------------
# File: hawki/core/static_rule_engine/rules/deprecated_constructs.py
# --------------------
"""
Deprecated Solidity construct detection.

Flags usage of language constructs that Solidity has deprecated or removed:
`throw`, `sha3(`, `suicide(`, `var` declarations, `block.blockhash(` and the
`now` alias for `block.timestamp`. Works on the raw contract ``source`` text
with comments and string literals masked out so occurrences inside comments or
strings are never flagged. Findings are deduplicated per (file, construct).
"""

import re
from typing import Any, Dict, Iterator, List, Tuple

from . import BaseRule

_CONSTRUCTS: List[Tuple[str, "re.Pattern[str]", str]] = [
    ("throw", re.compile(r"\bthrow\b"),
     "use `revert()` / `require()` instead of `throw`"),
    ("sha3", re.compile(r"\bsha3\s*\("),
     "use `keccak256()` instead of `sha3()`"),
    ("suicide", re.compile(r"\bsuicide\s*\("),
     "use `selfdestruct()` instead of `suicide()`"),
    ("var", re.compile(r"\bvar\s+[A-Za-z_]\w*\s*="),
     "declare the explicit type instead of `var`"),
    ("block.blockhash", re.compile(r"\bblock\.blockhash\s*\("),
     "use the global `blockhash()` instead of `block.blockhash()`"),
    ("now", re.compile(r"\bnow\b"),
     "use `block.timestamp` instead of the deprecated `now` alias"),
]


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


class DeprecatedConstructsRule(BaseRule):
    severity = "Low"
    explanation_template = (
        "The contract uses a deprecated Solidity construct (`throw`, `sha3`, `suicide`, "
        "`var`, `block.blockhash` or `now`). These constructs have been superseded and "
        "removed in modern compiler versions, and their presence signals stale, "
        "unmaintained code that cannot compile on current toolchains."
    )
    impact_template = (
        "Deprecated constructs block compiler upgrades, may behave subtly differently "
        "from their replacements (e.g. `throw` consumes all remaining gas), and keep "
        "the contract tied to old compilers with known bugs."
    )
    fix_template = (
        "Replace deprecated constructs with their modern equivalents: `throw` -> "
        "`revert()`, `sha3()` -> `keccak256()`, `suicide()` -> `selfdestruct()`, "
        "`var` -> explicit types, `block.blockhash()` -> `blockhash()`, `now` -> "
        "`block.timestamp`."
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
            for keyword, pattern, advice in _CONSTRUCTS:
                if (path, keyword) in seen:
                    continue
                match = pattern.search(masked)
                if not match:
                    continue
                seen.add((path, keyword))
                line = masked[: match.start()].count("\n") + 1
                findings.append(self._create_finding(
                    title="Deprecated Solidity construct",
                    file=path,
                    line=line,
                    vulnerable_snippet=f"`{keyword}` is deprecated; {advice}",
                    construct=keyword,
                ))
        return findings
# EOF: hawki/core/static_rule_engine/rules/deprecated_constructs.py
