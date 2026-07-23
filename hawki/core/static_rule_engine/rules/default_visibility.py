# --------------------
# File: hawki/core/static_rule_engine/rules/default_visibility.py
# --------------------
"""
Default (implicit public) function visibility detection for pre-0.5 code.

Before Solidity 0.5.0 a function declared without a visibility keyword
defaulted to `public`, silently exposing internal logic to anyone (the root
cause of the 2017 Parity wallet hack). Solidity 0.5+ made visibility mandatory,
so this rule only fires when the file's pragma targets a compiler below 0.5;
on 0.5+ (or pragma-less) files it stays silent. Works on the raw contract
``source`` text with comments and string literals masked out.
"""

import re
from typing import Any, Dict, Iterator, List, Optional, Tuple

from . import BaseRule

_PRAGMA = re.compile(r"pragma\s+solidity\s+([^;]+);")
_VERSION = re.compile(r"(\d+)\.(\d+)")
_FUNC = re.compile(r"\bfunction\s+(\w+)?\s*\(")
_VISIBILITY = re.compile(r"\b(?:public|external|internal|private)\b")


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


def _pragma_version(masked: str) -> Optional[Tuple[int, int]]:
    """Return (major, minor) of the first pragma solidity version, if any."""
    pragma = _PRAGMA.search(masked)
    if not pragma:
        return None
    version = _VERSION.search(pragma.group(1))
    if not version:
        return None
    return int(version.group(1)), int(version.group(2))


def _close_paren(text: str, open_idx: int) -> int:
    """Index of the parenthesis matching text[open_idx] == '(' (or -1)."""
    depth = 0
    for i in range(open_idx, len(text)):
        if text[i] == "(":
            depth += 1
        elif text[i] == ")":
            depth -= 1
            if depth == 0:
                return i
    return -1


class DefaultVisibilityRule(BaseRule):
    severity = "Medium"
    explanation_template = (
        "The file targets a pre-0.5 Solidity compiler, where a function declared "
        "without an explicit visibility keyword silently defaults to `public`. "
        "Functions intended as internal helpers become callable by anyone."
    )
    impact_template = (
        "Anyone can invoke the implicitly-public function directly. If it mutates "
        "privileged state (the classic example being the Parity wallet's "
        "`initWallet`), an attacker can take over the contract or drain funds."
    )
    fix_template = (
        "Add an explicit visibility keyword (`external`, `public`, `internal` or "
        "`private`) to every function, and preferably upgrade to Solidity 0.5+ where "
        "explicit visibility is enforced by the compiler."
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
            version = _pragma_version(masked)
            # 0.5+ requires explicit visibility; without a pragma we assume modern.
            if version is None or version >= (0, 5):
                continue
            for match in _FUNC.finditer(masked):
                open_idx = masked.find("(", match.start())
                close_idx = _close_paren(masked, open_idx)
                if close_idx == -1:
                    continue
                # Header tail: everything between the parameter list and the body.
                brace = masked.find("{", close_idx)
                semi = masked.find(";", close_idx)
                if brace == -1 or (semi != -1 and semi < brace):
                    continue  # bodyless declaration (interface/abstract)
                tail = masked[close_idx + 1:brace]
                if _VISIBILITY.search(tail):
                    continue
                name = match.group(1) or "<fallback>"
                line = masked[: match.start()].count("\n") + 1
                key = (path, line)
                if key in seen:
                    continue
                seen.add(key)
                findings.append(self._create_finding(
                    title="Function without explicit visibility",
                    file=path,
                    line=line,
                    vulnerable_snippet=(
                        f"{name}() has no visibility keyword; "
                        "pre-0.5 this defaults to public"
                    ),
                    function_name=name,
                ))
        return findings
# EOF: hawki/core/static_rule_engine/rules/default_visibility.py
