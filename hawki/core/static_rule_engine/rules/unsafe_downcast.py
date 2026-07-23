# --------------------
# File: hawki/core/static_rule_engine/rules/unsafe_downcast.py
# --------------------
"""
Unsafe integer downcast detection.

Casting a wider integer into a narrower type (`uint32(n)`, `uint128(amount)`, ...)
silently truncates the high bits; Solidity never reverts on a narrowing cast.
The parser exposes no function bodies, so this rule works on the raw ``source``
text: comments/strings are blanked out, then narrowing casts applied to a
variable (not a literal) are located. Casts that live in a function whose body
`require`s a bound on the same variable (the SafeCast / `safe32` pattern) are
treated as guarded and skipped. Findings are deduplicated to one per file.
"""

import re
from typing import Any, Dict, Iterator, List, Tuple

from . import BaseRule

# A narrowing cast applied to a plain identifier, e.g. `uint32(n)`.
_CAST = re.compile(
    r"\b(uint(?:8|16|32|64|96|128|160)|int(?:8|16|32|64|96|128))"
    r"\s*\(\s*([A-Za-z_]\w*)\s*\)"
)
# Start of a function definition, up to the opening brace of its body.
_FUNC_HEADER = re.compile(r"function\s+(\w+)\s*\([^;{}]*?\)([^;{}]*?)\{", re.DOTALL)


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


def _iter_function_spans(source: str) -> Iterator[Tuple[int, int]]:
    """Yield (body_start, body_end) offsets for each function via brace matching."""
    for match in _FUNC_HEADER.finditer(source):
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
        yield brace_start + 1, i


class UnsafeDowncastRule(BaseRule):
    severity = "Medium"
    explanation_template = (
        "Casting an integer to a narrower type silently truncates the value's high "
        "bits: Solidity performs no overflow check on explicit narrowing casts, so "
        "`uint32(n)` for any `n >= 2**32` wraps around instead of reverting."
    )
    impact_template = (
        "Truncated balances, timestamps, or identifiers can wrap to small or zero "
        "values, corrupting accounting and letting attackers bypass limits that were "
        "computed on the wider value."
    )
    fix_template = (
        "Bound-check the value before narrowing (e.g. `require(n <= type(uint32).max)`) "
        "or use OpenZeppelin's SafeCast library (`n.toUint32()`)."
    )

    def run_check(self, contract_data: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        findings = []
        for entry in contract_data:
            source = entry.get("source", "")
            path = entry.get("path", "")
            if not source:
                continue
            clean = _sanitize(source)
            spans = list(_iter_function_spans(clean))
            for match in _CAST.finditer(clean):
                var = match.group(2)
                # Locate the enclosing function body; a `require(` that mentions
                # the same variable there marks the guarded SafeCast pattern.
                guarded = False
                for start, end in spans:
                    if start <= match.start() < end:
                        body = clean[start:end]
                        if re.search(
                            r"require\s*\([^;]*\b" + re.escape(var) + r"\b", body
                        ):
                            guarded = True
                        break
                if guarded:
                    continue
                lineno = clean[:match.start()].count("\n") + 1
                findings.append(self._create_finding(
                    title="Unsafe integer downcast",
                    file=path,
                    line=lineno,
                    vulnerable_snippet=match.group(0),
                ))
                break  # dedupe: one finding per file
        return findings
# EOF: hawki/core/static_rule_engine/rules/unsafe_downcast.py
