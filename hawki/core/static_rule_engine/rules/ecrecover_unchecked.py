# --------------------
# File: hawki/core/static_rule_engine/rules/ecrecover_unchecked.py
# --------------------
"""
Unvalidated ``ecrecover`` result detection.

`ecrecover` returns `address(0)` for an invalid signature instead of reverting.
If the caller never compares the recovered address against `address(0)` (or
otherwise `require`s it), a garbage signature "authenticates" as the zero
address, which frequently matches uninitialized storage slots. The parser
exposes no function bodies, so this rule isolates each function body from the
raw ``source`` by brace matching (after blanking comments/strings) and flags
`ecrecover` calls whose result is never zero-checked inside that body.
"""

import re
from typing import Any, Dict, Iterator, List, Tuple

from . import BaseRule

# Start of a function definition, up to the opening brace of its body.
_FUNC_HEADER = re.compile(r"function\s+(\w+)\s*\([^;{}]*?\)([^;{}]*?)\{", re.DOTALL)
_ECRECOVER = re.compile(r"\becrecover\s*\(")
# `<var> = ecrecover(...)`, optionally with an `address` declaration.
_ASSIGNED = re.compile(r"(?:\baddress\s+)?([A-Za-z_]\w*)\s*=\s*ecrecover\s*\(")
# `ecrecover(...)` used directly inside a require/if comparison against address(0).
_INLINE_ZERO_CHECK = re.compile(
    r"ecrecover\s*\([^;]*?(?:==|!=)\s*address\s*\(\s*0\s*\)"
)
# `require(ecrecover(...)` counts as a guard on the recovered value.
_INLINE_REQUIRE = re.compile(r"require\s*\(\s*ecrecover\s*\(")


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


def _iter_function_bodies(source: str) -> Iterator[Tuple[str, str, int]]:
    """Yield (name, body, body_start_offset) for each function via brace matching."""
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
        yield match.group(1), source[brace_start + 1:i], brace_start + 1


def _is_checked(body: str) -> bool:
    """True when the recovered address is validated somewhere in this body."""
    assigned = _ASSIGNED.search(body)
    if assigned:
        var = re.escape(assigned.group(1))
        patterns = (
            r"\b" + var + r"\b\s*(?:==|!=)\s*address\s*\(\s*0\s*\)",
            r"address\s*\(\s*0\s*\)\s*(?:==|!=)\s*\b" + var + r"\b",
            r"require\s*\(\s*" + var + r"\b",
        )
        return any(re.search(p, body) for p in patterns)
    # Not assigned to a variable: only inline guards can validate it.
    return bool(_INLINE_ZERO_CHECK.search(body) or _INLINE_REQUIRE.search(body))


class EcrecoverUncheckedRule(BaseRule):
    severity = "High"
    explanation_template = (
        "`ecrecover` returns `address(0)` instead of reverting when the signature is "
        "invalid. This function uses the recovered address without ever comparing it "
        "to `address(0)`, so a malformed signature yields the zero address as a "
        "'valid' signer."
    )
    impact_template = (
        "An attacker can submit garbage signatures that recover to `address(0)` and "
        "impersonate unset owners/signers (storage defaults to zero), forging "
        "approvals, permits, or governance votes."
    )
    fix_template = (
        "After recovery, add `require(recovered != address(0), \"invalid signature\")` "
        "before trusting the address, or use OpenZeppelin's ECDSA library which "
        "reverts on invalid signatures."
    )

    def run_check(self, contract_data: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        findings = []
        for entry in contract_data:
            source = entry.get("source", "")
            path = entry.get("path", "")
            if not source:
                continue
            clean = _sanitize(source)
            for name, body, body_start in _iter_function_bodies(clean):
                call = _ECRECOVER.search(body)
                if not call or _is_checked(body):
                    continue
                offset = body_start + call.start()
                lineno = clean[:offset].count("\n") + 1
                findings.append(self._create_finding(
                    title="ecrecover result not validated",
                    file=path,
                    line=lineno,
                    vulnerable_snippet=f"unchecked ecrecover() result in {name}()",
                    function_name=name,
                ))
        return findings
# EOF: hawki/core/static_rule_engine/rules/ecrecover_unchecked.py
