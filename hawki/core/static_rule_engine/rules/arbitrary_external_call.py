# --------------------
# File: hawki/core/static_rule_engine/rules/arbitrary_external_call.py
# --------------------
"""
Arbitrary external call detection.

Works on the raw contract ``source`` text: each function body is isolated by
brace matching, its parameter list is parsed, and any low-level ``.call`` /
``.delegatecall`` whose target is an ``address`` PARAMETER of that function is
flagged. A caller-controlled call target lets an attacker make the contract
invoke arbitrary code (drain approvals, spoof callbacks, hijack storage via
delegatecall).

To stay quiet on audited production code (e.g. Compound-style Timelocks), the
rule skips ``internal``/``private`` helpers and functions that are visibly
access-controlled (an ``only*``/``auth`` modifier or a ``msg.sender ==`` check
in the body).
"""

import re
from typing import Any, Dict, Iterator, List, Tuple

from . import BaseRule

# Function header up to the opening brace, capturing name, params, and the
# modifier area between the parameter list and the body.
_FUNC_HEADER = re.compile(r"function\s+(\w+)\s*\(([^;{})]*)\)([^;{}]*?)\{", re.DOTALL)
_ADDRESS_PARAM = re.compile(r"^\s*address(?:\s+payable)?\s+(\w+)\s*$")
_NON_PUBLIC = re.compile(r"\b(?:internal|private)\b")
_AUTH_MODIFIER = re.compile(r"\b(?:only\w+|auth\b|requiresAuth\b)")
_SENDER_CHECK = re.compile(r"msg\.sender\s*==|==\s*msg\.sender")


def _mask_comments_and_strings(source: str) -> str:
    """Blank comments and string literals with spaces, preserving offsets/newlines."""
    out = list(source)
    i, n = 0, len(source)
    while i < n:
        ch = source[i]
        nxt = source[i + 1] if i + 1 < n else ""
        if ch == "/" and nxt == "/":
            while i < n and source[i] != "\n":
                out[i] = " "
                i += 1
        elif ch == "/" and nxt == "*":
            out[i] = out[i + 1] = " "
            i += 2
            while i < n and not (source[i] == "*" and i + 1 < n and source[i + 1] == "/"):
                if source[i] != "\n":
                    out[i] = " "
                i += 1
            if i < n:
                out[i] = " "
            if i + 1 < n:
                out[i + 1] = " "
            i += 2
        elif ch in ('"', "'"):
            quote = ch
            out[i] = " "
            i += 1
            while i < n and source[i] != quote and source[i] != "\n":
                if source[i] == "\\" and i + 1 < n:
                    out[i] = " "
                    i += 1
                if source[i] != "\n":
                    out[i] = " "
                i += 1
            if i < n and source[i] == quote:
                out[i] = " "
                i += 1
        else:
            i += 1
    return "".join(out)


def _iter_function_bodies(masked: str) -> Iterator[Tuple[str, str, str, str, int, int]]:
    """Yield (name, params, tail, body, start_line, body_start) via brace matching."""
    for match in _FUNC_HEADER.finditer(masked):
        name, params, tail = match.group(1), match.group(2), match.group(3)
        brace_start = match.end() - 1
        depth, i = 0, brace_start
        while i < len(masked):
            if masked[i] == "{":
                depth += 1
            elif masked[i] == "}":
                depth -= 1
                if depth == 0:
                    break
            i += 1
        body = masked[brace_start + 1:i]
        start_line = masked[: match.start()].count("\n") + 1
        yield name, params, tail, body, start_line, brace_start + 1


class ArbitraryExternalCallRule(BaseRule):
    severity = "High"
    explanation_template = (
        "A publicly reachable function performs a low-level `.call` or `.delegatecall` on an address "
        "that is supplied as a function parameter. The caller fully controls the call target (and often "
        "the calldata), so the contract can be made to execute arbitrary external code on the caller's "
        "behalf."
    )
    impact_template = (
        "An attacker can point the call at any contract: drain tokens the contract holds or is approved "
        "to spend, spoof trusted callbacks, or (with delegatecall) execute attacker code in this "
        "contract's storage context and take it over completely."
    )
    fix_template = (
        "Do not accept call targets from untrusted callers. Restrict targets to an allowlist or an "
        "immutable address, gate the function with strong access control (e.g. `onlyOwner`), and never "
        "expose `delegatecall` to a user-supplied address."
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
            masked = _mask_comments_and_strings(source)
            lines = source.splitlines()
            for name, params, tail, body, _start, body_start in _iter_function_bodies(masked):
                # Internal helpers and visibly access-controlled functions are
                # not attacker-reachable with an arbitrary target.
                if _NON_PUBLIC.search(tail) or _AUTH_MODIFIER.search(tail):
                    continue
                if _SENDER_CHECK.search(body):
                    continue
                addr_params = []
                for piece in params.split(","):
                    pm = _ADDRESS_PARAM.match(piece)
                    if pm:
                        addr_params.append(pm.group(1))
                if not addr_params:
                    continue
                for param in addr_params:
                    pattern = re.compile(
                        r"\b" + re.escape(param) +
                        r"\s*\.\s*(?:delegatecall\s*[({]|call\s*[({]|call\s*\.\s*value\s*\()"
                    )
                    for cm in pattern.finditer(body):
                        line = masked[: body_start + cm.start()].count("\n") + 1
                        key = (path, line)
                        if key in seen:
                            continue
                        seen.add(key)
                        snippet = lines[line - 1].strip() if 0 < line <= len(lines) else cm.group(0)
                        findings.append(self._create_finding(
                            title="Arbitrary external call",
                            file=path,
                            line=line,
                            vulnerable_snippet=snippet,
                            function_name=name,
                        ))
        return findings
# EOF: hawki/core/static_rule_engine/rules/arbitrary_external_call.py
