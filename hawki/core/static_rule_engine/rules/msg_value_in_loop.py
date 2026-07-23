# --------------------
# File: hawki/core/static_rule_engine/rules/msg_value_in_loop.py
# --------------------
"""
msg.value used inside a loop.

Works on the raw contract ``source`` text (the parser does not emit function
bodies): comments and strings are blanked out, each ``for``/``while`` loop body
is isolated by paren + brace matching, and any use of ``msg.value`` inside it is
flagged. ``msg.value`` is fixed for the whole transaction, so reading it once per
iteration (e.g. crediting it to several recipients) lets a caller reuse the same
ether value many times, a classic accounting bug.
"""

import re
from typing import Any, Dict, Iterator, List, Tuple

from . import BaseRule

_LOOP_START = re.compile(r"\b(?:for|while)\s*\(")
_MSG_VALUE = re.compile(r"\bmsg\.value\b")


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


def _iter_loop_bodies(masked: str) -> Iterator[Tuple[int, str]]:
    """Yield (body_offset, body) for each for/while loop body."""
    n = len(masked)
    for match in _LOOP_START.finditer(masked):
        i, depth = match.end() - 1, 0
        while i < n:
            if masked[i] == "(":
                depth += 1
            elif masked[i] == ")":
                depth -= 1
                if depth == 0:
                    break
            i += 1
        if i >= n:
            continue
        j = i + 1
        while j < n and masked[j] in " \t\r\n":
            j += 1
        if j < n and masked[j] == "{":
            k, depth = j, 0
            while k < n:
                if masked[k] == "{":
                    depth += 1
                elif masked[k] == "}":
                    depth -= 1
                    if depth == 0:
                        break
                k += 1
            yield j + 1, masked[j + 1:k]
        else:
            k = masked.find(";", j)
            yield j, masked[j:k if k != -1 else n]


class MsgValueInLoopRule(BaseRule):
    severity = "Medium"
    explanation_template = (
        "`msg.value` is read inside a loop. Its value is fixed for the entire transaction, so it does "
        "not change between iterations. Code that treats it as a per-iteration amount (e.g. crediting "
        "msg.value to each recipient) lets a caller spend the same ether many times over."
    )
    impact_template = (
        "An attacker can pass a single ether amount and have it counted once per loop iteration, "
        "draining or over-crediting the contract."
    )
    fix_template = (
        "Read `msg.value` once before the loop and divide/track the remaining balance explicitly, or "
        "require an exact total (e.g. `require(msg.value == amount * recipients.length)`)."
    )

    def run_check(self, contract_data: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        findings = []
        seen = set()
        for entry in contract_data:
            source = entry.get("source")
            if not source:
                continue
            path = entry.get("path", "")
            masked = _mask_comments_and_strings(source)
            lines = source.splitlines()
            for body_offset, body in _iter_loop_bodies(masked):
                hit = _MSG_VALUE.search(body)
                if not hit:
                    continue
                line = masked[: body_offset + hit.start()].count("\n") + 1
                if (path, line) in seen:
                    continue
                seen.add((path, line))
                snippet = lines[line - 1].strip() if 0 < line <= len(lines) else "msg.value"
                findings.append(self._create_finding(
                    title="msg.value used inside a loop",
                    file=path,
                    line=line,
                    vulnerable_snippet=snippet,
                ))
        return findings
# EOF: hawki/core/static_rule_engine/rules/msg_value_in_loop.py
