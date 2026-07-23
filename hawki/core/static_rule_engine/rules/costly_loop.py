# --------------------
# File: hawki/core/static_rule_engine/rules/costly_loop.py
# --------------------
"""
Costly operation inside a loop.

Works on the raw contract ``source`` text (comments and strings masked out):
each ``for``/``while`` loop body is isolated by paren + brace matching, then
searched for gas-heavy operations - external calls (``.call``, ``.transfer``,
``.send``) or storage-array ``.push(`` - repeated on every iteration. Loops
over unbounded data doing external calls or storage growth routinely exceed
the block gas limit and are a classic denial-of-service vector (one failing
recipient bricks the whole batch). One finding is emitted per loop.
"""

import re
from typing import Any, Dict, Iterator, List, Tuple

from . import BaseRule

_LOOP_START = re.compile(r"\b(?:for|while)\s*\(")
_COSTLY_OP = re.compile(
    r"\.call\s*[({]|\.call\s*\.\s*value\s*\(|\.delegatecall\s*[({]|"
    r"\.transfer\s*\(|\.send\s*\(|\.push\s*\("
)


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


def _iter_loop_bodies(masked: str) -> Iterator[Tuple[int, int, str]]:
    """Yield (loop_line, body_offset, body) for each for/while loop."""
    n = len(masked)
    for match in _LOOP_START.finditer(masked):
        # Match the loop-head parentheses.
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
            body_start, body = j + 1, masked[j + 1:k]
        else:  # single-statement loop body
            k = masked.find(";", j)
            body_start, body = j, masked[j:k if k != -1 else n]
        loop_line = masked[: match.start()].count("\n") + 1
        yield loop_line, body_start, body


class CostlyLoopRule(BaseRule):
    severity = "Low"
    explanation_template = (
        "A loop body performs a gas-heavy operation on every iteration: an external call "
        "(`.call`/`.transfer`/`.send`) or a storage-array `.push`. Gas cost grows linearly with the "
        "iteration count, and external calls add untrusted code execution per element."
    )
    impact_template = (
        "Once the iterated collection grows large enough, the transaction exceeds the block gas limit "
        "and the function becomes permanently uncallable (denial of service). With per-recipient "
        "transfers, a single reverting recipient can also block the entire batch."
    )
    fix_template = (
        "Move to a pull-payment model (recipients withdraw individually), bound the iteration count, or "
        "process the collection in resumable batches instead of calling out / growing storage inside "
        "one unbounded loop."
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
            for loop_line, body_start, body in _iter_loop_bodies(masked):
                op = _COSTLY_OP.search(body)
                if not op:
                    continue
                key = (path, loop_line)
                if key in seen:
                    continue
                seen.add(key)
                op_line = masked[: body_start + op.start()].count("\n") + 1
                snippet = lines[op_line - 1].strip() if 0 < op_line <= len(lines) else op.group(0)
                findings.append(self._create_finding(
                    title="Costly operation inside a loop",
                    file=path,
                    line=op_line,
                    vulnerable_snippet=snippet,
                ))
        return findings
# EOF: hawki/core/static_rule_engine/rules/costly_loop.py
