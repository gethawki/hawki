# --------------------
# File: hawki/core/static_rule_engine/rules/locked_ether.py
# --------------------
"""
Locked ether detection.

Works on the raw contract ``source`` text: each concrete ``contract`` block is
isolated by brace matching and inspected for an ether ENTRY point - a bodied
``receive()``, a ``payable`` ``fallback``/function, or an old-style payable
``function()`` - while the whole file is searched for any ether EXIT path
(``.transfer(``, ``.send(``, a ``{value: ...}`` call option, legacy
``.call.value(``, or ``selfdestruct``). A contract that can accept ether but
can never move it out traps every wei sent to it forever. One finding is
emitted per contract.

Interfaces, libraries, and abstract contracts are skipped (their payable
declarations have no bodies or are completed by inheritors), and the exit-path
scan is file-wide so same-file base contracts providing a withdrawal are
honored.
"""

import re
from typing import Any, Dict, Iterator, List, Tuple

from . import BaseRule

_CONTRACT_HEADER = re.compile(r"\b(abstract\s+contract|contract|interface|library)\s+(\w+)[^{;]*?\{")
_RECEIVE = re.compile(r"\breceive\s*\(\s*\)[^;{}]*\{")
_PAYABLE_FALLBACK = re.compile(r"\bfallback\s*\([^)]*\)[^;{}]*\bpayable\b[^;{}]*\{")
_OLD_FALLBACK = re.compile(r"\bfunction\s*\(\s*\)[^;{}]*\bpayable\b[^;{}]*\{")
_FUNC_HEADER = re.compile(r"function\s+(\w+)\s*\([^;{})]*\)([^;{}]*?)\{", re.DOTALL)
_ETHER_EXIT = re.compile(
    r"\.transfer\s*\(|\.send\s*\(|\{[^{}]*\bvalue\s*:|\.call\s*\.\s*value\s*\(|"
    r"\bselfdestruct\s*\(|\bsuicide\s*\("
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


def _iter_contract_bodies(masked: str) -> Iterator[Tuple[str, str, str, int]]:
    """Yield (kind, name, body, start_line) for each contract-like block."""
    for match in _CONTRACT_HEADER.finditer(masked):
        kind, name = match.group(1), match.group(2)
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
        yield kind, name, body, start_line


def _receives_ether(body: str) -> bool:
    if _RECEIVE.search(body) or _PAYABLE_FALLBACK.search(body) or _OLD_FALLBACK.search(body):
        return True
    for func in _FUNC_HEADER.finditer(body):
        name, tail = func.group(1), func.group(2)
        if name == "constructor":
            continue
        if re.search(r"\bpayable\b", tail):
            return True
    return False


class LockedEtherRule(BaseRule):
    severity = "Medium"
    explanation_template = (
        "The contract accepts ether (via `receive()`, a payable `fallback`, or a payable function) but "
        "defines no code path that can ever move ether out - no `.transfer`/`.send`, no `{value: ...}` "
        "call, no `selfdestruct`. Every wei sent to it becomes permanently unrecoverable."
    )
    impact_template = (
        "User or protocol funds sent to the contract are irreversibly frozen. There is no owner rescue, "
        "no upgrade hook, and no way to recover the balance short of redeploying and migrating."
    )
    fix_template = (
        "Either remove the payable entry points if the contract is not meant to hold ether, or add an "
        "explicit withdrawal path, e.g. an access-controlled "
        "`function withdraw(address payable to) external onlyOwner { to.transfer(address(this).balance); }`."
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
            if _ETHER_EXIT.search(masked):
                continue  # some code in this file can move ether out
            lines = source.splitlines()
            for kind, name, body, start_line in _iter_contract_bodies(masked):
                if kind != "contract":
                    continue  # interfaces/libraries/abstract bases are completed elsewhere
                if not _receives_ether(body):
                    continue
                key = (path, name)
                if key in seen:
                    continue
                seen.add(key)
                snippet = (
                    lines[start_line - 1].strip()
                    if 0 < start_line <= len(lines) else f"contract {name}"
                )
                findings.append(self._create_finding(
                    title="Ether can be locked in contract",
                    file=path,
                    line=start_line,
                    vulnerable_snippet=snippet,
                    contract_name=name,
                ))
        return findings
# EOF: hawki/core/static_rule_engine/rules/locked_ether.py
