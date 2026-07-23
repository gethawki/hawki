# --------------------
# File: hawki/core/static_rule_engine/rules/erc20_unchecked_transfer.py
# --------------------
"""
Unchecked ERC20 transfer detection.

Works on the raw contract ``source`` text: statement-level calls of the form
``token.transfer(to, amount)`` / ``token.transferFrom(from, to, amount)`` whose
boolean return value is dropped are flagged. Non-compliant tokens (USDT-style)
return nothing or false instead of reverting, so a dropped return value means a
failed transfer goes unnoticed.

Precision guards (verified quiet on the PancakeSwap farms-pools corpus):

* the receiver must be typed as an ERC20/BEP20 interface (declared in the file
  or used as an inline cast) - ``payable(x).transfer(amount)`` ether sends and
  concrete in-repo token contracts are not flagged;
* ``transfer`` needs two-or-more arguments (ether ``transfer`` takes one);
* the call must start its own statement (preceded by ``;``, ``{`` or ``}``),
  so calls wrapped in ``require``/``assert``/``if``/assignments are "checked";
* files that adopt ``using SafeERC20``/``SafeBEP20`` are skipped entirely.
"""

import re
from typing import Any, Dict, Iterator, List, Tuple

from . import BaseRule

_USING_SAFE = re.compile(r"\busing\s+Safe(?:ERC20|BEP20)\b")
# A transfer/transferFrom whose receiver is a bare identifier (possibly
# indexed) or an inline ERC20/BEP20 interface cast, at any position; statement
# anchoring is done separately by looking at the preceding non-space character.
_TOKEN_CALL = re.compile(
    r"(?P<recv>(?:I(?:ERC|BEP)20\w*|(?:ERC|BEP)20)\s*\([^()]*\)|[A-Za-z_]\w*(?:\s*\[[^\]]*\])?)"
    r"\s*\.\s*(?P<method>transferFrom|transfer)\s*(?P<paren>\()"
)
_TOKEN_TYPE_PREFIX = r"(?:I(?:ERC|BEP)20\w*|(?:ERC|BEP)20)"
_DECL_MODIFIERS = r"(?:(?:public|private|internal|immutable|constant|override|storage|memory|calldata)\s+)*"


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


def _is_statement_start(masked: str, pos: int) -> bool:
    """True when the previous non-whitespace char begins a fresh statement."""
    i = pos - 1
    while i >= 0 and masked[i] in " \t\r\n":
        i -= 1
    return i < 0 or masked[i] in ";{}"


def _top_level_commas(masked: str, open_paren: int) -> int:
    """Count top-level commas in the argument list starting at ``open_paren``."""
    depth, commas, i, n = 0, 0, open_paren, len(masked)
    while i < n:
        ch = masked[i]
        if ch in "([":
            depth += 1
        elif ch in ")]":
            depth -= 1
            if depth == 0:
                break
        elif ch == "," and depth == 1:
            commas += 1
        i += 1
    return commas


class Erc20UncheckedTransferRule(BaseRule):
    severity = "Medium"
    explanation_template = (
        "An ERC20 `transfer`/`transferFrom` call is executed as a bare statement, discarding its boolean "
        "return value. Many widely used tokens (e.g. USDT, BNB-chain BEP20s) signal failure by returning "
        "false instead of reverting, so the surrounding logic proceeds as if the tokens moved when they "
        "did not."
    )
    impact_template = (
        "Accounting desynchronizes from real balances: deposits can be credited without tokens arriving, "
        "withdrawals marked paid without tokens leaving, enabling theft or permanent loss of user funds."
    )
    fix_template = (
        "Wrap the call: `require(token.transfer(to, amount), \"transfer failed\");` or, better, use "
        "OpenZeppelin's SafeERC20 (`using SafeERC20 for IERC20;` then `token.safeTransfer(...)`), which "
        "also handles non-standard tokens that return no value."
    )

    def _iter_sources(self, contract_data: List[Dict[str, Any]]) -> Iterator[Tuple[str, str]]:
        for entry in contract_data:
            source = entry.get("source")
            if source:
                yield entry.get("path", ""), source

    def _receiver_is_erc20(self, masked: str, receiver: str) -> bool:
        receiver = receiver.strip()
        if re.match(_TOKEN_TYPE_PREFIX + r"\s*\(", receiver):
            return True  # inline cast, e.g. IERC20(token).transfer(...)
        name = receiver.split("[")[0].strip()
        if not re.match(r"^[A-Za-z_]\w*$", name):
            return False
        decl = re.compile(
            r"\b" + _TOKEN_TYPE_PREFIX + r"\s+" + _DECL_MODIFIERS + re.escape(name) + r"\b"
        )
        return bool(decl.search(masked))

    def run_check(self, contract_data: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        findings = []
        seen = set()
        for path, source in self._iter_sources(contract_data):
            masked = _mask_comments_and_strings(source)
            if _USING_SAFE.search(masked):
                continue
            lines = source.splitlines()
            for match in _TOKEN_CALL.finditer(masked):
                if not _is_statement_start(masked, match.start()):
                    continue  # inside require/if/assert/assignment/return
                # Two-or-more args distinguishes an ERC20 transfer from an
                # ether `address.transfer(amount)`.
                if _top_level_commas(masked, match.start("paren")) < 1:
                    continue
                if not self._receiver_is_erc20(masked, match.group("recv")):
                    continue
                line = masked[: match.start()].count("\n") + 1
                key = (path, line)
                if key in seen:
                    continue
                seen.add(key)
                snippet = lines[line - 1].strip() if 0 < line <= len(lines) else match.group(0)
                findings.append(self._create_finding(
                    title="Unchecked ERC20 transfer",
                    file=path,
                    line=line,
                    vulnerable_snippet=snippet,
                ))
        return findings
# EOF: hawki/core/static_rule_engine/rules/erc20_unchecked_transfer.py
