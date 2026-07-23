# --------------------
# File: hawki/core/static_rule_engine/rules/access_control_bypass.py
# --------------------
"""
Access control bypass: detect missing modifiers on sensitive functions.

The tree-sitter parser does not reliably surface modifier invocations (and
`contract_data` entries produced by the indexer nest functions one level
deeper, under ``contracts``), so this module also performs source-text guard
detection: before a function is reported as unprotected, its extracted
source is checked for common guards (``onlyOwner``-style modifiers,
``require(msg.sender == ...)``, ``_checkOwner``/``_checkRole``,
``if (msg.sender != ...) revert``). The helpers below are shared with the
other access-control rules in this package.
"""

import re

from . import BaseRule

# ----------------------------------------------------------------------
# Shared source-text guard detection helpers
# ----------------------------------------------------------------------

_BLOCK_COMMENT_RE = re.compile(r"/\*.*?\*/", re.DOTALL)
_LINE_COMMENT_RE = re.compile(r"//[^\n]*")

# Guards searched in the full function text (header + body).
_GUARD_TEXT_RES = [
    re.compile(r"\bonly[A-Z]\w*"),  # onlyOwner / onlyRole / onlyAdmin / ...
    re.compile(r"require\s*\(\s*msg\.sender\s*=="),
    re.compile(r"require\s*\(\s*_msgSender\s*\(\s*\)\s*=="),
    re.compile(r"require\s*\([^;]{0,120}==\s*msg\.sender"),
    re.compile(r"require\s*\([^;]{0,120}==\s*_msgSender\s*\(\s*\)"),
    re.compile(r"_checkOwner\s*\("),
    re.compile(r"_checkRole\s*\("),
    re.compile(r"if\s*\(\s*msg\.sender\s*!=[^;{]{0,160}\)\s*\{?\s*revert"),
    re.compile(r"if\s*\([^;{]{0,160}!=\s*msg\.sender\s*\)\s*\{?\s*revert"),
]

# Guards searched only in the function header (signature up to the body),
# where a lowercase custom modifier such as `onlyowner` is unambiguous.
_GUARD_HEADER_RE = re.compile(r"\bonly[A-Za-z_]\w*", re.IGNORECASE)

_GUARD_MODIFIER_NAMES = {
    "authorized",
    "auth",
    "hasrole",
    "requiresauth",
    "restricted",
    "owneronly",
    "adminonly",
}


def strip_comments(source):
    """Blank out Solidity comments while preserving offsets/line numbers."""

    def _blank(match):
        return re.sub(r"[^\n]", " ", match.group(0))

    source = _BLOCK_COMMENT_RE.sub(_blank, source)
    return _LINE_COMMENT_RE.sub(_blank, source)


def has_guard_modifier(modifiers):
    """True if the parsed modifier list contains an access-control guard."""
    for mod in modifiers or []:
        low = str(mod).lower()
        if low.startswith("only") or low in _GUARD_MODIFIER_NAMES:
            return True
    return False


def has_guard_text(text):
    """True if the given function text contains an access-control guard."""
    if not text:
        return False
    return any(rx.search(text) for rx in _GUARD_TEXT_RES)


def iter_functions(contract):
    """Yield function dicts from both contract_data shapes.

    Unit tests supply ``{"functions": [...]}`` directly, while the indexer
    produces ``{"contracts": [{"functions": [...]}]}`` per file. Each yielded
    item is ``(function_dict, enclosing_contract_name)``.
    """
    for func in contract.get("functions", []) or []:
        yield func, contract.get("name", "")
    for nested in contract.get("contracts", []) or []:
        for func in nested.get("functions", []) or []:
            yield func, nested.get("name", "")


def function_occurrences(source, name):
    """Extract every ``function <name>`` occurrence from source text.

    Returns a list of dicts: ``{"line", "header", "body", "text",
    "has_body"}``. Comments are stripped first so commented-out code and
    doc comments never influence guard detection.
    """
    occurrences = []
    if not source or not name:
        return occurrences
    clean = strip_comments(source)
    n = len(clean)
    for match in re.finditer(rf"function\s+{re.escape(name)}\s*\(", clean):
        depth = 0
        header_end = None
        has_body = False
        j = match.end() - 1
        while j < n:
            ch = clean[j]
            if ch == "(":
                depth += 1
            elif ch == ")":
                depth -= 1
            elif depth == 0 and ch == "{":
                header_end = j
                has_body = True
                break
            elif depth == 0 and ch == ";":
                header_end = j
                break
            j += 1
        if header_end is None:
            continue
        header = clean[match.start():header_end]
        body = ""
        if has_body:
            brace_depth = 0
            k = header_end
            while k < n:
                if clean[k] == "{":
                    brace_depth += 1
                elif clean[k] == "}":
                    brace_depth -= 1
                    if brace_depth == 0:
                        break
                k += 1
            body = clean[header_end:k + 1]
        occurrences.append({
            "line": clean[:match.start()].count("\n") + 1,
            "header": header,
            "body": body,
            "text": header + body,
            "has_body": has_body,
        })
    return occurrences


def _occurrence_guarded(occ):
    return bool(_GUARD_HEADER_RE.search(occ["header"])) or has_guard_text(occ["text"])


def unguarded_occurrence(func, source):
    """Return an occurrence dict if ``func`` is provably unprotected.

    Returns ``None`` when the function has a guard (parsed modifier, guard
    modifier in the header, or a guard check in the body) or when every
    occurrence in the source is a bodiless declaration (interface/abstract).
    When no source text is available, falls back to the parsed ``body`` and
    ``modifiers`` fields supplied by tests.
    """
    if has_guard_modifier(func.get("modifiers")):
        return None
    name = func.get("name", "")
    body = func.get("body") or ""
    occurrences = function_occurrences(source or "", name)
    if occurrences:
        bodied = [occ for occ in occurrences if occ["has_body"]]
        if not bodied:
            return None  # declaration-only: interface or abstract signature
        for occ in bodied:
            if not _occurrence_guarded(occ):
                return occ
        return None
    if body and has_guard_text(body):
        return None
    return {
        "line": func.get("line", 1),
        "header": "",
        "body": body,
        "text": body,
        "has_body": bool(body),
    }


# Fund-moving statements: a `withdraw`-style name alone is common on
# user-facing staking/vault functions, so it is only flagged when the
# function itself sends value.
_MOVES_FUNDS_RE = re.compile(
    r"\.transfer\s*\(|\.send\s*\(|\.call\s*\{\s*value|\.call\.value|selfdestruct\s*\("
)

# User-scoped accounting (`balances[msg.sender]`, `deposits[_msgSender()]`,
# `_burn(msg.sender, ...)`): a withdraw that only pays out the caller's own
# balance is a normal user action, not a missing access control.
_SELF_SCOPED_RE = re.compile(
    r"\[\s*msg\.sender\s*\]|\[\s*_msgSender\s*\(\s*\)\s*\]|_burn\s*\(\s*msg\.sender"
)


class AccessControlBypassRule(BaseRule):
    severity = "Critical"
    explanation_template = (
        "Sensitive functions (e.g., `withdraw`, `setOwner`, `pause`) must be protected by access control modifiers "
        "like `onlyOwner`. Without such protection, any user can call these functions and compromise the contract."
    )
    impact_template = (
        "An attacker can drain funds, change critical parameters, or take ownership of the contract."
    )
    fix_template = (
        "Add a modifier to restrict access:\n"
        "```solidity\n"
        "modifier onlyOwner() {\n"
        "    require(msg.sender == owner, \"Not owner\");\n"
        "    _;\n"
        "}\n"
        "function {{function_name}}() {{visibility}} onlyOwner {\n"
        "    // ...\n"
        "}\n"
        "```"
    )

    # Names that are only dangerous when the function moves funds.
    _FUND_GATED_NAMES = ("withdraw",)
    # Names that are always admin-only by convention.
    _ADMIN_NAMES = (
        "transferownership", "destroy", "kill", "setowner", "changeowner",
        "pause", "unpause", "setimplementation",
    )

    def run_check(self, contract_data):
        findings = []
        seen = set()
        for contract in contract_data:
            source = contract.get("source", "")
            path = contract.get("path", "")
            for func, contract_name in iter_functions(contract):
                func_name = func.get("name", "")
                lowered = func_name.lower()
                is_admin = any(s in lowered for s in self._ADMIN_NAMES)
                is_fund_gated = not is_admin and any(
                    s in lowered for s in self._FUND_GATED_NAMES
                )
                if not (is_admin or is_fund_gated):
                    continue
                # Old-style constructors share the contract name; setting
                # state there is normal.
                if contract_name and lowered == contract_name.lower():
                    continue
                if func.get("visibility") in ("internal", "private"):
                    continue
                if func.get("state_mutability") in ("view", "pure", "constant"):
                    continue
                occ = unguarded_occurrence(func, source)
                if occ is None:
                    continue
                fund_text = occ["text"] + "\n" + (func.get("body") or "")
                if is_fund_gated and not _MOVES_FUNDS_RE.search(fund_text):
                    continue
                if is_fund_gated and _SELF_SCOPED_RE.search(fund_text):
                    continue
                key = (path, func_name)
                if key in seen:
                    continue
                seen.add(key)
                snippet = (occ["body"] or occ["header"] or "").strip()[:100]
                findings.append(self._create_finding(
                    title=f"Missing access control on {func_name}",
                    file=path,
                    line=occ["line"],
                    vulnerable_snippet=snippet,
                    function_name=func_name,
                    visibility=func.get("visibility", "public"),
                ))
        return findings
# EOF: hawki/core/static_rule_engine/rules/access_control_bypass.py
