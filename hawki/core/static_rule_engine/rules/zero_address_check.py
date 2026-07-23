# --------------------
# File: hawki/core/static_rule_engine/rules/zero_address_check.py
# --------------------
"""
Missing zero-address check: functions that accept addresses should check for zero address to prevent burning tokens or locking funds.

The tree-sitter parser exposes function metadata but not function bodies, so
this rule works on the raw contract ``source`` text: it isolates each function
body by brace matching, extracts the ``address`` parameters from the header,
and flags functions that store such a parameter in state (``owner = _o;``) or
pass it to a transfer/mint sink without a ``require(_o != address(0))`` style
guard. Interface/abstract declarations have no body and are never flagged.

To keep the signal clean on production code, access-guarded functions
(``onlyOwner``-style modifiers, ``require(msg.sender == ...)``) and the
standard ERC20 entry points (``transfer``/``transferFrom``/``approve``/...)
are skipped: those omissions are ubiquitous, trusted-caller patterns rather
than actionable flaws. The legacy metadata path (top-level ``functions``
entries with ``body``/``parameters``, as used by unit tests) is preserved.
"""

import re

from . import BaseRule
from .access_control_bypass import has_guard_text, strip_comments

# Function header: name, parameter list, modifier area, then the body brace.
_FUNC_RE = re.compile(r"function\s+(\w+)\s*\(([^)]*)\)([^;{]*)\{")
# An `address` parameter name inside the header's parameter list.
_ADDR_PARAM_RE = re.compile(
    r"(?:^|,)\s*address(?:\s+payable)?(?:\s+(?:calldata|memory|storage))?\s+(\w+)"
)
_ONLY_MODIFIER_RE = re.compile(r"\bonly[A-Za-z_]\w*", re.IGNORECASE)
_INTERNAL_RE = re.compile(r"\b(?:internal|private)\b")
# Standard token entry points whose missing zero-check is conventional.
_STD_TOKEN_FUNCS = {
    "transfer", "transferfrom", "approve", "burnfrom", "permit",
    "increaseallowance", "decreaseallowance", "safetransferfrom",
}


def _guarded(body: str, param: str) -> bool:
    """True if the body zero-checks this specific address parameter."""
    name = re.escape(param)
    if re.search(rf"require\s*\(\s*{name}\s*!=\s*address\s*\(\s*0\s*\)", body):
        return True
    if re.search(rf"if\s*\(\s*{name}\s*==\s*address\s*\(\s*0\s*\)", body):
        return True
    # Conservative fallback: any explicit zero-address require in the body is
    # treated as a guard (matches the historical behavior; fewer false alarms).
    return "require" in body and "address(0)" in body


def _stored_or_transferred(body: str, param: str) -> bool:
    """True if the body actually assigns the parameter somewhere or passes it
    to a transfer/call-like sink. Address params that are only read/compared
    cannot burn tokens or lock ownership, so they are not flagged."""
    name = re.escape(param)
    # Assignment RHS: `owner = newOwner;`, `roles[x] = admin;`, but not
    # comparisons (`==`, `!=`, `<=`, `>=`).
    if re.search(rf"(?<![=!<>])=\s*{name}\b", body):
        return True
    # Passed to a value-moving sink.
    if re.search(
        rf"\b(?:transfer|transferFrom|safeTransfer|safeTransferFrom|send|call|"
        rf"mint|_mint|burnFrom|approve|push)\s*\([^;]*\b{name}\b",
        body,
    ):
        return True
    return bool(re.search(rf"payable\s*\(\s*{name}\s*\)", body))


def _iter_source_functions(source):
    """Yield (name, params, mods, body, line) for each bodied function."""
    clean = strip_comments(source)
    n = len(clean)
    for match in _FUNC_RE.finditer(clean):
        brace_start = match.end() - 1
        depth, i = 0, brace_start
        while i < n:
            if clean[i] == "{":
                depth += 1
            elif clean[i] == "}":
                depth -= 1
                if depth == 0:
                    break
            i += 1
        body = clean[brace_start + 1:i]
        line = clean[:match.start()].count("\n") + 1
        yield match.group(1), match.group(2), match.group(3), body, line


class ZeroAddressCheckRule(BaseRule):
    severity = "Medium"
    explanation_template = (
        "When setting an address (e.g., owner, token recipient), it's important to check for the zero address (0x0). "
        "Otherwise, tokens could be sent to a burn address or ownership could be lost."
    )
    impact_template = (
        "Tokens sent to zero address are permanently lost. Ownership could be transferred to zero address, locking the contract."
    )
    fix_template = (
        "Add a require statement: `require(to != address(0), \"Invalid address\");`"
    )

    def run_check(self, contract_data):
        findings = []
        for contract in contract_data:
            path = contract.get("path", "")
            # Source-text path: the shape the RepositoryIndexer produces.
            source = contract.get("source", "")
            if source:
                for name, params, mods, body, line in _iter_source_functions(source):
                    if not body.strip():
                        continue
                    if name.lower() in _STD_TOKEN_FUNCS:
                        continue
                    if _INTERNAL_RE.search(mods):
                        continue
                    # Access-guarded functions have a trusted caller; the
                    # missing check is hygiene, not an actionable flaw.
                    if _ONLY_MODIFIER_RE.search(mods) or has_guard_text(mods + body):
                        continue
                    for pmatch in _ADDR_PARAM_RE.finditer(params):
                        pname = pmatch.group(1)
                        if not _stored_or_transferred(body, pname):
                            continue
                        if _guarded(body, pname):
                            continue
                        findings.append(self._create_finding(
                            title="Missing zero-address check",
                            file=path,
                            line=line,
                            vulnerable_snippet=f"function {name}(address {pname}) ...",
                            function_name=name,
                        ))
                        # Dedupe: at most one finding per function.
                        break
            # Legacy metadata path: unit tests supply top-level `functions`
            # dicts with `body`/`parameters` (the real parser has no bodies).
            for func in contract.get("functions", []):
                body = (func.get("body") or "").strip()
                # Interface/abstract declarations (no body, or the signature
                # just ends in `;`) have nothing to store, never flag them.
                if not body or body == ";":
                    continue
                for param in func.get("parameters", []):
                    if param.get("type") != "address":
                        continue
                    name = param.get("name") or ""
                    if not name:
                        continue
                    # Only fire when the body actually stores or transfers the
                    # address parameter without a zero-address guard for it.
                    if not _stored_or_transferred(body, name):
                        continue
                    if _guarded(body, name):
                        continue
                    line = func.get("line", 1)
                    snippet = f"function {func['name']}(address {name}) ..."
                    findings.append(self._create_finding(
                        title="Missing zero-address check",
                        file=path,
                        line=line,
                        vulnerable_snippet=snippet,
                    ))
                    # Dedupe: at most one finding per function.
                    break
        return findings
# EOF: hawki/core/static_rule_engine/rules/zero_address_check.py
