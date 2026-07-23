# --------------------
# File: hawki/core/static_rule_engine/rules/approval_race.py
# --------------------
"""
Improper ERC20 approval race condition: detect missing allowance checks that could lead to double spending.

The tree-sitter parser exposes function metadata but not function bodies, so
this rule extracts ``approve`` implementations from the raw contract
``source`` text (via the shared brace-matching helper) and flags the classic
non-atomic approve: a direct double-mapping assignment
``allowance[owner][spender] = value`` with no requirement that the prior
allowance be zero. The legacy metadata path (top-level ``functions`` entries
carrying a ``body`` string, as used by unit tests) applies the same predicate.
"""

import re

from . import BaseRule
from .access_control_bypass import function_occurrences

# Direct allowance write: `allowed[msg.sender][spender] = amount;` (any names).
_ALLOWANCE_ASSIGN = re.compile(r"\w+\s*\[[^\[\]]+\]\s*\[[^\[\]]+\]\s*=(?!=)")
# Race mitigation: require the previous allowance (or the new value) to be 0,
# or delegation to the increase/decrease pattern.
_RACE_GUARD = re.compile(
    r"require\s*\([^;]*==\s*0"
    r"|increaseAllowance|decreaseAllowance|safeApprove"
)


def _vulnerable_body(body: str) -> bool:
    """True for an approve body that writes the allowance without a zero guard."""
    if not body:
        return False
    if not _ALLOWANCE_ASSIGN.search(body):
        return False
    return not _RACE_GUARD.search(body)


class ApprovalRaceRule(BaseRule):
    severity = "Low"
    explanation_template = (
        "The standard ERC20 `approve` function is vulnerable to a race condition: if an owner changes allowance from N to M, "
        "and the spender submits a transfer before the new approval, they can spend N and then M, exceeding the intended limit."
    )
    impact_template = (
        "An attacker can spend more tokens than allowed, leading to theft."
    )
    fix_template = (
        "Use OpenZeppelin's `safeApprove` or `increaseAllowance`/`decreaseAllowance` to mitigate the race condition. "
        "Alternatively, require the new allowance to be zero before changing it."
    )

    def run_check(self, contract_data):
        findings = []
        seen = set()
        for contract in contract_data:
            path = contract.get("path", "")
            # Source-text path: the shape the RepositoryIndexer produces.
            source = contract.get("source", "")
            if source:
                for occ in function_occurrences(source, "approve"):
                    if not occ["has_body"] or not _vulnerable_body(occ["body"]):
                        continue
                    key = (path, occ["line"])
                    if key in seen:
                        continue
                    seen.add(key)
                    findings.append(self._create_finding(
                        title="ERC20 approval race condition",
                        file=path,
                        line=occ["line"],
                        vulnerable_snippet=occ["header"].strip()
                                           or "function approve(...)",
                        function_name="approve",
                    ))
            # Legacy metadata path: unit tests supply top-level `functions`
            # dicts with a `body` string (the real parser never fills these).
            for func in contract.get("functions", []):
                if func.get("name") != "approve":
                    continue
                if not _vulnerable_body(func.get("body", "")):
                    continue
                line = func.get("line", 1)
                key = (path, line)
                if key in seen:
                    continue
                seen.add(key)
                findings.append(self._create_finding(
                    title="ERC20 approval race condition",
                    file=path,
                    line=line,
                    vulnerable_snippet="function approve(address spender, uint256 amount) ...",
                ))
        return findings
# EOF: hawki/core/static_rule_engine/rules/approval_race.py
