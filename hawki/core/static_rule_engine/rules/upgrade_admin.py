# --------------------
# File: hawki/core/static_rule_engine/rules/upgrade_admin.py
# --------------------
"""
UpgradeAdmin - Detects improper upgrade admin transfer mechanisms.
If the admin of an upgradeable proxy can be changed by anyone without access control,
an attacker could take over the contract.

Uses the shared source-text guard detection from ``access_control_bypass``:
the parser does not surface modifier invocations, so a function is only
reported when neither its parsed modifiers nor its extracted source text
show an access-control guard.
"""

import re

from . import BaseRule
from .access_control_bypass import (
    has_guard_modifier,
    has_guard_text,
    iter_functions,
    unguarded_occurrence,
)

# Matches an assignment to a bare `admin` variable (not `pendingAdmin =`,
# not `admin ==` comparisons).
_ADMIN_ASSIGN_RE = re.compile(r"(?<![\w$])admin\s*=(?!=)")


class UpgradeAdminRule(BaseRule):
    severity = "Medium"
    explanation_template = (
        "In upgradeable contracts, the admin address controls upgrades. If the function that changes the admin "
        "is unprotected (e.g., no `onlyOwner` modifier), any user can set themselves as admin and then upgrade "
        "to a malicious implementation, compromising the contract."
    )
    impact_template = (
        "An attacker can take permanent control of the contract, drain funds, or brick the contract by upgrading "
        "to a malicious implementation."
    )
    fix_template = (
        "Add access control to the admin change function, e.g., `onlyOwner` modifier. Ensure that only the current "
        "admin or a privileged role can change the admin address.\n"
        "```solidity\n"
        "function changeAdmin(address newAdmin) public onlyOwner {\n"
        "    require(newAdmin != address(0), \"Zero address\");\n"
        "    admin = newAdmin;\n"
        "}\n"
        "```"
    )

    _ADMIN_CHANGE_NAMES = ("changeadmin", "setadmin", "updateadmin", "transferownership")

    def run_check(self, contract_data):
        findings = []
        seen = set()
        for contract in contract_data:
            source = contract.get("source", "")
            path = contract.get("path", "")
            for func, contract_name in iter_functions(contract):
                func_name = func.get("name", "")
                lowered = func_name.lower()
                # Constructors (old-style: function named after the contract)
                # legitimately set the admin.
                if contract_name and lowered == contract_name.lower():
                    continue
                if func.get("visibility") in ("internal", "private"):
                    continue
                key = (path, func_name)
                if key in seen:
                    continue
                # Admin-change function without access control.
                if any(k in lowered for k in self._ADMIN_CHANGE_NAMES):
                    occ = unguarded_occurrence(func, source)
                    if occ is not None:
                        seen.add(key)
                        findings.append(self._create_finding(
                            title="Unprotected upgrade admin change",
                            file=path,
                            line=occ["line"],
                            vulnerable_snippet=f"function {func_name}(...)",
                        ))
                        continue
                # Assignment to the admin variable without any check.
                if has_guard_modifier(func.get("modifiers")):
                    continue
                occ = unguarded_occurrence(func, source)
                if occ is None:
                    continue
                text = occ["text"] + "\n" + (func.get("body") or "")
                if not _ADMIN_ASSIGN_RE.search(text):
                    continue
                if "require" in text or "modifier" in text or has_guard_text(text):
                    continue
                seen.add(key)
                findings.append(self._create_finding(
                    title="Admin variable assignment without access control",
                    file=path,
                    line=occ["line"],
                    vulnerable_snippet=f"function {func_name}() ... // contains admin =",
                ))
        return findings
# EOF
