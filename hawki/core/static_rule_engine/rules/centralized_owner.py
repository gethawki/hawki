# --------------------
# File: hawki/core/static_rule_engine/rules/centralized_owner.py
# --------------------
"""
CentralizedOwner - Flags contracts with a single owner that has absolute power.
This is a systemic risk, not a direct vulnerability, but important for governance assessment.

The tree-sitter parser never fills the parsed ``modifiers`` list, so this rule
counts owner-privileged functions straight from the ``source`` text: bodied
function headers carrying an ``onlyOwner``-style modifier. A contract file
with three or more such functions is reported once (excessive centralization).
When the scanned repository ships a Timelock contract, the source path stays
quiet: routing owner powers through a timelock is the standard mitigation for
exactly this risk. The legacy metadata path (top-level ``functions`` entries
with parsed ``modifiers``, as used by unit tests) is preserved.
"""

import re

from . import BaseRule
from .access_control_bypass import iter_functions, strip_comments

_OWNER_WORD_RE = re.compile(r"\b(owner|admin)\b", re.IGNORECASE)
# `onlyOwner` / `onlyAdmin` / `onlyGovernance` / ... in a function header.
_ONLY_MODIFIER_RE = re.compile(r"\bonly[A-Za-z_]\w*")
# Function header up to the body brace (bodied implementations only).
_FUNC_RE = re.compile(r"function\s+(\w+)\s*\(([^)]*)\)([^;{]*)\{")
# A timelock contract in the same repository mitigates owner centralization.
_TIMELOCK_RE = re.compile(r"\bcontract\s+\w*[Tt]imelock\w*\b")

# How many owner-privileged functions count as "excessive centralization".
_PRIVILEGED_THRESHOLD = 3


class CentralizedOwnerRule(BaseRule):
    severity = "Low"
    explanation_template = (
        "This contract has a single owner with absolute control over critical functions (e.g., withdrawal, upgrades, pausing). "
        "While not an immediate vulnerability, it introduces centralization risk: if the owner's private key is compromised, "
        "the entire contract is compromised."
    )
    impact_template = (
        "A compromised owner account can drain funds, pause the contract indefinitely, or upgrade to a malicious implementation."
    )
    fix_template = (
        "Consider using a multi-signature wallet for the owner account, or implement a timelock and/or a DAO-based governance "
        "mechanism to decentralize control."
    )

    def run_check(self, contract_data):
        findings = []
        seen = set()
        repo_has_timelock = any(
            _TIMELOCK_RE.search(entry.get("source") or "")
            for entry in contract_data
        )
        for contract in contract_data:
            path = contract.get("path", "")
            source = contract.get("source", "")
            clean = strip_comments(source) if source else ""
            has_owner = bool(_OWNER_WORD_RE.search(clean))

            # Source-text path: count bodied functions guarded by an
            # onlyOwner-style modifier in their header.
            guarded_lines = []
            if clean and not repo_has_timelock:
                for match in _FUNC_RE.finditer(clean):
                    if _ONLY_MODIFIER_RE.search(match.group(3)):
                        guarded_lines.append(clean[:match.start()].count("\n") + 1)

            # Legacy metadata path: parsed `modifiers` supplied by unit tests
            # (the real parser leaves this list empty).
            only_owner_count = 0
            for func, _contract_name in iter_functions(contract):
                if "onlyOwner" in (func.get("modifiers") or []):
                    only_owner_count += 1

            fires = len(guarded_lines) >= _PRIVILEGED_THRESHOLD or (
                has_owner and only_owner_count > 0
            )
            if not fires:
                continue
            if path in seen:
                continue
            seen.add(path)
            # Determine line for owner declaration.
            match = re.search(
                r"(address|address\s+public|address\s+internal)\s+owner\s*;", source
            )
            if match:
                line = source[:match.start()].count("\n") + 1
                snippet = match.group(0)
            elif guarded_lines:
                line = guarded_lines[0]
                snippet = "owner-privileged function"
            else:
                line, snippet = 1, "owner variable"
            findings.append(self._create_finding(
                title="Centralized owner risk",
                file=path,
                line=line,
                vulnerable_snippet=snippet,
            ))
        return findings
# EOF: hawki/core/static_rule_engine/rules/centralized_owner.py
