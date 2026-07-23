# --------------------
# File: hawki/core/static_rule_engine/rules/input_validation.py
# --------------------
"""
Improper input validation: missing bounds checks on user-supplied values.
"""

import re

from . import BaseRule

# An indexed READ of the form `name[index]` where the index is a bare identifier
# (a candidate user-supplied index), e.g. `data[i]`. Deliberately does NOT match:
#   - array/type declarations `uint256[] memory` (empty brackets),
#   - numeric-constant indices `data[0]`,
#   - member-expression indices such as `balances[msg.sender]` (the closing
#     bracket does not immediately follow the identifier),
# which are the overwhelming majority of bracketed lines and are not themselves
# missing-validation smells. This keeps the rule from firing on every mapping or
# array declaration in a real codebase.
_INDEXED_READ = re.compile(r"\b([A-Za-z_]\w*)\s*\[\s*([A-Za-z_]\w*)\s*\]")

# The variable name declared by a `mapping(...) ... name;` state-variable line
# (applied only to lines that contain the `mapping` keyword). Mapping accesses
# are keyed lookups (address/hash keys) with no out-of-bounds surface, so they
# are not missing-index-validation candidates. Handles nested mappings because
# the search anchors on the last `) <modifiers> name;` tail of the line.
_MAPPING_DECL_NAME = re.compile(r"\)\s*(?:\w+\s+)*([A-Za-z_]\w*)\s*;")

# A plain or compound assignment operator, excluding comparison (`==`, `!=`,
# `<=`, `>=`), arrow (`=>`) and shift-assign contexts. Used to tell an indexed
# WRITE target (`m[k] = v;`, `balanceOf[src] -= wad;`) apart from an indexed
# read: writes are the canonical mapping-update idiom and are bounds-checked by
# the EVM for real arrays, so they are not read-validation smells.
_ASSIGN_OP = re.compile(r"(?<![=!<>&|+\-*/%^])[+\-*/%|&^]?=(?![=>])")


class InputValidationRule(BaseRule):
    severity = "High"
    explanation_template = (
        "User-supplied inputs should be validated to prevent out-of-bounds errors, integer overflows, "
        "or unexpected behavior. Missing checks can lead to vulnerabilities like underflows or access to invalid indices."
    )
    impact_template = (
        "An attacker could supply values that cause array index errors, arithmetic issues, or bypass logic."
    )
    fix_template = (
        "Add input validation using `require` statements: e.g., `require(amount > 0, \"amount must be >0\")`, "
        "`require(index < array.length, \"index out of bounds\")`."
    )

    def run_check(self, contract_data):
        findings = []
        for contract in contract_data:
            source = contract.get("source", "")
            path = contract.get("path", "")
            lines = source.split("\n")

            # Collect names declared as mappings anywhere in this file so that
            # `userInfo[_user]` / `allowance[src]` style keyed lookups are not
            # mistaken for unvalidated array indexing.
            mapping_names = set()
            for line in lines:
                if "mapping" in line:
                    decl = _MAPPING_DECL_NAME.search(line)
                    if decl:
                        mapping_names.add(decl.group(1))

            # Report each distinct indexed array at most once per contract so a
            # single unchecked array does not produce a finding on every access.
            seen = set()
            for i, line in enumerate(lines):
                # Lines that already bound-check, or are mapping declarations,
                # are not missing-validation candidates.
                if "length" in line or "require" in line or "assert" in line or "mapping" in line:
                    continue
                stripped = line.lstrip()
                # Comment lines are never findings.
                if stripped.startswith("//") or stripped.startswith("*") or stripped.startswith("/*"):
                    continue
                assign = _ASSIGN_OP.search(line)
                for match in _INDEXED_READ.finditer(line):
                    array_name = match.group(1)
                    index_name = match.group(2)
                    # Accesses on names declared as mappings in this file are
                    # keyed lookups, not array indexing.
                    if array_name in mapping_names:
                        continue
                    # An ALL_CAPS index is a constant by Solidity convention,
                    # not a user-supplied value.
                    if index_name.isupper():
                        continue
                    # An indexed expression left of an assignment operator is a
                    # write target (mapping-update idiom), not an unchecked read.
                    if assign and match.start() < assign.start():
                        continue
                    key = (path, array_name)
                    if key in seen:
                        continue
                    seen.add(key)
                    findings.append(self._create_finding(
                        title="Possible missing input validation",
                        file=path,
                        line=i + 1,
                        vulnerable_snippet=line.strip(),
                    ))
        return findings
# EOF: hawki/core/static_rule_engine/rules/input_validation.py
