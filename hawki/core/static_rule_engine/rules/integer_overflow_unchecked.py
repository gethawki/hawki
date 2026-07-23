# --------------------
# File: hawki/core/static_rule_engine/rules/integer_overflow_unchecked.py
# --------------------
"""
Integer overflow in unchecked blocks: detect arithmetic inside `unchecked` blocks that could overflow.
"""

from . import BaseRule


class IntegerOverflowUncheckedRule(BaseRule):
    severity = "Critical"
    explanation_template = (
        "Arithmetic inside `unchecked` blocks bypasses Solidity's built-in overflow checks. If the values are unbounded, "
        "this can lead to integer overflow/underflow vulnerabilities."
    )
    impact_template = (
        "An attacker can manipulate arithmetic to cause unexpected behavior, such as inflating balances or breaking invariants."
    )
    fix_template = (
        "Avoid `unchecked` for user-supplied values. If necessary, ensure the operation cannot overflow by adding explicit checks:\n"
        "```solidity\n"
        "unchecked {\n"
        "    require(x <= type(uint256).max - y, \"overflow\");\n"
        "    z = x + y;\n"
        "}\n"
        "```"
    )

    def run_check(self, contract_data):
        findings = []
        import re
        # Look for arithmetic operators inside unchecked blocks
        # Simple: find "unchecked {" and then look for + - * / within that block
        for contract in contract_data:
            source = contract.get("source", "")
            # Find all unchecked blocks
            unchecked_blocks = re.finditer(r'unchecked\s*\{([^}]*)\}', source, re.DOTALL)
            for block in unchecked_blocks:
                block_content = block.group(1)
                # Check for arithmetic ops
                if re.search(r'[\+\-\*/]', block_content):
                    # Find line of the unchecked block
                    line = source[:block.start()].count('\n') + 1
                    snippet = f"unchecked {{ {block_content.strip()} }}"
                    findings.append(self._create_finding(
                        title="Unchecked arithmetic may overflow",
                        file=contract.get("path", ""),
                        line=line,
                        vulnerable_snippet=snippet,
                    ))
        return findings
# EOF: hawki/core/static_rule_engine/rules/integer_overflow_unchecked.py