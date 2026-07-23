# --------------------
# File: hawki/core/static_rule_engine/rules/delegatecall_misuse.py
# --------------------
"""
delegatecall misuse: detect calls to untrusted addresses via delegatecall.
"""

from . import BaseRule


class DelegatecallMisuseRule(BaseRule):
    severity = "Critical"
    explanation_template = (
        "`delegatecall` executes code from another contract in the context of the caller. "
        "If the target address can be controlled by an attacker, they can manipulate the contract's storage "
        "and potentially drain funds or take over the contract."
    )
    impact_template = (
        "An attacker can execute arbitrary code in the context of the vulnerable contract, "
        "leading to complete loss of funds or contract takeover."
    )
    fix_template = (
        "Avoid `delegatecall` to user-supplied addresses. If necessary, use a whitelist of trusted targets:\n"
        "```solidity\n"
        "address trustedImplementation = ...;\n"
        "require(target == trustedImplementation, \"Unauthorized target\");\n"
        "(bool success, ) = target.delegatecall(data);\n"
        "```"
    )

    def run_check(self, contract_data):
        findings = []
        import re
        delegate_pattern = re.compile(r'(\w+)\.delegatecall\(')
        for contract in contract_data:
            source = contract.get("source", "")
            matches = delegate_pattern.finditer(source)
            for match in matches:
                # Try to locate line number (crude: count newlines before match)
                line = source[:match.start()].count('\n') + 1
                snippet = source[match.start():match.end()] + "..."
                findings.append(self._create_finding(
                    title="Unsafe delegatecall",
                    file=contract.get("path", ""),
                    line=line,
                    vulnerable_snippet=snippet,
                ))
        return findings
# EOF: hawki/core/static_rule_engine/rules/delegatecall_misuse.py