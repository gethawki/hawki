# --------------------
# File: hawki/core/static_rule_engine/rules/hardcoded_address.py
# --------------------
"""
Hardcoded privileged address: using a fixed address for critical roles reduces flexibility and trust.
"""

import re

from . import BaseRule

# A 40-hex-digit literal that is not embedded inside a longer hex constant
# (e.g. a bytes32 hash contains 40-hex-digit substrings but is not an address).
_ADDRESS = re.compile(r"(?<![0-9a-fA-Fx])0x[a-fA-F0-9]{40}(?![0-9a-fA-F])")

# Well-known zero/burn/sentinel addresses: intentional, not privileged roles.
_SENTINELS = {
    "0x" + "0" * 40,                                      # zero address
    "0x000000000000000000000000000000000000dead",         # burn address
    "0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",         # native-ETH placeholder
}

# Blank out comments while preserving offsets/line numbers.
_COMMENT = re.compile(r"//[^\n]*|/\*.*?\*/", re.DOTALL)


def _strip_comments(source: str) -> str:
    return _COMMENT.sub(lambda m: re.sub(r"[^\n]", " ", m.group(0)), source)


class HardcodedAddressRule(BaseRule):
    severity = "Medium"
    explanation_template = (
        "Hardcoding an address (e.g., owner, admin) in the contract code makes it immutable and reduces trust. "
        "If the private key is compromised, the contract cannot be updated."
    )
    impact_template = (
        "If the hardcoded address is compromised, the attacker gains permanent control over the contract. "
        "Also, the contract cannot be upgraded to change ownership."
    )
    fix_template = (
        "Use a constructor parameter to set the address at deployment, and include an upgrade mechanism if needed. "
        "Consider using OpenZeppelin's Ownable with a transferable owner."
    )

    def run_check(self, contract_data):
        findings = []
        for contract in contract_data:
            source = contract.get("source", "")
            clean = _strip_comments(source)
            seen = set()
            for match in _ADDRESS.finditer(clean):
                literal = match.group(0)
                normalized = literal.lower()
                if normalized in _SENTINELS:
                    continue
                # Dedupe: one finding per distinct address literal per contract.
                if normalized in seen:
                    continue
                seen.add(normalized)
                line = clean[:match.start()].count('\n') + 1
                findings.append(self._create_finding(
                    title="Hardcoded address",
                    file=contract.get("path", ""),
                    line=line,
                    vulnerable_snippet=literal,
                ))
        return findings
# EOF: hawki/core/static_rule_engine/rules/hardcoded_address.py
