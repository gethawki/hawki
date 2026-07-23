# --------------------
# File: hawki/core/static_rule_engine/rules/missing_initializer.py
# --------------------
"""
Missing initializer in UUPS upgradeable contracts.
Detects upgradeable contracts that lack an initializer function or are missing the initializer modifier.

Because the parser does not surface modifier invocations, the check also
looks at the (comment-stripped) source text for an ``initializer`` /
``onlyInitializing`` modifier or a ``_disableInitializers()`` call before
reporting the contract as unprotected.
"""

import re

from . import BaseRule
from .access_control_bypass import strip_comments

_UPGRADEABLE_BASE_RE = re.compile(
    r"\bis\s[^{]*\b(UUPSUpgradeable|Initializable)\b", re.DOTALL
)
_INITIALIZER_SOURCE_RE = re.compile(
    r"\binitializer\b|\bonlyInitializing\b|_disableInitializers\s*\("
)


class MissingInitializerRule(BaseRule):
    severity = "Critical"
    explanation_template = (
        "Upgradeable contracts (UUPS or transparent proxies) must have an initializer function instead of a constructor. "
        "The initializer function should be protected by the `initializer` modifier to prevent re-initialization."
    )
    impact_template = (
        "Without a proper initializer, the contract may be left uninitialized, allowing anyone to take ownership "
        "or set critical parameters, leading to complete compromise."
    )
    fix_template = (
        "Add an initializer function with the `initializer` modifier:\n"
        "```solidity\n"
        "function initialize() public initializer {\n"
        "    __Ownable_init();\n"
        "    // set initial state\n"
        "}\n"
        "```"
    )

    def run_check(self, contract_data):
        findings = []
        for contract in contract_data:
            source = contract.get("source", "")
            clean = strip_comments(source)
            # Check if contract inherits from UUPSUpgradeable or similar
            match = _UPGRADEABLE_BASE_RE.search(clean)
            if not match:
                continue
            # Look for a function with the initializer modifier (parsed
            # modifiers first, then the source text, since the parser does
            # not extract modifier invocations).
            has_initializer = False
            for func in contract.get("functions", []):
                if "initializer" in (func.get("modifiers") or []):
                    has_initializer = True
                    break
            if not has_initializer and _INITIALIZER_SOURCE_RE.search(clean):
                has_initializer = True
            if not has_initializer:
                findings.append(self._create_finding(
                    title="Missing initializer in upgradeable contract",
                    file=contract.get("path", ""),
                    line=clean[:match.start()].count("\n") + 1,
                    vulnerable_snippet="Contract inherits from upgradeable base but has no initializer.",
                ))
        return findings
# EOF: hawki/core/static_rule_engine/rules/missing_initializer.py
