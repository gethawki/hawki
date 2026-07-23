# --------------------
# File: hawki/core/static_rule_engine/rules/oracle_manipulation.py
# --------------------
"""
Oracle price manipulation: detect usage of spot prices from manipulatable sources.

Works on the raw contract ``source`` text (comments stripped). Flags single
spot-price oracle reads: Chainlink's deprecated ``.latestAnswer()``, generic
``.getPrice(...)`` calls, Uniswap ``.consult(...)`` / ``.getReserves()`` /
``priceXCumulativeLast`` reads used for pricing. Pool-reserve and consult
reads are suppressed when the file shows evidence of time-weighted averaging
(TWAP), which is the standard manipulation resistance.
"""

import re

from . import BaseRule
from .access_control_bypass import strip_comments

# Spot reads that always warrant a finding.
_ALWAYS_PATTERNS = [
    re.compile(r"\.latestAnswer\s*\("),
    re.compile(r"\.getPrice\s*\("),
    re.compile(r"price\s*=\s*\w+\.balanceOf\(address\(this\)\)"),
]
# Spot reads that a TWAP in the same file legitimately mitigates.
_TWAP_MITIGATED_PATTERNS = [
    re.compile(r"\.getReserves\s*\("),
    re.compile(r"\.consult\s*\("),
    re.compile(r"\.price[01]CumulativeLast\b"),
]
_TWAP_HINT_RE = re.compile(r"twap|time.?weighted", re.IGNORECASE)


class OracleManipulationRule(BaseRule):
    severity = "Critical"
    explanation_template = (
        "Using a spot price from a single on-chain source (e.g., a pool's reserve ratio) without manipulation resistance "
        "allows attackers to temporarily skew the price with a large trade or flash loan, then profit from the distorted price."
    )
    impact_template = (
        "An attacker can drain funds by manipulating the oracle and then trading against the protocol."
    )
    fix_template = (
        "Use a time-weighted average price (TWAP) oracle like Uniswap V2's `price0CumulativeLast`, or a decentralized "
        "oracle network like Chainlink. Avoid using instantaneous spot prices."
    )

    def run_check(self, contract_data):
        findings = []
        seen = set()
        for contract in contract_data:
            path = contract.get("path", "")
            source = contract.get("source", "")
            if not source:
                continue
            clean = strip_comments(source)
            has_twap = bool(_TWAP_HINT_RE.search(clean))
            patterns = list(_ALWAYS_PATTERNS)
            if not has_twap:
                patterns += _TWAP_MITIGATED_PATTERNS
            for pattern in patterns:
                for match in pattern.finditer(clean):
                    line = clean[:match.start()].count("\n") + 1
                    key = (path, line)
                    if key in seen:
                        continue
                    seen.add(key)
                    snippet = clean[match.start():match.end()].strip()
                    findings.append(self._create_finding(
                        title="Potential oracle manipulation",
                        file=path,
                        line=line,
                        vulnerable_snippet=snippet,
                    ))
        return findings
# EOF: hawki/core/static_rule_engine/rules/oracle_manipulation.py
