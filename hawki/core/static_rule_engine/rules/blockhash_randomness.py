# --------------------
# File: hawki/core/static_rule_engine/rules/blockhash_randomness.py
# --------------------
"""
Blockhash as randomness source: using blockhash for randomness is insecure because it can be manipulated by miners.
"""

import re

from . import BaseRule

# One combined pattern so overlapping alternatives (`block.blockhash(` used to
# match BOTH `block\.blockhash` and `blockhash\(`) cannot double-count a single
# occurrence. Also covers the other miner-influenced entropy sources.
_PATTERN = re.compile(
    r"block\.(?:blockhash|difficulty|prevrandao)\b|\bblockhash\s*\("
)

# Blank out comments while preserving offsets/line numbers.
_COMMENT = re.compile(r"//[^\n]*|/\*.*?\*/", re.DOTALL)


def _strip_comments(source: str) -> str:
    return _COMMENT.sub(lambda m: re.sub(r"[^\n]", " ", m.group(0)), source)


class BlockhashRandomnessRule(BaseRule):
    severity = "High"
    explanation_template = (
        "Using `blockhash` or `block.blockhash` as a source of randomness is insecure because miners can influence it. "
        "They can choose to withhold blocks or manipulate the hash to their advantage."
    )
    impact_template = (
        "An attacker could predict or manipulate the randomness, leading to unfair outcomes in games, lotteries, "
        "or other mechanisms that rely on unpredictable values."
    )
    fix_template = (
        "Use a verifiable randomness source like Chainlink VRF, or a commit-reveal scheme with a future blockhash "
        "that cannot be influenced by the caller."
    )

    def run_check(self, contract_data):
        findings = []
        for contract in contract_data:
            source = contract.get("source", "")
            clean = _strip_comments(source)
            for match in _PATTERN.finditer(clean):
                line = clean[:match.start()].count('\n') + 1
                snippet = clean[match.start():match.end()]
                findings.append(self._create_finding(
                    title="Insecure randomness via blockhash",
                    file=contract.get("path", ""),
                    line=line,
                    vulnerable_snippet=snippet,
                ))
        return findings
# EOF
