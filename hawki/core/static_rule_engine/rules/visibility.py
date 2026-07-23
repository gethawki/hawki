# --------------------
# File: hawki/core/static_rule_engine/rules/visibility.py
# --------------------
"""
Improper visibility: functions that should be internal are marked public.

Detection is deliberately conservative to avoid false positives: it fires on
the unambiguous case of an underscore-prefixed helper (`function _helper(...)
public`) that has a real body, by Solidity convention the `_` prefix marks
internal helpers, so a `public` declaration is almost certainly a visibility
mistake. Detection runs on the raw ``source`` text (the parser emits function
metadata but no bodies), with the parsed-metadata path kept for unit tests;
results from both paths are deduped per function.
"""

import re

from . import BaseRule
from .access_control_bypass import function_occurrences, iter_functions, strip_comments

# A bodied, underscore-prefixed function declared public in the source text.
_PUBLIC_HELPER_RE = re.compile(r"function\s+(_\w+)\s*\(([^)]*)\)([^;{]*)\{")
_PUBLIC_KEYWORD_RE = re.compile(r"\bpublic\b")


class VisibilityRule(BaseRule):
    severity = "High"
    explanation_template = (
        "Functions that are only meant to be called internally should be marked `internal` or `private`. "
        "If they are `public`, they can be called by anyone, potentially exposing sensitive logic."
    )
    impact_template = (
        "An attacker could call internal functions directly, bypassing access controls or causing unexpected behavior."
    )
    fix_template = (
        "Change the visibility to `internal` or `private` if the function is not meant to be part of the public interface."
    )

    def run_check(self, contract_data):
        findings = []
        seen = set()
        for contract in contract_data:
            source = contract.get("source", "")
            path = contract.get("path", "")

            # Source-text path: underscore-prefixed helper declared public.
            if source:
                clean = strip_comments(source)
                for match in _PUBLIC_HELPER_RE.finditer(clean):
                    name = match.group(1)
                    if not _PUBLIC_KEYWORD_RE.search(match.group(3)):
                        continue
                    key = (path, name)
                    if key in seen:
                        continue
                    seen.add(key)
                    line = clean[:match.start()].count("\n") + 1
                    findings.append(self._create_finding(
                        title="Public function that may be internal",
                        file=path,
                        line=line,
                        vulnerable_snippet=f"function {name}() public ...",
                        function_name=name,
                    ))

            # Parsed-metadata path (unit tests; also covers the indexer's
            # nested `contracts[].functions[]` shape via iter_functions).
            for func, _contract_name in iter_functions(contract):
                name = func.get("name", "")
                if func.get("visibility") != "public" or not name.startswith("_"):
                    continue
                key = (path, name)
                if key in seen:
                    continue
                occurrences = function_occurrences(source, name)
                line = func.get("line", 1)
                if occurrences:
                    bodied = [occ for occ in occurrences if occ["has_body"]]
                    # Declaration-only signatures (interfaces/abstract) are
                    # not callable implementations; skip them.
                    if not bodied:
                        continue
                    line = bodied[0]["line"]
                seen.add(key)
                snippet = f"function {name}() public ..."
                findings.append(self._create_finding(
                    title="Public function that may be internal",
                    file=path,
                    line=line,
                    vulnerable_snippet=snippet,
                    function_name=name,
                ))
        return findings
# EOF: hawki/core/static_rule_engine/rules/visibility.py
