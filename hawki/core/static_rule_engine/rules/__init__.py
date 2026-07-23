# --------------------
# File: hawki/core/static_rule_engine/rules/__init__.py
# --------------------
"""
Base rule class and rule loader.

Also provides the shared building blocks that make every finding
self-explanatory: a canonical severity normalizer and a robust snippet
extractor that reads real surrounding context from the source file so the
report always shows accurate, readable code around the flagged line.
"""

from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any, Dict, List, Optional

# Canonical severity spelling used across the whole platform (rules -> scoring
# -> report). Everything normalizes to Title case so counts and colors line up.
CANONICAL_SEVERITIES = ("Critical", "High", "Medium", "Low", "Info")

_SEVERITY_ALIASES = {
    "critical": "Critical",
    "high": "High",
    "medium": "Medium",
    "moderate": "Medium",
    "low": "Low",
    "info": "Info",
    "informational": "Info",
    "note": "Info",
    "none": "Info",
    "": "Info",
}


def normalize_severity(value: Any) -> str:
    """Return the canonical Title-case severity for any casing/alias.

    Unknown values are Title-cased rather than dropped, so nothing silently
    disappears from the report.
    """
    key = str(value or "").strip().lower()
    if key in _SEVERITY_ALIASES:
        return _SEVERITY_ALIASES[key]
    return key.capitalize() if key else "Info"


class BaseRule(ABC):
    """Abstract base class for all static analysis rules."""

    # Rule metadata (should be overridden by subclasses)
    severity = "Info"  # Default, override in subclass
    explanation_template = "No explanation provided."
    impact_template = "No impact analysis provided."
    fix_template = "No fix snippet available."

    # How many lines of context to show above/below the flagged line.
    snippet_context_lines = 2

    @abstractmethod
    def run_check(self, contract_data: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Execute the rule on the provided contract data.
        Returns a list of findings (dictionaries). Each finding should contain at least:
            - 'title': short description
            - 'severity': string (Critical, High, Medium, Low, Info)
            - 'file': relative path
            - 'line': int
            - 'vulnerable_snippet': the exact code lines
        Additional fields (explanation, impact, fix_snippet) will be merged by the RuleEngine.
        """
        pass

    def _create_finding(self, title: str, file: str, line: int, vulnerable_snippet: str,
                        severity: Optional[str] = None, **extra) -> Dict[str, Any]:
        """
        Helper to create a finding dictionary with consistent fields.

        The snippet is upgraded in place: whenever the flagged line can be read
        back from the source file, the bare fragment a rule passed is replaced
        with a clean, line-numbered block of surrounding context so the report
        pinpoints exactly where the flaw lives. The RuleEngine later adds the
        explanation, impact, and fix_snippet.
        """
        safe_file = (file or "").strip() or "unknown"
        safe_line = line if isinstance(line, int) and line > 0 else 0

        snippet = self._build_snippet(safe_file, safe_line, vulnerable_snippet)

        finding = {
            "title": title or "Security finding",
            "severity": normalize_severity(severity or self.severity),
            "file": safe_file,
            "line": safe_line or "?",
            "vulnerable_snippet": snippet,
            # Rule-specific fix advice, used by the remediation engine as a
            # fallback when no JSON template matches this rule.
            "_fix_template": getattr(self, "fix_template", "") or "",
        }
        finding.update(extra)
        return finding

    # ------------------------------------------------------------------
    # Snippet extraction
    # ------------------------------------------------------------------
    def _build_snippet(self, file: str, line: int, fallback: str) -> str:
        """Return a readable snippet, preferring real file context."""
        context = self._read_snippet_with_context(file, line)
        if context:
            return context
        cleaned = self._clean_fragment(fallback)
        return cleaned or "// snippet unavailable"

    def _read_snippet_with_context(self, file: str, line: int) -> Optional[str]:
        """Read a few lines around `line` from `file` and format them.

        Produces a line-numbered block with a marker on the offending line, for
        example::

            5 |     function random() public view returns (uint) {
          > 6 |         return uint(blockhash(block.number - 1));
            7 |     }

        Returns None when the file cannot be read or the line is unknown.
        """
        if not line or line < 1 or not file or file == "unknown":
            return None
        try:
            path = Path(file)
            if not path.is_file():
                return None
            text = path.read_text(encoding="utf-8", errors="replace")
        except Exception:
            return None

        lines = text.splitlines()
        if not lines or line > len(lines):
            return None

        ctx = max(0, int(getattr(self, "snippet_context_lines", 2)))
        start = max(1, line - ctx)
        end = min(len(lines), line + ctx)
        block = lines[start - 1:end]

        # Dedent by the smallest indentation shared across the block so the
        # snippet reads cleanly regardless of nesting depth.
        indents = [len(l) - len(l.lstrip()) for l in block if l.strip()]
        strip = min(indents) if indents else 0

        width = len(str(end))
        rendered = []
        for offset, raw in enumerate(block):
            n = start + offset
            body = raw[strip:] if len(raw) >= strip else raw
            marker = ">" if n == line else " "
            rendered.append(f"{marker} {str(n).rjust(width)} | {body}".rstrip())
        return "\n".join(rendered)

    @staticmethod
    def _clean_fragment(fragment: str) -> str:
        """Trim a rule-supplied fragment into something presentable."""
        if not fragment:
            return ""
        stripped = str(fragment).strip("\n")
        lines = [l.rstrip() for l in stripped.splitlines()]
        indents = [len(l) - len(l.lstrip()) for l in lines if l.strip()]
        strip = min(indents) if indents else 0
        return "\n".join(l[strip:] if len(l) >= strip else l for l in lines).strip()

# EOF: hawki/core/static_rule_engine/rules/__init__.py
