# --------------------
# File: hawki/core/remediation_engine/engine.py
# --------------------
"""
RemediationEngine class: loads templates and populates fix snippets using AST context.

The engine guarantees every finding leaves with a concrete, readable fix. It
resolves a finding to its JSON template even when the rule id and the template
filename differ only by underscores, substitutes {{double-brace}} placeholders
robustly, and falls back to the rule's own fix guidance (never a blank field)
when no template exists.
"""

import json
import logging
import re
from pathlib import Path
from typing import Any, Dict, Optional

logger = logging.getLogger(__name__)

# Sensible defaults so a substituted fix still reads as valid guidance even when
# the AST context could not supply a value for a placeholder.
_PLACEHOLDER_DEFAULTS = {
    "function_name": "vulnerableFunction",
    "visibility": "public",
    "condition": "input is valid",
    "state_updates": "// update state here",
    "external_call": "recipient",
    "amount": "amount",
    "variable": "value",
    "owner": "owner",
}

_GENERIC_FIX = "No specific fix snippet available. Review the code and apply secure patterns."


class RemediationEngine:
    """Generates fix snippets from templates and AST context."""

    def __init__(self, templates_dir: Optional[Path] = None):
        self.templates_dir = templates_dir or Path(__file__).parent / "templates"
        self.templates: Dict[str, Dict[str, str]] = {}
        # Index keyed by the template stem with separators removed, so that a
        # rule id like "blockhashrandomness" resolves to "blockhash_randomness".
        self._normalized_index: Dict[str, Dict[str, str]] = {}
        self._load_templates()

    @staticmethod
    def _normalize_key(name: str) -> str:
        """Collapse a rule id / template stem to a comparable form."""
        return re.sub(r"[^a-z0-9]", "", str(name or "").lower())

    def _load_templates(self):
        """Load all JSON templates from the templates directory."""
        if not self.templates_dir.exists():
            logger.warning(f"Templates directory not found: {self.templates_dir}")
            return
        for template_file in self.templates_dir.glob("*.json"):
            try:
                with open(template_file) as f:
                    template_data = json.load(f)
                rule_name = template_file.stem  # e.g., "reentrancy"
                self.templates[rule_name] = template_data
                self._normalized_index[self._normalize_key(rule_name)] = template_data
                logger.debug(f"Loaded remediation template: {rule_name}")
            except Exception as e:
                logger.error(f"Failed to load template {template_file}: {e}")

    def _resolve_template(self, rule_name: str, title: str) -> Optional[Dict[str, str]]:
        """Find the best template for a finding by rule id or title."""
        if rule_name:
            template = self.templates.get(rule_name)
            if template:
                return template
            template = self._normalized_index.get(self._normalize_key(rule_name))
            if template:
                return template
        # Last resort: try to match a known template against the title text.
        norm_title = self._normalize_key(title)
        if norm_title:
            for key, template in self._normalized_index.items():
                if key and key in norm_title:
                    return template
        return None

    def get_fix(self, finding: Dict[str, Any], context: Dict[str, Any]) -> str:
        """
        Generate a fix snippet for a given finding using the appropriate template.

        Resolution order:
          1. JSON template matched by rule id (exact, then separator-insensitive).
          2. JSON template matched by keywords in the finding title.
          3. The rule's own fix guidance (stashed on the finding as _fix_template).
          4. A clear generic message.

        Args:
            finding: The finding dictionary, must contain a rule identifier.
            context: AST-derived context (function names, variable names, etc.).

        Returns:
            A populated, non-empty fix snippet string.
        """
        rule_name = str(finding.get("rule", "") or "").lower()
        title = finding.get("title", "") or ""

        template = self._resolve_template(rule_name, title)

        # Rule-supplied fallback advice (attached by BaseRule._create_finding).
        rule_fix = str(finding.pop("_fix_template", "") or "").strip()

        if template:
            fix_template = template.get("fix_snippet", "")
            if fix_template:
                return self._populate_placeholders(fix_template, context)
            logger.debug(f"Template for '{rule_name}' has no fix_snippet; using rule guidance")

        if rule_fix and rule_fix.lower() != "no fix snippet available.":
            return rule_fix

        logger.debug(f"No remediation template for rule '{rule_name}', using generic")
        return _GENERIC_FIX

    def _populate_placeholders(self, template: str, context: Dict[str, Any]) -> str:
        """
        Replace {{placeholder}} with values from context, falling back to
        readable defaults so the rendered fix never contains empty holes.
        """
        def replacer(match):
            key = match.group(1).strip()
            # Allow nested keys like "function.name".
            parts = key.split('.')
            value = context
            for part in parts:
                if isinstance(value, dict):
                    value = value.get(part, None)
                else:
                    value = None
                    break
            if value is None or value == "":
                return str(_PLACEHOLDER_DEFAULTS.get(parts[-1], parts[-1]))
            return str(value)

        return re.sub(r'\{\{\s*([^}]+?)\s*\}\}', replacer, template)

# EOF: hawki/core/remediation_engine/engine.py
