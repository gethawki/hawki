# --------------------
# File: hawki/core/static_rule_engine/__init__.py (updated)
# --------------------
"""
Static rule engine that auto-discovers rule classes from the rules/ directory.
Now integrates with Remediation Engine to enrich findings with fix snippets.
"""

import importlib
import logging
import pkgutil
from pathlib import Path
from typing import Any, Dict, List, Optional

from ..remediation_engine import RemediationEngine
from .rules import BaseRule

logger = logging.getLogger(__name__)

class RuleEngine:
    """Discovers and executes all rules against contract data."""

    def __init__(self, remediation_engine: Optional[RemediationEngine] = None):
        self.rules: List[BaseRule] = []
        self.remediation = remediation_engine or RemediationEngine()
        self._discover_rules()

    def _discover_rules(self):
        """Dynamically import all modules in the rules package and instantiate rule classes."""
        package = "hawki.core.static_rule_engine.rules"
        rules_dir = str(Path(__file__).parent / "rules")
        for _, module_name, _ in pkgutil.iter_modules([rules_dir]):
            full_module = f"{package}.{module_name}"
            try:
                module = importlib.import_module(full_module)
                for attr_name in dir(module):
                    attr = getattr(module, attr_name)
                    if isinstance(attr, type) and issubclass(attr, BaseRule) and attr is not BaseRule:
                        self.rules.append(attr())
                        logger.debug(f"Loaded rule: {attr_name}")
            except Exception as e:
                logger.error(f"Failed to load rule module {full_module}: {e}")

    def run_all(self, contract_data: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Run all rules, then enrich findings with remediation snippets."""
        findings = []
        for rule in self.rules:
            try:
                rule_findings = rule.run_check(contract_data)
                if rule_findings:
                    # Add rule metadata to each finding (explanation, impact, etc.)
                    for f in rule_findings:
                        # Ensure required fields
                        f.setdefault("explanation", getattr(rule, "explanation_template", ""))
                        f.setdefault("impact", getattr(rule, "impact_template", ""))
                        f.setdefault("fix_snippet", "")  # will be populated by remediation
                        # Store rule class name for remediation
                        f["rule"] = rule.__class__.__name__.replace("Rule", "").lower()
                        # Provide basic context for remediation (function name, etc.)
                        # We'll pass the whole finding as context for now; remediation engine can extract what it needs.
                    findings.extend(rule_findings)
            except Exception as e:
                logger.error(f"Rule {rule.__class__.__name__} failed: {e}")

        # Apply remediation to all findings
        for f in findings:
            # Build context from the finding itself and possibly from contract_data (if needed)
            context = {
                "function_name": f.get("function_name", ""),
                "visibility": f.get("visibility", "public"),
                "condition": "amount > 0",  # placeholder; real extraction would be complex
                "state_updates": "// state updates",
                "external_call": "msg.sender",
                "amount": "amount",
            }
            fix = self.remediation.get_fix(f, context)
            f["fix_snippet"] = fix

        return findings

# EOF: hawki/core/static_rule_engine/__init__.py