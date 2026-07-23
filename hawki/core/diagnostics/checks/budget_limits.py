# File: hawki/core/diagnostics/checks/budget_limits.py
"""
Check budget limits for deep agent.
"""

import os
from typing import Any, Dict, Optional

from .base import CheckResult, DiagnosticCheck


class BudgetLimitsCheck(DiagnosticCheck):
    """Validate deep agent budget settings."""

    @property
    def name(self) -> str:
        return "budget_limits"

    @property
    def category(self) -> str:
        return "budget"

    def run(self, config: Optional[Dict[str, Any]] = None) -> CheckResult:
        details = {}
        warnings = []

        # Check budget-attempts from config or env
        attempts = config.get("budget_attempts") if config else None
        if attempts is not None and attempts <= 0:
            details["budget_attempts"] = {"status": "warn", "message": f"Attempts set to {attempts} (will be ignored)"}
            warnings.append("budget_attempts")
        else:
            details["budget_attempts"] = {"status": "ok", "message": f"Attempts: {attempts or 'default'}"}

        # Check budget-tokens
        tokens = config.get("budget_tokens") if config else None
        if tokens is not None and tokens <= 0:
            details["budget_tokens"] = {"status": "warn", "message": f"Tokens set to {tokens} (will be ignored)"}
            warnings.append("budget_tokens")
        elif tokens is not None and tokens < 1000:
            details["budget_tokens"] = {"status": "warn", "message": f"Tokens set to {tokens} (very low)"}
            warnings.append("budget_tokens_low")
        else:
            details["budget_tokens"] = {"status": "ok", "message": f"Tokens: {tokens or 'default'}"}

        # Check if OpenAI or Anthropic keys are set for novel attacks
        openai_key = os.environ.get("OPENAI_API_KEY") or (config and config.get("openai_api_key"))
        anthropic_key = os.environ.get("ANTHROPIC_API_KEY") or (config and config.get("anthropic_api_key"))
        if not openai_key and not anthropic_key:
            details["llm_key"] = {"status": "warn", "message": "No LLM API keys found (novel attacks may fail)"}
            warnings.append("llm_key")

        if warnings:
            return CheckResult(
                name=self.name,
                status="warn",
                message=f"Budget warnings: {', '.join(warnings)}",
                fix="Adjust budget values or set LLM API keys.",
                details=details,
            )

        return CheckResult(
            name=self.name,
            status="pass",
            message="Budget limits configured.",
            details=details,
        )
# EOF
