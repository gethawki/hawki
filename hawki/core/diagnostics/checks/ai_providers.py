# File: hawki/core/diagnostics/checks/ai_providers.py
"""
Check AI provider connectivity (OpenAI, Anthropic).
"""

import logging
import os
from typing import Any, Dict, Optional

from .base import CheckResult, DiagnosticCheck

logger = logging.getLogger(__name__)

class AIProvidersCheck(DiagnosticCheck):
    """Test API keys for configured AI providers."""

    @property
    def name(self) -> str:
        return "ai_providers"

    @property
    def category(self) -> str:
        return "ai"

    def run(self, config: Optional[Dict[str, Any]] = None) -> CheckResult:
        details = {}
        failures = []

        # Check OpenAI
        openai_key = os.environ.get("OPENAI_API_KEY") or (config and config.get("openai_api_key"))
        if openai_key:
            try:
                import openai
                client = openai.OpenAI(api_key=openai_key)
                models = client.models.list(limit=5)
                details["openai"] = {"status": "ok", "message": f"Connected. Found {len(models.data)} models."}
            except Exception as e:
                details["openai"] = {"status": "error", "message": str(e)}
                failures.append("OpenAI")
        else:
            details["openai"] = {"status": "skipped", "message": "OPENAI_API_KEY not set"}

        # Check Anthropic
        anthropic_key = os.environ.get("ANTHROPIC_API_KEY") or (config and config.get("anthropic_api_key"))
        if anthropic_key:
            try:
                import anthropic
                client = anthropic.Anthropic(api_key=anthropic_key)
                # Just a simple ping
                client.messages.create(
                    model="claude-3-haiku-20240307",
                    max_tokens=10,
                    messages=[{"role": "user", "content": "Hello"}]
                )
                details["anthropic"] = {"status": "ok", "message": "Connected successfully."}
            except Exception as e:
                details["anthropic"] = {"status": "error", "message": str(e)}
                failures.append("Anthropic")
        else:
            details["anthropic"] = {"status": "skipped", "message": "ANTHROPIC_API_KEY not set"}

        if failures:
            return CheckResult(
                name=self.name,
                status="warn",
                message=f"Some AI providers failed: {', '.join(failures)}",
                fix="Check your API keys and network connectivity.",
                details=details,
            )

        return CheckResult(
            name=self.name,
            status="pass",
            message="AI providers configured.",
            details=details,
        )
# EOF
