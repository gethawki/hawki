# --------------------
# File: hawki/core/ai_engine/llm_orchestrator.py
# --------------------
"""
High-level orchestrator for LLM interactions.
Manages prompt rendering, calling the adapter, and parsing responses.
"""

import json
import logging
from pathlib import Path
from typing import Any, Dict, Optional

from .lite_llm_adapter import LiteLLMAdapter
from .prompt_manager import PromptManager

logger = logging.getLogger(__name__)

class LLMOrchestrator:
    """Orchestrates LLM calls using templates and adapters."""

    def __init__(
        self,
        model: Optional[str] = None,
        api_key: Optional[str] = None,
        templates_dir: Optional[Path] = None,
    ):
        self.adapter = LiteLLMAdapter(model=model, api_key=api_key)
        self.prompts = PromptManager(templates_dir)

    def analyze(
        self,
        template_name: str,
        temperature: float = 0.2,
        max_tokens: int = 2000,
        **kwargs,
    ) -> Optional[Dict[str, Any]]:
        """
        Render a prompt template, call the LLM, and attempt to parse JSON response.
        Returns a dict if parsing succeeds, else None.
        """
        messages = self.prompts.render(template_name, **kwargs)
        if not messages:
            return None

        response = self.adapter.complete(
            messages=messages,
            temperature=temperature,
            max_tokens=max_tokens,
        )
        if not response:
            return None

        # Attempt to extract JSON from response (handle markdown fences)
        try:
            # Remove possible markdown code fences
            cleaned = response.strip()
            if cleaned.startswith("```json"):
                cleaned = cleaned[7:]
            if cleaned.startswith("```"):
                cleaned = cleaned[3:]
            if cleaned.endswith("```"):
                cleaned = cleaned[:-3]
            cleaned = cleaned.strip()

            data = json.loads(cleaned)
            return data
        except json.JSONDecodeError:
            logger.warning("LLM response was not valid JSON")
            # Fallback: return raw text in a structure
            return {"raw_response": response}

# EOF: hawki/core/ai_engine/llm_orchestrator.py