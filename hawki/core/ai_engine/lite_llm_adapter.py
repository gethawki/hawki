# --------------------
# File: hawki/core/ai_engine/lite_llm_adapter.py
# --------------------
"""
Adapter for LiteLLM to unify LLM calls.
Handles API key management, retries, and error logging.
"""

import logging
import os
from typing import Dict, List, Optional

from litellm import completion
from litellm.exceptions import (
    APIConnectionError,
    RateLimitError,
    ServiceUnavailableError,
)

logger = logging.getLogger(__name__)

class LiteLLMAdapter:
    """Wrapper around LiteLLM with built-in error handling and configuration."""

    DEFAULT_MODEL = "gemini/gemini-1.5-flash"  # Free tier, widely available

    def __init__(
        self,
        model: Optional[str] = None,
        api_key: Optional[str] = None,
        max_retries: int = 3,
        timeout: int = 60,
    ):
        self.model = model or self.DEFAULT_MODEL
        self.max_retries = max_retries
        self.timeout = timeout

        # Set API key if provided (LiteLLM reads env vars automatically)
        if api_key:
            # Determine provider from model string (e.g., "gemini/..." -> GEMINI_API_KEY)
            if self.model.startswith("gemini/"):
                os.environ["GEMINI_API_KEY"] = api_key
            elif self.model.startswith("openai/"):
                os.environ["OPENAI_API_KEY"] = api_key
            elif self.model.startswith("anthropic/"):
                os.environ["ANTHROPIC_API_KEY"] = api_key
            # Add more as needed

    def complete(
        self,
        messages: List[Dict[str, str]],
        temperature: float = 0.2,
        max_tokens: int = 2000,
    ) -> Optional[str]:
        """
        Send a chat completion request with retries.
        Returns the response content or None on failure.
        """
        for attempt in range(1, self.max_retries + 1):
            try:
                response = completion(
                    model=self.model,
                    messages=messages,
                    temperature=temperature,
                    max_tokens=max_tokens,
                    timeout=self.timeout,
                )
                content = response.choices[0].message.content
                logger.debug(f"LLM response received ({len(content)} chars)")
                return content
            except (APIConnectionError, RateLimitError, ServiceUnavailableError) as e:
                logger.warning(f"LLM attempt {attempt} failed: {e}")
                if attempt == self.max_retries:
                    logger.error("Max retries exceeded for LLM call")
                    return None
            except Exception as e:
                logger.error(f"Unexpected LLM error: {e}", exc_info=True)
                return None
        return None

# EOF: hawki/core/ai_engine/lite_llm_adapter.py