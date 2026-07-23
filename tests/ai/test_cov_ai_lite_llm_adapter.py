# File: tests/ai/test_cov_ai_lite_llm_adapter.py
"""
Coverage tests for LiteLLMAdapter. litellm.completion is fully mocked at the
adapter's import site -- no real LLM is ever contacted. Covers API-key routing
into provider env vars, successful completion, retry exhaustion on transient
errors, and the generic-exception short-circuit.
"""

import os
import unittest
from unittest import mock

from litellm.exceptions import RateLimitError

from hawki.core.ai_engine import lite_llm_adapter as mod
from hawki.core.ai_engine.lite_llm_adapter import LiteLLMAdapter


def _response(text):
    r = mock.MagicMock()
    r.choices[0].message.content = text
    return r


class TestKeyRouting(unittest.TestCase):
    def test_gemini_key_routed(self):
        with mock.patch.dict(os.environ, {}, clear=False):
            LiteLLMAdapter(model="gemini/gemini-1.5-flash", api_key="G-KEY")
            self.assertEqual(os.environ["GEMINI_API_KEY"], "G-KEY")

    def test_openai_key_routed(self):
        with mock.patch.dict(os.environ, {}, clear=False):
            LiteLLMAdapter(model="openai/gpt-4o", api_key="O-KEY")
            self.assertEqual(os.environ["OPENAI_API_KEY"], "O-KEY")

    def test_anthropic_key_routed(self):
        with mock.patch.dict(os.environ, {}, clear=False):
            LiteLLMAdapter(model="anthropic/claude-3", api_key="A-KEY")
            self.assertEqual(os.environ["ANTHROPIC_API_KEY"], "A-KEY")

    def test_default_model_and_no_key(self):
        adapter = LiteLLMAdapter()
        self.assertEqual(adapter.model, LiteLLMAdapter.DEFAULT_MODEL)

    def test_unknown_prefix_sets_nothing(self):
        # A provider prefix we do not special-case leaves env untouched.
        with mock.patch.dict(os.environ, {}, clear=True):
            LiteLLMAdapter(model="cohere/command", api_key="C-KEY")
            self.assertNotIn("GEMINI_API_KEY", os.environ)
            self.assertNotIn("OPENAI_API_KEY", os.environ)


class TestComplete(unittest.TestCase):
    def test_complete_success_returns_content(self):
        adapter = LiteLLMAdapter(model="gemini/x")
        with mock.patch.object(mod, "completion", return_value=_response("hello")) as c:
            out = adapter.complete([{"role": "user", "content": "hi"}])
        self.assertEqual(out, "hello")
        c.assert_called_once()

    def test_complete_generic_exception_returns_none(self):
        adapter = LiteLLMAdapter(model="gemini/x")
        with mock.patch.object(mod, "completion", side_effect=ValueError("boom")):
            self.assertIsNone(adapter.complete([{"role": "user", "content": "hi"}]))

    def test_complete_retries_then_returns_none(self):
        adapter = LiteLLMAdapter(model="gemini/x", max_retries=3)
        err = RateLimitError(message="slow down", llm_provider="gemini", model="x")
        with mock.patch.object(mod, "completion", side_effect=err) as c:
            out = adapter.complete([{"role": "user", "content": "hi"}])
        self.assertIsNone(out)
        self.assertEqual(c.call_count, 3)

    def test_complete_recovers_on_second_attempt(self):
        adapter = LiteLLMAdapter(model="gemini/x", max_retries=3)
        err = RateLimitError(message="slow down", llm_provider="gemini", model="x")
        with mock.patch.object(
            mod, "completion", side_effect=[err, _response("ok")]
        ) as c:
            out = adapter.complete([{"role": "user", "content": "hi"}])
        self.assertEqual(out, "ok")
        self.assertEqual(c.call_count, 2)


if __name__ == "__main__":
    unittest.main()
