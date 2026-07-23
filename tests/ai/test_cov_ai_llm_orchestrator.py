# File: tests/ai/test_cov_ai_llm_orchestrator.py
"""
Coverage tests for LLMOrchestrator.analyze. A real PromptManager is pointed at a
tmp template dir, and the LiteLLMAdapter is replaced with a mock so no LLM is
contacted. Covers JSON parsing, markdown-fence stripping, the raw-response
fallback, and the missing-template / empty-response short-circuits.
"""

import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from hawki.core.ai_engine.llm_orchestrator import LLMOrchestrator


class TestLLMOrchestrator(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        tdir = Path(self.tmp.name)
        (tdir / "vuln_analysis_prompt.json").write_text(
            json.dumps({"system": "sys {contract_name}", "user": "usr {source_code}"})
        )
        self.orch = LLMOrchestrator(templates_dir=tdir)
        # Replace the real adapter so no litellm call is made.
        self.orch.adapter = mock.MagicMock()

    def _analyze(self):
        return self.orch.analyze(
            "vuln_analysis_prompt", contract_name="C", source_code="src"
        )

    def test_plain_json_parsed(self):
        self.orch.adapter.complete.return_value = '{"findings": [1, 2]}'
        self.assertEqual(self._analyze(), {"findings": [1, 2]})

    def test_json_fence_stripped(self):
        self.orch.adapter.complete.return_value = '```json\n{"a": 1}\n```'
        self.assertEqual(self._analyze(), {"a": 1})

    def test_bare_fence_stripped(self):
        self.orch.adapter.complete.return_value = '```\n{"b": 2}\n```'
        self.assertEqual(self._analyze(), {"b": 2})

    def test_invalid_json_falls_back_to_raw(self):
        self.orch.adapter.complete.return_value = "not json at all"
        self.assertEqual(self._analyze(), {"raw_response": "not json at all"})

    def test_missing_template_returns_none(self):
        self.assertIsNone(self.orch.analyze("no_such_template", x=1))
        self.orch.adapter.complete.assert_not_called()

    def test_empty_response_returns_none(self):
        self.orch.adapter.complete.return_value = None
        self.assertIsNone(self._analyze())

    def test_analyze_passes_temperature_and_tokens(self):
        self.orch.adapter.complete.return_value = "{}"
        self.orch.analyze(
            "vuln_analysis_prompt",
            temperature=0.9,
            max_tokens=123,
            contract_name="C",
            source_code="src",
        )
        _, kwargs = self.orch.adapter.complete.call_args
        self.assertEqual(kwargs["temperature"], 0.9)
        self.assertEqual(kwargs["max_tokens"], 123)


if __name__ == "__main__":
    unittest.main()
