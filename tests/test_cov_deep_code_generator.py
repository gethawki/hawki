# File: tests/deep/test_cov_deep_code_generator.py
"""
Unit tests for CodeGenerator. LiteLLMAdapter.complete is patched, so no network
call happens. Uses the real bundled prompt templates (hardhat + foundry).
"""

import unittest
from pathlib import Path
from unittest.mock import patch

from hawki.core.ai_engine.lite_llm_adapter import LiteLLMAdapter
from hawki.core.deep.executor.code_generator import CodeGenerator
from hawki.core.deep.planner.base import AttackPlan


def _plan():
    return AttackPlan(
        plan_type="novel",
        signature="novel:x",
        parameters={"name": "x", "description": "d", "steps": ["a"]},
        description="d",
    )


class TestCodeGenerator(unittest.TestCase):
    def test_generate_plain_code(self):
        with patch.object(LiteLLMAdapter, "complete", return_value="const x = 1;"):
            gen = CodeGenerator(model="openai/gpt-4")
            code = gen.generate(_plan(), "contract V {}")
        self.assertEqual(code, "const x = 1;")

    def test_generate_strips_javascript_fence(self):
        resp = "```javascript\nconst x = 1;\n```"
        with patch.object(LiteLLMAdapter, "complete", return_value=resp):
            gen = CodeGenerator(model="openai/gpt-4")
            code = gen.generate(_plan(), "contract V {}")
        self.assertEqual(code, "const x = 1;")

    def test_generate_strips_solidity_fence(self):
        resp = "```solidity\ncontract T {}\n```"
        with patch.object(LiteLLMAdapter, "complete", return_value=resp):
            gen = CodeGenerator(model="openai/gpt-4", poc_format="foundry")
            code = gen.generate(_plan(), "contract V {}")
        self.assertEqual(code, "contract T {}")

    def test_generate_strips_bare_fence(self):
        resp = "```\nplain code\n```"
        with patch.object(LiteLLMAdapter, "complete", return_value=resp):
            gen = CodeGenerator(model="openai/gpt-4")
            code = gen.generate(_plan(), "contract V {}")
        self.assertEqual(code, "plain code")

    def test_generate_empty_response_returns_none(self):
        with patch.object(LiteLLMAdapter, "complete", return_value=None):
            gen = CodeGenerator(model="openai/gpt-4")
            self.assertIsNone(gen.generate(_plan(), "contract V {}"))

    def test_foundry_uses_foundry_prompt(self):
        with patch.object(LiteLLMAdapter, "complete", return_value="x"):
            gen = CodeGenerator(model="openai/gpt-4", poc_format="foundry")
        self.assertTrue(gen.prompt_path.name.endswith("foundry.txt"))

    def test_hardhat_uses_hardhat_prompt(self):
        with patch.object(LiteLLMAdapter, "complete", return_value="x"):
            gen = CodeGenerator(model="openai/gpt-4", poc_format="hardhat")
        self.assertEqual(gen.prompt_path.name, "exploit_code.txt")

    def test_missing_prompt_raises(self):
        with self.assertRaises(FileNotFoundError):
            CodeGenerator(model="openai/gpt-4", prompts_dir=Path("/nope/prompts"))

    def test_prompt_placeholders_replaced(self):
        captured = {}

        def fake_complete(self, messages, temperature=0.2, max_tokens=3000):
            captured["prompt"] = messages[0]["content"]
            return "code"

        with patch.object(LiteLLMAdapter, "complete", fake_complete):
            gen = CodeGenerator(model="openai/gpt-4")
            gen.generate(_plan(), "contract Vault {}")
        self.assertIn("contract Vault {}", captured["prompt"])
        self.assertNotIn("{plan_json}", captured["prompt"])
        self.assertNotIn("{target_code_snippet}", captured["prompt"])


if __name__ == "__main__":
    unittest.main()
