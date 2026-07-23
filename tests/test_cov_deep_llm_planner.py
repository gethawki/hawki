# File: tests/deep/test_cov_deep_llm_planner.py
"""
Unit tests for LLMPlanner. The LLM is fully mocked (LiteLLMAdapter.complete is
patched) so no network call happens. Uses the real bundled prompt template.
"""

import json
import unittest
from pathlib import Path
from unittest.mock import patch

from hawki.core.ai_engine.lite_llm_adapter import LiteLLMAdapter
from hawki.core.deep.planner.llm_planner import LLMPlanner


class _FakeMemory:
    def __init__(self, recent=None):
        self._recent = recent or []

    def get_recent(self, limit=10):
        return self._recent


_VALID_PLAN = {
    "name": "transient-storage-reentrancy",
    "description": "Reenter via transient storage slot.",
    "vulnerability_type": "reentrancy",
    "steps": ["deposit", "withdraw", "reenter"],
    "expected_impact": "drains the vault",
}


def _make_planner():
    return LLMPlanner(model="openai/gpt-4", api_key="dummy")


class TestLLMPlanner(unittest.TestCase):
    def test_valid_plan_parsed(self):
        with patch.object(LiteLLMAdapter, "complete", return_value=json.dumps(_VALID_PLAN)):
            planner = _make_planner()
            plan = planner.next_attack(_FakeMemory(), goal="drain", repo_summary="Contract V")
        self.assertIsNotNone(plan)
        self.assertEqual(plan.type, "novel")
        self.assertEqual(plan.signature, "novel:transient-storage-reentrancy")
        self.assertEqual(plan.parameters["name"], "transient-storage-reentrancy")
        self.assertEqual(plan.parameters["vulnerability_type"], "reentrancy")
        # estimated_tokens is attached to the plan after parsing.
        self.assertIn("estimated_tokens", plan.parameters)
        self.assertGreater(plan.parameters["estimated_tokens"], 0)

    def test_markdown_fences_stripped(self):
        fenced = "```json\n" + json.dumps(_VALID_PLAN) + "\n```"
        with patch.object(LiteLLMAdapter, "complete", return_value=fenced):
            planner = _make_planner()
            plan = planner.next_attack(_FakeMemory(), goal="drain")
        self.assertIsNotNone(plan)
        self.assertEqual(plan.parameters["name"], "transient-storage-reentrancy")

    def test_bare_fences_stripped(self):
        fenced = "```\n" + json.dumps(_VALID_PLAN) + "\n```"
        with patch.object(LiteLLMAdapter, "complete", return_value=fenced):
            planner = _make_planner()
            plan = planner.next_attack(_FakeMemory(), goal="drain")
        self.assertIsNotNone(plan)

    def test_missing_required_field_returns_none(self):
        bad = dict(_VALID_PLAN)
        del bad["steps"]
        with patch.object(LiteLLMAdapter, "complete", return_value=json.dumps(bad)):
            planner = _make_planner()
            plan = planner.next_attack(_FakeMemory(), goal="drain")
        self.assertIsNone(plan)

    def test_invalid_json_returns_none(self):
        with patch.object(LiteLLMAdapter, "complete", return_value="not json at all {"):
            planner = _make_planner()
            plan = planner.next_attack(_FakeMemory(), goal="drain")
        self.assertIsNone(plan)

    def test_empty_response_returns_none(self):
        with patch.object(LiteLLMAdapter, "complete", return_value=""):
            planner = _make_planner()
            plan = planner.next_attack(_FakeMemory(), goal="drain")
        self.assertIsNone(plan)

    def test_no_llm_client_returns_none(self):
        with patch.object(LiteLLMAdapter, "complete", return_value=json.dumps(_VALID_PLAN)):
            planner = _make_planner()
        planner.llm = None
        self.assertIsNone(planner.next_attack(_FakeMemory(), goal="drain"))

    def test_build_context_injects_memory_and_goal(self):
        recent = [{"attack_type": "rule", "success": False}]
        with patch.object(LiteLLMAdapter, "complete", return_value=json.dumps(_VALID_PLAN)):
            planner = _make_planner()
            context = planner._build_context(_FakeMemory(recent=recent), goal="steal-eth", repo_summary="Contract Foo")
        self.assertIn("steal-eth", context)
        self.assertIn("Contract Foo", context)
        self.assertIn("attack_type", context)  # memory json embedded
        self.assertNotIn("{goal}", context)
        self.assertNotIn("{repo_summary}", context)

    def test_build_context_no_previous_attempts(self):
        with patch.object(LiteLLMAdapter, "complete", return_value=json.dumps(_VALID_PLAN)):
            planner = _make_planner()
            context = planner._build_context(_FakeMemory(recent=[]), goal="g", repo_summary="s")
        self.assertIn("No previous attempts.", context)

    def test_missing_prompt_file_raises(self):
        with self.assertRaises(FileNotFoundError):
            LLMPlanner(model="openai/gpt-4", prompts_dir=Path("/nonexistent/prompts/dir"))


if __name__ == "__main__":
    unittest.main()
