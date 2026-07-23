# File: tests/deep/test_cov_deep_novel_executor.py
"""
Unit tests for NovelExecutor. Both the LLM (via CodeGenerator) and the sandbox
(SandboxManager) are patched, so neither an LLM call nor Docker is ever used.
"""

import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

from hawki.core.ai_engine.lite_llm_adapter import LiteLLMAdapter
from hawki.core.deep.executor.novel_executor import NovelExecutor
from hawki.core.deep.planner.base import AttackPlan


def _plan(estimated_tokens=500):
    return AttackPlan(
        plan_type="novel",
        signature="novel:x",
        parameters={"name": "x", "description": "d", "steps": ["a"], "estimated_tokens": estimated_tokens},
        description="d",
    )


class _Base(unittest.TestCase):
    def setUp(self):
        # Patch complete so CodeGenerator construction (which builds a
        # LiteLLMAdapter) never risks a real call.
        self._p = patch.object(LiteLLMAdapter, "complete", return_value="const x = 1;")
        self._p.start()
        self.addCleanup(self._p.stop)


class TestNovelExecutor(_Base):
    def _make(self, poc_format="hardhat"):
        return NovelExecutor(llm_model="openai/gpt-4", llm_api_key="k", poc_format=poc_format)

    def test_no_solidity_files_fails(self, ):
        ex = self._make()
        result = ex.execute(_plan(), Path("/tmp/does-not-exist-repo-xyz"))
        self.assertFalse(result["success"])
        self.assertIn("No Solidity files", result["logs"])

    def test_hardhat_success(self):
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            repo = Path(d)
            (repo / "V.sol").write_text("contract V {}")
            sandbox = MagicMock()
            sandbox.run_generated_script.return_value = {"success": True, "gas_used": 100}
            ex = self._make("hardhat")
            with patch.object(ex.code_gen, "generate", return_value="const x=1;"), \
                 patch("hawki.core.deep.executor.novel_executor.SandboxManager", return_value=sandbox):
                result = ex.execute(_plan(estimated_tokens=42), repo)
        self.assertTrue(result["success"])
        self.assertEqual(result["estimated_tokens"], 42)
        sandbox.run_generated_script.assert_called_once()
        sandbox.cleanup.assert_called_once()

    def test_foundry_uses_forge(self):
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            repo = Path(d)
            (repo / "V.sol").write_text("contract V {}")
            sandbox = MagicMock()
            sandbox.run_foundry_test.return_value = {"success": False, "gas_used": 0}
            ex = self._make("foundry")
            with patch.object(ex.code_gen, "generate", return_value="contract T {}"), \
                 patch("hawki.core.deep.executor.novel_executor.SandboxManager", return_value=sandbox):
                result = ex.execute(_plan(), repo)
        sandbox.run_foundry_test.assert_called_once()
        sandbox.run_generated_script.assert_not_called()
        self.assertIn("estimated_tokens", result)

    def test_code_generation_failure_fails(self):
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            repo = Path(d)
            (repo / "V.sol").write_text("contract V {}")
            ex = self._make()
            with patch.object(ex.code_gen, "generate", return_value=None):
                result = ex.execute(_plan(), repo)
        self.assertFalse(result["success"])
        self.assertIn("Code generation failed", result["logs"])

    def test_sandbox_error_returns_fail_and_cleans_up(self):
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            repo = Path(d)
            (repo / "V.sol").write_text("contract V {}")
            sandbox = MagicMock()
            sandbox.run_generated_script.side_effect = RuntimeError("sandbox exploded")
            ex = self._make()
            with patch.object(ex.code_gen, "generate", return_value="const x=1;"), \
                 patch("hawki.core.deep.executor.novel_executor.SandboxManager", return_value=sandbox):
                result = ex.execute(_plan(), repo)
        self.assertFalse(result["success"])
        self.assertIn("sandbox exploded", result["logs"])
        self.assertEqual(result["attack_name"], "x")
        sandbox.cleanup.assert_called_once()


if __name__ == "__main__":
    unittest.main()
