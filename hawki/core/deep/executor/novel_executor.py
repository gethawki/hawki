# File: hawki/core/deep/executor/novel_executor.py
"""
Execute novel attacks: generate code, run in sandbox, record results.
Supports both Hardhat (JS) and Foundry (Solidity) formats.
"""

import logging
import tempfile
from pathlib import Path
from typing import Any, Dict

from ...exploit_sandbox.sandbox_manager import SandboxManager
from .base import Executor
from .code_generator import CodeGenerator

logger = logging.getLogger(__name__)

class NovelExecutor(Executor):
    def __init__(self, llm_model: str, llm_api_key: str = None, poc_format: str = "hardhat"):
        """
        Initialize the NovelExecutor.

        Args:
            llm_model: LLM model string (e.g., 'openai/gpt-4')
            llm_api_key: Optional API key
            poc_format: 'hardhat' or 'foundry'
        """
        self.llm_model = llm_model
        self.llm_api_key = llm_api_key
        self.poc_format = poc_format  # NEW: store the format
        # Pass poc_format to CodeGenerator
        self.code_gen = CodeGenerator(
            model=llm_model,
            api_key=llm_api_key,
            poc_format=poc_format
        )

    def execute(self, plan, repo_path: Path, goal: str = "") -> Dict[str, Any]:
        """
        Generate exploit code from plan, run in sandbox, return result.
        """
        # Step 1: Get target contract code (simplified: read first .sol file)
        sol_files = list(repo_path.rglob("*.sol"))
        if not sol_files:
            return self._fail_result("No Solidity files found", plan)
        target_code = sol_files[0].read_text(encoding="utf-8")

        # Step 2: Generate code (returns appropriate language based on poc_format)
        code = self.code_gen.generate(plan, target_code)
        if not code:
            return self._fail_result("Code generation failed", plan)

        # Step 3: Write code to temp file with correct extension
        # Determine file extension based on format
        if self.poc_format == "foundry":
            suffix = ".sol"
        else:
            suffix = ".js"  # Hardhat/JavaScript

        with tempfile.NamedTemporaryFile(mode="w", suffix=suffix, delete=False) as f:
            f.write(code)
            temp_path = Path(f.name)

        # Step 4: Run in sandbox
        sandbox = SandboxManager(repo_path)
        try:
            # Use the appropriate sandbox method
            # For Hardhat, we use run_generated_script (which expects JS)
            # For Foundry, we need to run forge test on the generated .sol file
            if self.poc_format == "foundry":
                # We'll need to adapt the sandbox to handle Foundry tests.
                # For now, we run run_generated_script but note it's limited.
                # In a future improvement, we could run `forge test` inside the sandbox.
                # The current sandbox runs node for .js and python for .py.
                # We'll add support for Foundry by detecting .sol and using forge.
                # We'll implement a dedicated method in SandboxManager: run_foundry_test
                # For now, we'll call run_generated_script which will treat .sol as unknown.
                # We'll add a check: if extension is .sol, run forge test.
                # We'll add a method to SandboxManager called run_foundry_test.
                # I'll include that method below.
                result = sandbox.run_foundry_test(temp_path)
            else:
                result = sandbox.run_generated_script(temp_path)

            # Add token estimation
            result["estimated_tokens"] = plan.parameters.get("estimated_tokens", 0)
            return result
        except Exception as e:
            logger.exception("NovelExecutor failed")
            return self._fail_result(str(e), plan)
        finally:
            sandbox.cleanup()
            if temp_path.exists():
                temp_path.unlink()

    def _fail_result(self, error_msg: str, plan) -> Dict[str, Any]:
        return {
            "success": False,
            "before_balance": 0,
            "after_balance": 0,
            "gas_used": 0,
            "transaction_hash": "",
            "logs": error_msg,
            "attack_name": plan.parameters.get("name", "unknown"),
            "estimated_tokens": 0,
        }

# EOF