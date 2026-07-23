# File: hawki/core/deep/executor/rule_executor.py
"""
Executor for rule-based attacks: runs existing attack scripts via SandboxManager.
"""

import logging
from pathlib import Path
from typing import Any, Dict

from ...exploit_sandbox.sandbox_manager import SandboxManager
from .base import Executor

logger = logging.getLogger(__name__)

class RuleExecutor(Executor):
    def __init__(self):
        pass

    def execute(self, plan, repo_path: Path, goal: str = "") -> Dict[str, Any]:
        """
        Run a single attack script.
        Expects plan.rule_name to be the script name (without .py).
        """
        script_name = plan.rule_name + ".py"
        sandbox = None
        try:
            # Construct inside the try so a Docker/sandbox setup failure is
            # recorded as a failed attempt rather than crashing the campaign.
            sandbox = SandboxManager(repo_path)
            result = sandbox.run_script(script_name)
            return result
        except Exception as e:
            logger.exception("RuleExecutor failed")
            return {
                "success": False,
                "before_balance": 0,
                "after_balance": 0,
                "gas_used": 0,
                "transaction_hash": "",
                "logs": str(e),
                "attack_name": plan.rule_name,
            }
        finally:
            if sandbox is not None:
                sandbox.cleanup()

# EOF