# File: hawki/core/deep/executor/base.py
"""
Executor abstract base class.
"""

from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any, Dict


class Executor(ABC):
    @abstractmethod
    def execute(self, plan, repo_path: Path, goal: str = "") -> Dict[str, Any]:
        """
        Execute an attack plan.
        Returns a result dict with at least:
            success (bool),
            before_balance (int),
            after_balance (int),
            gas_used (int),
            transaction_hash (str),
            logs (str)
        """
        pass

# EOF