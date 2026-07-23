# File: hawki/core/deep/planner/base.py
"""
Planner abstract base class.
"""

from abc import ABC, abstractmethod
from typing import Any, Dict, Optional


class AttackPlan:
    """Represents a planned attack (rule or novel)."""
    def __init__(self, plan_type: str, rule_name: Optional[str] = None,
                 signature: str = "", parameters: Optional[Dict] = None,
                 description: str = ""):
        self.type = plan_type          # "rule" or "novel"
        self.rule_name = rule_name     # for rule attacks: the script name
        self.signature = signature     # unique identifier (e.g., rule_name + param hash)
        self.parameters = parameters or {}
        self.description = description

    def to_dict(self) -> Dict[str, Any]:
        return {
            "type": self.type,
            "rule_name": self.rule_name,
            "signature": self.signature,
            "parameters": self.parameters,
            "description": self.description,
        }

class Planner(ABC):
    @abstractmethod
    def next_attack(self, memory, goal: str, force: bool = False) -> Optional[AttackPlan]:
        """Return the next attack to try, or None if no more attacks."""
        pass

# EOF