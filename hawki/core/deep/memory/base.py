# File: hawki/core/deep/memory/base.py
"""
Abstract base class for memory storage.
All memory backends must implement these methods.
"""

# File: hawki/core/deep/memory/base.py (updated)
from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional


class MemoryStore(ABC):
    @abstractmethod
    def record(self, attack_plan: Dict[str, Any], result: Dict[str, Any]) -> None:
        pass

    @abstractmethod
    def get_all(self, filters: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
        pass

    @abstractmethod
    def has_attempted(self, attack_signature: str) -> bool:
        pass

    @abstractmethod
    def get_recent(self, limit: int = 10) -> List[Dict[str, Any]]:
        pass

    @abstractmethod
    def get_stats(self) -> Dict[str, Any]:
        pass

    @abstractmethod
    def clear_rule_attempts(self) -> None:
        """Delete all rule-based attack records from memory."""
        pass

# EOF