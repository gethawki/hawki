# --------------------
# File: hawki/core/monitoring/watcher_base.py
# --------------------
"""
Abstract base class for all watchers.
Defines the interface and common utilities.
"""

import logging
from abc import ABC, abstractmethod
from typing import Any, Dict, Optional

logger = logging.getLogger(__name__)

class Watcher(ABC):
    """Base class for a monitoring watcher."""

    def __init__(self, name: str, config: Dict[str, Any]):
        self.name = name
        self.config = config
        self.state: Dict[str, Any] = {}

    @abstractmethod
    def check(self) -> Optional[Dict[str, Any]]:
        """
        Perform a single check. If an event occurs, return a dictionary
        describing the event. Return None if nothing happened.
        """
        pass

    def load_state(self, state: Dict[str, Any]) -> None:
        """Restore persisted state."""
        self.state = state

    def save_state(self) -> Dict[str, Any]:
        """Return current state to be persisted."""
        return self.state

    def get_id(self) -> str:
        """Unique identifier for this watcher instance (used in state key)."""
        return f"{self.__class__.__name__}:{self.name}"

# EOF: hawki/core/monitoring/watcher_base.py