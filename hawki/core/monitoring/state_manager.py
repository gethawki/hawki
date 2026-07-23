# --------------------
# File: hawki/core/monitoring/state_manager.py
# --------------------
"""
Persistent storage for watcher states using a JSON file.
"""

import json
import logging
from pathlib import Path
from typing import Any, Dict, Optional

logger = logging.getLogger(__name__)

class StateManager:
    """Manages persistent state for watchers."""

    def __init__(self, state_dir: Optional[Path] = None):
        if state_dir is None:
            state_dir = Path.home() / ".hawki" / "monitor_state"
        self.state_dir = state_dir
        self.state_dir.mkdir(parents=True, exist_ok=True)
        self.state_file = self.state_dir / "watcher_states.json"
        self._states: Dict[str, Any] = self._load()

    def _load(self) -> Dict[str, Any]:
        """Load states from JSON file."""
        if not self.state_file.exists():
            return {}
        try:
            with open(self.state_file) as f:
                return json.load(f)
        except Exception as e:
            logger.error(f"Failed to load state file: {e}")
            return {}

    def save(self) -> None:
        """Save states to JSON file."""
        try:
            with open(self.state_file, "w") as f:
                json.dump(self._states, f, indent=2)
        except Exception as e:
            logger.error(f"Failed to save state file: {e}")

    def get(self, watcher_id: str) -> Dict[str, Any]:
        """Get state for a specific watcher."""
        return self._states.get(watcher_id, {})

    def set(self, watcher_id: str, state: Dict[str, Any]) -> None:
        """Set state for a watcher."""
        self._states[watcher_id] = state

# EOF: hawki/core/monitoring/state_manager.py