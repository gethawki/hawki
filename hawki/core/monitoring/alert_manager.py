# --------------------
# File: hawki/core/monitoring/alert_manager.py
# --------------------
"""
Alert manager: receives events from watchers and dispatches to handlers.
"""

import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

logger = logging.getLogger(__name__)

class AlertManager:
    """Manages alert handlers and dispatches alerts."""

    def __init__(self, alert_log_file: Optional[Path] = None):
        self.handlers: List[Callable[[Dict[str, Any]], None]] = []
        if alert_log_file:
            self.add_handler(self._file_handler(alert_log_file))
        # Always log to console via logger
        self.add_handler(self._log_handler)

    def add_handler(self, handler: Callable[[Dict[str, Any]], None]) -> None:
        """Register an alert handler."""
        self.handlers.append(handler)

    def alert(self, event: Dict[str, Any]) -> None:
        """Dispatch an alert to all handlers."""
        # Add timestamp if missing
        if "timestamp" not in event:
            event["timestamp"] = datetime.utcnow().isoformat() + "Z"
        for handler in self.handlers:
            try:
                handler(event)
            except Exception as e:
                logger.error(f"Alert handler failed: {e}")

    def _log_handler(self, event: Dict[str, Any]) -> None:
        """Default handler: log as warning."""
        logger.warning(f"ALERT: {event.get('message', 'No message')} - {event}")

    def _file_handler(self, log_file: Path):
        """Create a file handler that appends alerts to a file."""
        def handler(event: Dict[str, Any]):
            try:
                with open(log_file, "a") as f:
                    f.write(json.dumps(event) + "\n")
            except Exception as e:
                logger.error(f"Failed to write alert to file: {e}")
        return handler

# EOF: hawki/core/monitoring/alert_manager.py