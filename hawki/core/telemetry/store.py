# --------------------
# File: hawki/core/telemetry/store.py
# --------------------
"""
Local storage for telemetry metrics.
"""

import json
import logging
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

class MetricsStore:
    """Stores metrics locally in ~/.hawki/metrics.json."""

    DEFAULT_PATH = Path.home() / ".hawki" / "metrics.json"

    def __init__(self, path: Optional[Path] = None):
        self.path = path or self.DEFAULT_PATH
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def append(self, metrics: Dict[str, Any]) -> None:
        """Append a metrics record to the local file."""
        try:
            if self.path.exists():
                with open(self.path) as f:
                    data = json.load(f)
            else:
                data = []
        except (json.JSONDecodeError, OSError):
            data = []

        data.append(metrics)

        try:
            with open(self.path, "w") as f:
                json.dump(data, f, indent=2)
            logger.debug(f"Metrics appended to {self.path}")
        except OSError as e:
            logger.warning(f"Failed to write metrics: {e}")

    def get_all(self) -> List[Dict[str, Any]]:
        """Retrieve all stored metrics."""
        try:
            if self.path.exists():
                with open(self.path) as f:
                    return json.load(f)
            else:
                return []
        except (json.JSONDecodeError, OSError) as e:
            logger.warning(f"Failed to read metrics: {e}")
            return []

    def clear(self) -> None:
        """Clear the metrics file (useful for testing)."""
        try:
            if self.path.exists():
                self.path.unlink()
        except OSError as e:
            logger.warning(f"Failed to clear metrics: {e}")
# EOF
