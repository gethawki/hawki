# File: hawki/core/exporters/base.py
"""
Abstract base class for all exporters.
"""

from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any, Dict


class Exporter(ABC):
    """Base class for exporting scan results."""

    @abstractmethod
    def export(self, context: Dict[str, Any], output_path: Path) -> Path:
        """
        Export scan results to the given output path.

        Args:
            context: Complete report context (findings, metadata, score, etc.)
            output_path: Where to write the export.

        Returns:
            Path to the exported file.
        """
        pass

    @property
    @abstractmethod
    def name(self) -> str:
        """Unique name for this exporter (e.g., 'structured', 'csv')."""
        pass

    @property
    @abstractmethod
    def description(self) -> str:
        """Human-readable description."""
        pass
# EOF
