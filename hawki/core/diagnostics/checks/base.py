# File: hawki/core/diagnostics/checks/base.py
"""
Abstract base class for all diagnostic checks.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any, Dict, Optional


@dataclass
class CheckResult:
    """Result of a single diagnostic check."""
    name: str
    status: str  # "pass", "fail", "warn", "skip"
    message: str
    fix: Optional[str] = None
    details: Optional[Dict[str, Any]] = None
    duration_ms: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "status": self.status,
            "message": self.message,
            "fix": self.fix,
            "details": self.details or {},
            "duration_ms": self.duration_ms,
        }


class DiagnosticCheck(ABC):
    """Base class for a diagnostic check."""

    @property
    @abstractmethod
    def name(self) -> str:
        """Unique name for this check."""
        pass

    @property
    @abstractmethod
    def category(self) -> str:
        """Category (e.g., 'system', 'ai', 'network', 'config', 'tools', 'budget')."""
        pass

    @property
    def description(self) -> str:
        """Human-readable description."""
        return f"Check {self.name}"

    @abstractmethod
    def run(self, config: Optional[Dict[str, Any]] = None) -> CheckResult:
        """
        Run the diagnostic check.
        Returns a CheckResult.
        """
        pass

    def is_critical(self) -> bool:
        """Whether failure of this check should abort the scan."""
        return False
# EOF
