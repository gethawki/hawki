# File: hawki/core/diagnostics/__init__.py
"""
Diagnostic system for Hawk-i environment health checks.
"""

from .checks.base import DiagnosticCheck
from .doctor import Doctor
from .reporters.json_reporter import JSONReporter
from .reporters.terminal_reporter import TerminalReporter

__all__ = ["Doctor", "DiagnosticCheck", "TerminalReporter", "JSONReporter"]
# EOF
